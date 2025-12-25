#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <sys/time.h>
#include <jansson.h>
#include <ctype.h>
#include <math.h>

#include "stratum.h"
#include "config.h"
#include "utils.h"
#include "bitcoin.h"

static Client g_clients[MAX_CLIENTS];
static pthread_mutex_t g_clients_lock = PTHREAD_MUTEX_INITIALIZER;

#define SHARE_CACHE_SIZE 65536
static uint64_t g_share_cache[SHARE_CACHE_SIZE];
static int g_share_head = 0;
static pthread_mutex_t g_cache_lock = PTHREAD_MUTEX_INITIALIZER;

// --- Web Stats Globals ---
#define MAX_SHARE_LOGS 50
#define HISTORY_POINTS 60 

static ShareLog g_share_logs[MAX_SHARE_LOGS];
static int g_share_log_head = 0;
static pthread_mutex_t g_stats_lock = PTHREAD_MUTEX_INITIALIZER;

static double g_hashrate_history[HISTORY_POINTS]; 
static time_t g_last_history_update = 0;

// --- Stats Helpers ---
static void record_share(const char *ex1, double diff, const char *hash, bool is_block) {
    pthread_mutex_lock(&g_stats_lock);
    int idx = g_share_log_head;
    strncpy(g_share_logs[idx].worker_ex1, ex1, 8);
    g_share_logs[idx].worker_ex1[8] = 0;
    g_share_logs[idx].difficulty = diff;
    strncpy(g_share_logs[idx].share_hash, hash, 64);
    g_share_logs[idx].share_hash[64] = 0;
    g_share_logs[idx].timestamp = time(NULL);
    g_share_logs[idx].is_block = is_block;
    
    g_share_log_head = (g_share_log_head + 1) % MAX_SHARE_LOGS;
    pthread_mutex_unlock(&g_stats_lock);
}

static void update_global_hashrate_history(double total_hashrate) {
    time_t now = time(NULL);
    pthread_mutex_lock(&g_stats_lock);
    if (g_last_history_update == 0) g_last_history_update = now;
    
    if (now - g_last_history_update >= 60) {
        for (int i = 0; i < HISTORY_POINTS - 1; i++) {
            g_hashrate_history[i] = g_hashrate_history[i+1];
        }
        g_hashrate_history[HISTORY_POINTS - 1] = total_hashrate;
        g_last_history_update = now;
    } else {
        g_hashrate_history[HISTORY_POINTS - 1] = total_hashrate;
    }
    pthread_mutex_unlock(&g_stats_lock);
}

// --- Stratum Logic ---
static uint64_t fnv1a64(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t*)data;
    uint64_t h = 1469598103934665603ULL;
    for (size_t i = 0; i < len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static bool is_duplicate_share_fp(uint64_t fp) {
    pthread_mutex_lock(&g_cache_lock);
    for (int i = 0; i < SHARE_CACHE_SIZE; i++) {
        if (g_share_cache[i] == fp) {
            pthread_mutex_unlock(&g_cache_lock);
            return true;
        }
    }
    g_share_cache[g_share_head] = fp;
    g_share_head = (g_share_head + 1) % SHARE_CACHE_SIZE;
    pthread_mutex_unlock(&g_cache_lock);
    return false;
}

static void init_clients(void) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        g_clients[i].active = false;
        g_clients[i].sock = -1;
        g_clients[i].is_authorized = false;
        g_clients[i].last_job_id[0] = '\0';
    }
}

static Client* client_add(int sock, struct sockaddr_in addr) {
    struct timeval tv;
    tv.tv_sec = 2; 
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
        log_error("Failed to set SO_SNDTIMEO on client socket");
    }

    tv.tv_sec = 600; 
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    pthread_mutex_lock(&g_clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!g_clients[i].active) {
            Client *c = &g_clients[i];
            c->active = true;
            c->sock = sock;
            c->addr = addr;
            c->id = i + 1;
            c->is_authorized = false;

            c->current_diff = (double)g_config.initial_diff;
            c->last_retarget_time = time(NULL);
            c->shares_in_window = 0;
            
            // Stats Init
            c->hashrate_est = 0.0;
            c->last_submit_time = time(NULL);
            c->total_shares = 0;
            c->best_diff = 0.0;

            snprintf(c->extranonce1_hex, sizeof(c->extranonce1_hex), "%08x", (uint32_t)c->id);
            c->last_job_id[0] = '\0';

            pthread_mutex_unlock(&g_clients_lock);
            return c;
        }
    }
    pthread_mutex_unlock(&g_clients_lock);
    return NULL;
}

static void client_remove(Client *c) {
    if (!c) return;
    pthread_mutex_lock(&g_clients_lock);
    if (c->active) {
        close(c->sock);
        c->active = false;
        c->sock = -1;
        c->is_authorized = false;
        c->last_job_id[0] = '\0';
        log_info("Client %d disconnected", c->id);
    }
    pthread_mutex_unlock(&g_clients_lock);
}

static void send_json(int sock, json_t *response) {
    char *s = json_dumps(response, JSON_COMPACT);
    if (!s) return;
    size_t l = strlen(s);
    char *m = malloc(l + 2);
    if (!m) { free(s); return; }
    memcpy(m, s, l);
    m[l] = '\n';
    m[l + 1] = '\0';
    
    ssize_t sent = send(sock, m, l + 1, MSG_NOSIGNAL);
    if (sent < 0) {}

    free(m);
    free(s);
}

static void send_difficulty(Client *c, double diff) {
    json_t *res = json_object();
    json_object_set_new(res, "id", json_null());
    json_object_set_new(res, "method", json_string("mining.set_difficulty"));
    json_t *params = json_array();
    json_array_append_new(params, json_real(diff));
    json_object_set_new(res, "params", params);
    send_json(c->sock, res);
    json_decref(res);
}

static bool is_fixed_hex(const char *s, size_t n) {
    if (!s || strlen(s) != n) return false;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (!isxdigit(c)) return false;
    }
    return true;
}

static bool is_all_digits(const char *s) {
    if (!s || !*s) return false;
    for (const char *p = s; *p; p++) {
        if (*p < '0' || *p > '9') return false;
    }
    return true;
}

static void parse_nonce_auto(const char *s,
                            bool *ok_dec, uint32_t *val_dec,
                            bool *ok_hex, uint32_t *val_hex) {
    if (ok_dec) *ok_dec = false;
    if (ok_hex) *ok_hex = false;
    if (val_dec) *val_dec = 0;
    if (val_hex) *val_hex = 0;
    if (!s || !*s) return;

    bool has_hex_alpha = false;
    for (const char *p = s; *p; p++) {
        if ((*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')) {
            has_hex_alpha = true;
            break;
        }
    }

    if (is_fixed_hex(s, strlen(s))) {
        char *end = NULL;
        unsigned long v = strtoul(s, &end, 16);
        if (end && *end == '\0' && v <= 0xffffffffUL) {
            if (ok_hex) *ok_hex = true;
            if (val_hex) *val_hex = (uint32_t)v;
        }
    }
    if (has_hex_alpha) return;
    if (is_all_digits(s)) {
        char *end = NULL;
        unsigned long v = strtoul(s, &end, 10);
        if (end && *end == '\0' && v <= 0xffffffffUL) {
            if (ok_dec) *ok_dec = true;
            if (val_dec) *val_dec = (uint32_t)v;
        }
    }
}

static void json_reply_error(json_t *res, int code, const char *msg) {
    json_object_set_new(res, "result", json_false());
    json_t *e = json_array();
    json_array_append_new(e, json_integer(code));
    json_array_append_new(e, json_string(msg));
    json_object_set_new(res, "error", e);
}

static Client* client_find_by_sock(int sock) {
    Client *out = NULL;
    pthread_mutex_lock(&g_clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].active && g_clients[i].sock == sock) {
            out = &g_clients[i];
            break;
        }
    }
    pthread_mutex_unlock(&g_clients_lock);
    return out;
}

void stratum_send_mining_notify(int sock, Template *tmpl) {
    if (!tmpl) return;

    Client *c = client_find_by_sock(sock);
    if (c) {
        snprintf(c->last_job_id, sizeof(c->last_job_id), "%s", tmpl->job_id);
    }

    json_t *p = json_array();
    json_array_append_new(p, json_string(tmpl->job_id));
    json_array_append_new(p, json_string(tmpl->prev_hash_stratum));
    json_array_append_new(p, json_string(tmpl->coinb1));
    json_array_append_new(p, json_string(tmpl->coinb2));

    json_t *m = json_array();
    for (size_t i = 0; i < tmpl->merkle_count; i++) {
        json_array_append_new(m, json_string(tmpl->merkle_branch[i]));
    }
    json_array_append_new(p, m);

    json_array_append_new(p, json_string(tmpl->version_hex));
    json_array_append_new(p, json_string(tmpl->nbits_hex));
    json_array_append_new(p, json_string(tmpl->ntime_hex));
    json_array_append_new(p, json_boolean(tmpl->clean_jobs));

    json_t *r = json_object();
    json_object_set_new(r, "id", json_null());
    json_object_set_new(r, "method", json_string("mining.notify"));
    json_object_set_new(r, "params", p);
    send_json(sock, r);
    json_decref(r);
}

void stratum_broadcast_job(Template *tmpl) {
    int sockets[MAX_CLIENTS];
    int count = 0;

    pthread_mutex_lock(&g_clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].active && g_clients[i].is_authorized) {
            sockets[count++] = g_clients[i].sock;
        }
    }
    pthread_mutex_unlock(&g_clients_lock);

    for (int i = 0; i < count; i++) {
        stratum_send_mining_notify(sockets[i], tmpl);
    }
    if (count > 0) log_info("Broadcast job %s to %d miners", tmpl->job_id, count);
}

// API Export
json_t* stratum_get_stats(void) {
    json_t *root = json_object();
    json_t *workers = json_array();
    double total_hashrate = 0;

    double global_best_diff = 0;
    char global_best_worker[16] = {0};

    pthread_mutex_lock(&g_clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].active) {
            json_t *w = json_object();
            json_object_set_new(w, "id", json_integer(g_clients[i].id));
            json_object_set_new(w, "ex1", json_string(g_clients[i].extranonce1_hex));
            json_object_set_new(w, "ip", json_string(inet_ntoa(g_clients[i].addr.sin_addr)));
            json_object_set_new(w, "hashrate", json_real(g_clients[i].hashrate_est));
            json_object_set_new(w, "diff", json_real(g_clients[i].current_diff));
            json_object_set_new(w, "shares", json_integer(g_clients[i].total_shares));
            json_object_set_new(w, "last_seen", json_integer((long)g_clients[i].last_submit_time));
            json_array_append_new(workers, w);
            total_hashrate += g_clients[i].hashrate_est;

            if (g_clients[i].best_diff > global_best_diff) {
                global_best_diff = g_clients[i].best_diff;
                snprintf(global_best_worker, sizeof(global_best_worker), "%s", g_clients[i].extranonce1_hex);
            }
        }
    }
    pthread_mutex_unlock(&g_clients_lock);
    
    update_global_hashrate_history(total_hashrate);

    json_object_set_new(root, "workers", workers);

    uint32_t height = 0;
    int64_t reward = 0;
    uint32_t net_diff = 0;
    bitcoin_get_telemetry(&height, &reward, &net_diff);
    
    json_t *blk = json_object();
    json_object_set_new(blk, "height", json_integer(height));
    json_object_set_new(blk, "reward", json_integer(reward));
    json_object_set_new(blk, "net_diff", json_real((double)net_diff));
    json_object_set_new(blk, "best_diff", json_real(global_best_diff));
    json_object_set_new(blk, "best_worker", json_string(global_best_worker));
    json_object_set_new(root, "block_info", blk);

    json_t *logs = json_array();
    pthread_mutex_lock(&g_stats_lock);
    for(int i=0; i<MAX_SHARE_LOGS; i++) {
        if (g_share_logs[i].timestamp != 0) {
            json_t *l = json_object();
            json_object_set_new(l, "worker", json_string(g_share_logs[i].worker_ex1));
            json_object_set_new(l, "diff", json_real(g_share_logs[i].difficulty));
            json_object_set_new(l, "hash", json_string(g_share_logs[i].share_hash));
            json_object_set_new(l, "time", json_integer((long)g_share_logs[i].timestamp));
            json_object_set_new(l, "is_block", json_boolean(g_share_logs[i].is_block));
            json_array_append_new(logs, l);
        }
    }
    
    json_t *hist = json_array();
    for(int i=0; i<HISTORY_POINTS; i++) {
        json_array_append_new(hist, json_real(g_hashrate_history[i]));
    }
    pthread_mutex_unlock(&g_stats_lock);

    json_object_set_new(root, "recent_shares", logs);
    json_object_set_new(root, "history", hist);
    
    return root;
}

static void *client_worker(void *arg) {
    Client *c = (Client*)arg;
    char buf[8192];
    int rpos = 0;

    log_info("Worker connected: ID=%d IP=%s", c->id, inet_ntoa(c->addr.sin_addr));

    while (c->active) {
        ssize_t n = recv(c->sock, buf + rpos, sizeof(buf) - 1 - rpos, 0);
        if (n <= 0) break;
        rpos += (int)n;
        buf[rpos] = 0;

        char *start = buf;
        char *end;
        while ((end = strchr(start, '\n')) != NULL) {
            *end = 0;
            if (*start) {
                json_error_t e;
                json_t *req = json_loads(start, 0, &e);
                if (req) {
                    const char *m = json_string_value(json_object_get(req, "method"));
                    json_t *id = json_object_get(req, "id");
                    json_t *res = json_object();
                    if (id) json_object_set(res, "id", id);
                    else json_object_set_new(res, "id", json_null());

                    if (!m) {
                        json_reply_error(res, 20, "Missing method");
                        send_json(c->sock, res);
                    }
                    else if (strcmp(m, "mining.subscribe") == 0) {
                        json_object_set_new(res, "error", json_null());
                        json_t *arr = json_array();
                        json_t *subs = json_array();
                        json_t *s1 = json_array();
                        json_array_append_new(s1, json_string("mining.set_difficulty"));
                        json_array_append_new(s1, json_string("1"));
                        json_array_append_new(subs, s1);
                        json_t *s2 = json_array();
                        json_array_append_new(s2, json_string("mining.notify"));
                        json_array_append_new(s2, json_string("1"));
                        json_array_append_new(subs, s2);
                        json_array_append_new(arr, subs);
                        json_array_append_new(arr, json_string(c->extranonce1_hex));
                        json_array_append_new(arr, json_integer(g_config.extranonce2_size));
                        json_object_set_new(res, "result", arr);
                        send_json(c->sock, res);
                        log_info("ID=%d subscribed", c->id);
                    }
                    else if (strcmp(m, "mining.authorize") == 0) {
                        c->is_authorized = true;
                        json_object_set_new(res, "error", json_null());
                        json_object_set_new(res, "result", json_true());
                        send_json(c->sock, res);
                        log_info("ID=%d authorized", c->id);
                        send_difficulty(c, c->current_diff);
                        Template t;
                        if (bitcoin_get_latest_job(&t)) {
                            t.clean_jobs = true; // [FIX 1] Force clean=true on first auth
                            stratum_send_mining_notify(c->sock, &t);
                            bitcoin_free_job(&t);
                        }
                    }
                    else if (strcmp(m, "mining.configure") == 0) {
                        char ms[16];
                        snprintf(ms, sizeof(ms), "%08x", g_config.version_mask);
                        json_object_set_new(res, "error", json_null());
                        json_t *r = json_object();
                        json_object_set_new(r, "version-rolling", json_true());
                        json_object_set_new(r, "version-rolling.mask", json_string(ms));
                        json_object_set_new(res, "result", r);
                        send_json(c->sock, res);
                    }
                    else if (strcmp(m, "mining.submit") == 0) {
                        json_t *p = json_object_get(req, "params");
                        if (!p || !json_is_array(p) || json_array_size(p) < 5) {
                            json_reply_error(res, 20, "Bad params");
                            send_json(c->sock, res);
                            json_decref(res); json_decref(req); start = end + 1; continue;
                        }

                        const char *jid = json_string_value(json_array_get(p, 1));
                        const char *en2 = json_string_value(json_array_get(p, 2));
                        const char *nt  = json_string_value(json_array_get(p, 3));
                        const char *nh  = json_string_value(json_array_get(p, 4));
                        const char *vh  = NULL;
                        if (json_array_size(p) >= 6) vh = json_string_value(json_array_get(p, 5));
                        if (!vh) vh = "";

                        if (!jid || strlen(jid) == 0 ||
                            !en2 || !is_fixed_hex(en2, (size_t)g_config.extranonce2_size * 2) ||
                            !nt  || !is_fixed_hex(nt, 8) ||
                            !nh  || strlen(nh) == 0 ||
                            (strlen(vh) > 0 && !is_fixed_hex(vh, 8))) {
                            json_reply_error(res, 20, "Invalid submit fields");
                            send_json(c->sock, res);
                            json_decref(res); json_decref(req); start = end + 1; continue;
                        }

                        uint32_t version_bits = 0;
                        if (vh[0]) version_bits = (uint32_t)strtoul(vh, NULL, 16);

                        bool ok_dec = false, ok_hex = false;
                        uint32_t nonce_dec = 0, nonce_hex = 0;
                        parse_nonce_auto(nh, &ok_dec, &nonce_dec, &ok_hex, &nonce_hex);
                        if (!ok_dec && !ok_hex) {
                            json_reply_error(res, 20, "Invalid nonce");
                            send_json(c->sock, res);
                            json_decref(res); json_decref(req); start = end + 1; continue;
                        }

                        char full_extranonce[128];
                        snprintf(full_extranonce, sizeof(full_extranonce), "%s%s", c->extranonce1_hex, en2);

                        const char *jid_used = jid;
                        int ret = 0;
                        double actual_share_diff = 0.0; // [FIX 2] Variable for stats

                        if (ok_dec) ret = bitcoin_validate_and_submit(jid, full_extranonce, nt, nonce_dec, version_bits, c->current_diff, &actual_share_diff);
                        if (ret == 0 && ok_hex) ret = bitcoin_validate_and_submit(jid, full_extranonce, nt, nonce_hex, version_bits, c->current_diff, &actual_share_diff);

                        if (ret == 0 && c->last_job_id[0] && strcmp(c->last_job_id, jid) != 0) {
                            jid_used = c->last_job_id;
                            if (ok_dec) ret = bitcoin_validate_and_submit(jid_used, full_extranonce, nt, nonce_dec, version_bits, c->current_diff, &actual_share_diff);
                            if (ret == 0 && ok_hex) ret = bitcoin_validate_and_submit(jid_used, full_extranonce, nt, nonce_hex, version_bits, c->current_diff, &actual_share_diff);
                        }

                        char keybuf[256];
                        snprintf(keybuf, sizeof(keybuf), "%s|%s|%s|%s|%s|%d", jid_used, c->extranonce1_hex, en2, nt, nh, c->id);
                        uint64_t fp = fnv1a64(keybuf, strlen(keybuf));
                        if (is_duplicate_share_fp(fp)) {
                            json_reply_error(res, 22, "Duplicate");
                            send_json(c->sock, res);
                            json_decref(res); json_decref(req); start = end + 1; continue;
                        }

                        if (ret == 0) {
                            json_reply_error(res, 21, "Stale or Low Difficulty");
                        } else {
                            json_object_set_new(res, "result", json_true());
                            json_object_set_new(res, "error", json_null());

                            // Stats Update
                            c->shares_in_window++;
                            c->total_shares++;
                            time_t now = time(NULL);
                            c->last_submit_time = now;
                            
                            // Update Personal Best
                            if (actual_share_diff > c->best_diff) {
                                c->best_diff = actual_share_diff;
                            }

                            double share_work = c->current_diff * 4294967296.0;
                            double dt_est = difftime(now, c->last_retarget_time);
                            if (dt_est < 1.0) dt_est = 1.0;
                            double instant_hr = share_work / dt_est * c->shares_in_window;
                            if (c->hashrate_est == 0) c->hashrate_est = instant_hr;
                            else c->hashrate_est = c->hashrate_est * 0.95 + instant_hr * 0.05;

                            // Record share with actual diff
                            record_share(c->extranonce1_hex, actual_share_diff, "Valid Share", (ret == 2));

                            double dt = difftime(now, c->last_retarget_time);
                            if (dt >= 60.0) {
                                double spm = (c->shares_in_window / dt) * 60.0;
                                double target = (double)g_config.vardiff_target;
                                double new_diff = c->current_diff;
                                bool changed = false;

                                if (spm < target * 0.4) { new_diff /= 1.2; changed = true; }
                                else if (spm > target * 1.5) { new_diff *= 1.2; changed = true; }

                                if (new_diff < g_config.vardiff_min_diff) new_diff = g_config.vardiff_min_diff;
                                if (new_diff > g_config.vardiff_max_diff) new_diff = g_config.vardiff_max_diff;

                                if (changed && new_diff != c->current_diff) {
                                    log_info("VarDiff ID=%d: %.0f -> %.0f (SPM: %.1f)", c->id, c->current_diff, new_diff, spm);
                                    c->current_diff = new_diff;
                                    send_difficulty(c, new_diff);
                                    Template t;
                                    if (bitcoin_get_latest_job(&t)) {
                                        t.clean_jobs = true; // Still force clean on Diff change
                                        stratum_send_mining_notify(c->sock, &t);
                                        bitcoin_free_job(&t);
                                    }
                                }
                                c->last_retarget_time = now;
                                c->shares_in_window = 0;
                            }
                        }
                        send_json(c->sock, res);
                    }
                    else {
                        json_reply_error(res, 20, "Unknown method");
                        send_json(c->sock, res);
                    }
                    json_decref(res); json_decref(req);
                }
            }
            start = end + 1;
        }

        if (start < buf + rpos) {
            size_t rem = (size_t)((buf + rpos) - start);
            memmove(buf, start, rem);
            rpos = (int)rem;
        } else {
            rpos = 0;
        }
    }

    client_remove(c);
    return NULL;
}

static void *server_thread(void *arg) {
    (void)arg;
    int sfd;
    struct sockaddr_in addr;
    int opt = 1;
    init_clients();
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd < 0) exit(1);
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) != 0) exit(1);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons((uint16_t)g_config.stratum_port);
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) exit(1);
    if (listen(sfd, 64) < 0) exit(1);
    log_info("Stratum server listening on port %d", g_config.stratum_port);
    while (1) {
        struct sockaddr_in c_addr;
        socklen_t l = sizeof(c_addr);
        int ns = accept(sfd, (struct sockaddr *)&c_addr, &l);
        if (ns >= 0) {
            Client *c = client_add(ns, c_addr);
            if (c) {
                pthread_create(&c->thread_id, NULL, client_worker, c);
                pthread_detach(c->thread_id);
            } else {
                close(ns);
            }
        }
    }
    return NULL;
}

int stratum_start_thread(void) {
    pthread_t t;
    return pthread_create(&t, NULL, server_thread, NULL);
}
