#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <jansson.h>
#include <ctype.h>

#include "stratum.h"
#include "config.h"
#include "utils.h"
#include "bitcoin.h"

static Client g_clients[MAX_CLIENTS];
static pthread_mutex_t g_clients_lock = PTHREAD_MUTEX_INITIALIZER;

// 64-bit share fingerprint cache (ring)
#define SHARE_CACHE_SIZE 4096
static uint64_t g_share_cache[SHARE_CACHE_SIZE];
static int g_share_head = 0;
static pthread_mutex_t g_cache_lock = PTHREAD_MUTEX_INITIALIZER;

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
    (void)send(sock, m, l + 1, MSG_NOSIGNAL);
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

// --- helpers ---

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

// nonce 兼容：
// - 如果含 a-f/A-F -> 只按 hex
// - 否则若全数字 -> 优先按 dec，同时保留 hex fallback（有些矿机会把 hex nonce 写成纯数字字符串）
// 返回：ok_dec/ok_hex + 对应值
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

    // hex parse attempt
    if (is_fixed_hex(s, strlen(s))) {
        char *end = NULL;
        unsigned long v = strtoul(s, &end, 16);
        if (end && *end == '\0' && v <= 0xffffffffUL) {
            if (ok_hex) *ok_hex = true;
            if (val_hex) *val_hex = (uint32_t)v;
        }
    }

    if (has_hex_alpha) return;

    // dec parse attempt if pure digits
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

// find client by socket (to store last_job_id in send_mining_notify without changing call sites)
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

    // remember last job id for this client
    Client *c = client_find_by_sock(sock);
    if (c) {
        snprintf(c->last_job_id, sizeof(c->last_job_id), "%s", tmpl->job_id ? tmpl->job_id : "");
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

static void *client_worker(void *arg) {
    Client *c = (Client*)arg;
    char buf[8192];
    int rpos = 0;

    log_info("Worker connected: ID=%d IP=%s", c->id, inet_ntoa(c->addr.sin_addr));

    struct timeval tv;
    tv.tv_sec = 600;
    tv.tv_usec = 0;
    setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

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
                            json_decref(res);
                            json_decref(req);
                            start = end + 1;
                            continue;
                        }

                        const char *jid = json_string_value(json_array_get(p, 1));
                        const char *en2 = json_string_value(json_array_get(p, 2));
                        const char *nt  = json_string_value(json_array_get(p, 3));
                        const char *nh  = json_string_value(json_array_get(p, 4));
                        const char *vh  = NULL;
                        if (json_array_size(p) >= 6) vh = json_string_value(json_array_get(p, 5));
                        if (!vh) vh = "";

                        // Validate required fields except nonce: nonce may be decimal or hex
                        if (!jid || strlen(jid) == 0 ||
                            !en2 || !is_fixed_hex(en2, (size_t)g_config.extranonce2_size * 2) ||
                            !nt  || !is_fixed_hex(nt, 8) ||
                            !nh  || strlen(nh) == 0 ||
                            (strlen(vh) > 0 && !is_fixed_hex(vh, 8))) {
                            json_reply_error(res, 20, "Invalid submit fields");
                            send_json(c->sock, res);
                            json_decref(res);
                            json_decref(req);
                            start = end + 1;
                            continue;
                        }

                        uint32_t version_bits = 0;
                        if (vh[0]) version_bits = (uint32_t)strtoul(vh, NULL, 16);

                        // Parse nonce (decimal/hex compatible)
                        bool ok_dec = false, ok_hex = false;
                        uint32_t nonce_dec = 0, nonce_hex = 0;
                        parse_nonce_auto(nh, &ok_dec, &nonce_dec, &ok_hex, &nonce_hex);
                        if (!ok_dec && !ok_hex) {
                            json_reply_error(res, 20, "Invalid nonce");
                            send_json(c->sock, res);
                            json_decref(res);
                            json_decref(req);
                            start = end + 1;
                            continue;
                        }

                        char full_extranonce[128];
                        snprintf(full_extranonce, sizeof(full_extranonce), "%s%s", c->extranonce1_hex, en2);

                        // Try validate in this order:
                        // 1) job_id as provided + nonce as DEC (if dec ok)
                        // 2) job_id as provided + nonce as HEX (if hex ok)
                        // If still fail, try with last_job_id (per-connection) similarly
                        const char *jid_used = jid;
                        uint32_t nonce_used = 0;
                        int ret = 0;

                        // helper macro to attempt one combination
                        #define TRY_ONE(_jid, _nonce) \
                            do { \
                                ret = bitcoin_validate_and_submit((_jid), full_extranonce, nt, (_nonce), version_bits, c->current_diff); \
                                if (ret != 0) { jid_used = (_jid); nonce_used = (_nonce); } \
                            } while (0)

                        if (ok_dec) { TRY_ONE(jid, nonce_dec); }
                        if (ret == 0 && ok_hex) { TRY_ONE(jid, nonce_hex); }

                        // Fallback to last_job_id if mismatch/unknown job_id caused stale
                        if (ret == 0 && c->last_job_id[0] && strcmp(c->last_job_id, jid) != 0) {
                            if (ok_dec) { TRY_ONE(c->last_job_id, nonce_dec); }
                            if (ret == 0 && ok_hex) { TRY_ONE(c->last_job_id, nonce_hex); }
                        }

                        // Duplicate fingerprint should use the job_id actually used for validation
                        // (and include nonce string to stay stable vs decimal/hex interpretation)
                        char keybuf[256];
                        snprintf(keybuf, sizeof(keybuf), "%s|%s|%s|%s|%s|%d",
                                 jid_used, c->extranonce1_hex, en2, nt, nh, c->id);
                        uint64_t fp = fnv1a64(keybuf, strlen(keybuf));
                        if (is_duplicate_share_fp(fp)) {
                            json_reply_error(res, 22, "Duplicate");
                            send_json(c->sock, res);
                            json_decref(res);
                            json_decref(req);
                            start = end + 1;
                            continue;
                        }

                        if (ret == 0) {
                            json_reply_error(res, 21, "Stale or Low Difficulty");
                        } else {
                            json_object_set_new(res, "result", json_true());
                            json_object_set_new(res, "error", json_null());

                            // vardiff window update
                            c->shares_in_window++;
                            time_t now = time(NULL);
                            double dt = difftime(now, c->last_retarget_time);
                            if (dt >= 60.0) {
                                double spm = (c->shares_in_window / dt) * 60.0;
                                double target = (double)g_config.vardiff_target;
                                double new_diff = c->current_diff;
                                bool changed = false;

                                if (spm < target * 0.4) { new_diff /= 2.0; changed = true; }
                                else if (spm > target * 1.5) { new_diff *= 2.0; changed = true; }

                                if (new_diff < g_config.vardiff_min_diff) new_diff = g_config.vardiff_min_diff;
                                if (new_diff > g_config.vardiff_max_diff) new_diff = g_config.vardiff_max_diff;

                                if (changed && new_diff != c->current_diff) {
                                    log_info("VarDiff ID=%d: %.0f -> %.0f (SPM: %.1f)", c->id, c->current_diff, new_diff, spm);
                                    c->current_diff = new_diff;
                                    send_difficulty(c, new_diff);

                                    // send clean job to force switch
                                    Template t;
                                    if (bitcoin_get_latest_job(&t)) {
                                        t.clean_jobs = true;
                                        stratum_send_mining_notify(c->sock, &t);
                                        bitcoin_free_job(&t);
                                    }
                                }
                                c->last_retarget_time = now;
                                c->shares_in_window = 0;
                            }
                        }

                        send_json(c->sock, res);

                        #undef TRY_ONE
                    }
                    else {
                        json_reply_error(res, 20, "Unknown method");
                        send_json(c->sock, res);
                    }

                    json_decref(res);
                    json_decref(req);
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
