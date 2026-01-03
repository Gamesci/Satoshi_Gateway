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
    ShareLog *log = &g_share_logs[g_share_log_head];
    strncpy(log->worker_ex1, ex1, sizeof(log->worker_ex1)-1);
    log->difficulty = diff;
    strncpy(log->share_hash, hash, sizeof(log->share_hash)-1);
    log->timestamp = time(NULL);
    log->is_block = is_block;
    
    g_share_log_head = (g_share_log_head + 1) % MAX_SHARE_LOGS;
    pthread_mutex_unlock(&g_stats_lock);
}

// [NEW] Helper: Get active miner count
int stratum_get_client_count(void) {
    int count = 0;
    pthread_mutex_lock(&g_clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].active && g_clients[i].is_authorized) {
            count++;
        }
    }
    pthread_mutex_unlock(&g_clients_lock);
    return count;
}

static void init_clients(void) {
    for (int i = 0; i < MAX_CLIENTS; i++) {
        g_clients[i].active = false;
        g_clients[i].is_authorized = false;
    }
}

static void client_remove(Client *c) {
    pthread_mutex_lock(&g_clients_lock);
    if (c->active) {
        close(c->sock);
        c->active = false;
        c->is_authorized = false;
        log_info("Client %d disconnected", c->id);
    }
    pthread_mutex_unlock(&g_clients_lock);
}

static bool check_duplicate_share(uint64_t nonce_val, const char *extranonce2_hex, uint32_t ntime_val) {
    // Simple deduplication using a hash of (nonce ^ extra2_first_8_bytes ^ ntime)
    // Production systems need better deduplication.
    uint64_t ex2_low = 0;
    if (extranonce2_hex) {
        // Just take first 8 bytes or less
        ex2_low = strtoull(extranonce2_hex, NULL, 16);
    }
    uint64_t key = nonce_val ^ ex2_low ^ (uint64_t)ntime_val;
    
    pthread_mutex_lock(&g_cache_lock);
    for (int i = 0; i < SHARE_CACHE_SIZE; i++) {
        if (g_share_cache[i] == key) {
            pthread_mutex_unlock(&g_cache_lock);
            return true;
        }
    }
    g_share_cache[g_share_head] = key;
    g_share_head = (g_share_head + 1) % SHARE_CACHE_SIZE;
    pthread_mutex_unlock(&g_cache_lock);
    return false;
}

static void send_line(int sock, const char *line) {
    send(sock, line, strlen(line), 0);
    send(sock, "\n", 1, 0);
}

static void send_result_bool(int sock, json_t *id, bool res) {
    json_t *resp = json_object();
    json_object_set_new(resp, "id", json_incref(id));
    json_object_set_new(resp, "result", json_boolean(res));
    json_object_set_new(resp, "error", json_null());
    char *s = json_dumps(resp, 0);
    send_line(sock, s);
    free(s);
    json_decref(resp);
}

static void send_reply_true(int sock, json_t *id) {
    send_result_bool(sock, id, true);
}

static void send_error(int sock, json_t *id, int code, const char *msg) {
    json_t *resp = json_object();
    json_object_set_new(resp, "id", json_incref(id));
    json_object_set_new(resp, "result", json_null());
    json_t *err = json_array();
    json_array_append_new(err, json_integer(code));
    json_array_append_new(err, json_string(msg));
    json_array_append_new(err, json_null());
    json_object_set_new(resp, "error", err);
    char *s = json_dumps(resp, 0);
    send_line(sock, s);
    free(s);
    json_decref(resp);
}

static void handle_subscribe(Client *c, json_t *id, json_t *params) {
    // params: [userAgent, extraNonce1_optional]
    // Ignore params for simplicity, generate Extranonce1
    // Format: Configurable ID ? No, let's just use client ID hex
    snprintf(c->extranonce1_hex, sizeof(c->extranonce1_hex), "%08x", c->id);
    
    // Check if user agent hints at variant
    c->coinbase_variant = CB_VARIANT_DEFAULT;
    if (json_array_size(params) > 0) {
        const char *ua = json_string_value(json_array_get(params, 0));
        if (ua) {
            strncpy(c->user_agent, ua, sizeof(c->user_agent)-1);
            if (strstr(ua, "NiceHash")) c->coinbase_variant = CB_VARIANT_NICEHASH;
            else if (strstr(ua, "WhatsMiner")) c->coinbase_variant = CB_VARIANT_WHATSMINER;
        }
    }

    json_t *resp = json_object();
    json_object_set_new(resp, "id", json_incref(id));
    json_object_set_new(resp, "error", json_null());
    
    json_t *res_arr = json_array();
    
    json_t *subs = json_array();
    json_t *sub1 = json_array();
    json_array_append_new(sub1, json_string("mining.set_difficulty"));
    json_array_append_new(sub1, json_string("1")); // subscription id
    json_array_append_new(subs, sub1);
    json_t *sub2 = json_array();
    json_array_append_new(sub2, json_string("mining.notify"));
    json_array_append_new(sub2, json_string("1"));
    json_array_append_new(subs, sub2);
    
    json_array_append_new(res_arr, subs);
    json_array_append_new(res_arr, json_string(c->extranonce1_hex));
    json_array_append_new(res_arr, json_integer(g_config.extranonce2_size));
    
    json_object_set_new(resp, "result", res_arr);
    
    char *s = json_dumps(resp, 0);
    send_line(c->sock, s);
    free(s);
    json_decref(resp);
}

static void handle_authorize(Client *c, json_t *id, json_t *params) {
    // Accept any user/pass
    c->is_authorized = true;
    send_reply_true(c->sock, id);
    
    // Send initial diff
    json_t *dreq = json_object();
    json_object_set_new(dreq, "id", json_null());
    json_object_set_new(dreq, "method", json_string("mining.set_difficulty"));
    json_t *dparams = json_array();
    
    // Start with a reasonable difficulty, e.g. 2048 or config based
    // For now hardcoded 2048
    c->current_diff = 2048.0;
    c->previous_diff = 2048.0;
    c->last_retarget_time = time(NULL);
    
    json_array_append_new(dparams, json_real(c->current_diff));
    json_object_set_new(dreq, "params", dparams);
    char *ds = json_dumps(dreq, 0);
    send_line(c->sock, ds);
    free(ds);
    json_decref(dreq);

    // Send current job
    Template tmpl;
    if (bitcoin_get_latest_job(&tmpl)) {
        // ... (notify logic duplication avoided by broadcast, but here we unicast)
        // Re-implement unicast notify
        json_t *nreq = json_object();
        json_object_set_new(nreq, "id", json_null());
        json_object_set_new(nreq, "method", json_string("mining.notify"));
        json_t *nparams = json_array();
        
        json_array_append_new(nparams, json_string(tmpl.job_id));
        json_array_append_new(nparams, json_string(tmpl.prev_hash_stratum));
        
        int v = c->coinbase_variant;
        // fallback if variant not available in tmpl? tmpl has all.
        json_array_append_new(nparams, json_string(tmpl.coinb1[v]));
        json_array_append_new(nparams, json_string(tmpl.coinb2[v]));
        
        json_t *merkle = json_array();
        for (size_t i = 0; i < tmpl.merkle_count; i++) {
            json_array_append_new(merkle, json_string(tmpl.merkle_branch[i]));
        }
        json_array_append_new(nparams, merkle);
        
        json_array_append_new(nparams, json_string(tmpl.version_hex));
        json_array_append_new(nparams, json_string(tmpl.nbits_hex));
        json_array_append_new(nparams, json_string(tmpl.ntime_hex));
        json_array_append_new(nparams, json_boolean(tmpl.clean_jobs));
        
        json_object_set_new(nreq, "params", nparams);
        char *ns = json_dumps(nreq, 0);
        send_line(c->sock, ns);
        free(ns);
        json_decref(nreq);
        
        bitcoin_free_job(&tmpl);
    }

    // [ECO MODE] Wake up if this is the first miner
    if (stratum_get_client_count() == 1) {
        log_info("💤 -> ⚡ First miner connected! Waking up gateway...");
        bitcoin_update_template(true);
    }
}

static void handle_submit(Client *c, json_t *id, json_t *params) {
    if (!c->is_authorized) {
        send_error(c->sock, id, 24, "Unauthorized");
        return;
    }
    
    // params: [worker, job_id, extranonce2, ntime, nonce]
    if (json_array_size(params) < 5) {
        send_error(c->sock, id, 20, "Invalid parameters");
        return;
    }

    const char *job_id = json_string_value(json_array_get(params, 1));
    const char *en2 = json_string_value(json_array_get(params, 2));
    const char *ntime = json_string_value(json_array_get(params, 3));
    const char *nonce_hex = json_string_value(json_array_get(params, 4));

    if (!job_id || !en2 || !ntime || !nonce_hex) {
        send_error(c->sock, id, 20, "Invalid parameters");
        return;
    }

    uint32_t nonce = (uint32_t)strtoul(nonce_hex, NULL, 16);
    uint32_t ntime_val = (uint32_t)strtoul(ntime, NULL, 16);

    // Duplicate check
    if (check_duplicate_share(nonce, en2, ntime_val)) {
        send_error(c->sock, id, 22, "Duplicate share");
        return;
    }

    char full_en[64];
    snprintf(full_en, sizeof(full_en), "%s%s", c->extranonce1_hex, en2);

    // [New] Use current_diff or previous_diff?
    // Simplified: use current_diff. Real pools handle diff transition gracefully.
    double share_diff = 0.0;
    
    // Validate
    int res = bitcoin_validate_and_submit(job_id, full_en, ntime, nonce, 0, c->current_diff, &share_diff);
    
    if (res > 0) {
        send_reply_true(c->sock, id);
        
        // Stats update
        c->shares_in_window++;
        c->total_shares++;
        c->last_submit_time = time(NULL);
        if (share_diff > c->best_diff) c->best_diff = share_diff;
        
        // Log valid share
        record_share(c->extranonce1_hex, c->current_diff, "(hash_calc_inside)", (res == 2));
        
        // Vardiff Logic (Simple)
        time_t now = time(NULL);
        if (now - c->last_retarget_time > g_config.diff_retarget_interval) {
            double spm = (double)c->shares_in_window / ((double)(now - c->last_retarget_time) / 60.0);
            
            double new_diff = c->current_diff;
            if (spm > 20.0) new_diff *= 2.0;
            else if (spm < 5.0) new_diff /= 2.0;
            
            if (new_diff < 1024.0) new_diff = 1024.0; // Min diff
            
            if (fabs(new_diff - c->current_diff) > 0.1) {
                c->previous_diff = c->current_diff;
                c->current_diff = new_diff;
                
                json_t *dreq = json_object();
                json_object_set_new(dreq, "id", json_null());
                json_object_set_new(dreq, "method", json_string("mining.set_difficulty"));
                json_t *dparams = json_array();
                json_array_append_new(dparams, json_real(c->current_diff));
                json_object_set_new(dreq, "params", dparams);
                char *ds = json_dumps(dreq, 0);
                send_line(c->sock, ds);
                free(ds);
                json_decref(dreq);
                
                log_info("VarDiff ID=%d: %.0f -> %.0f (SPM: %.2f, Shares: %d)", 
                         c->id, c->previous_diff, c->current_diff, spm, c->shares_in_window);
            }
            
            c->shares_in_window = 0;
            c->last_retarget_time = now;
        }

    } else {
        send_error(c->sock, id, 21, "Job not found or invalid share");
    }
}

static void *client_thread(void *arg) {
    Client *c = (Client*)arg;
    char buf[1024];
    int rpos = 0;
    
    while (1) {
        int n = recv(c->sock, buf + rpos, sizeof(buf) - rpos - 1, 0);
        if (n <= 0) break;
        rpos += n;
        buf[rpos] = 0;
        
        char *start = buf;
        while (1) {
            char *end = strchr(start, '\n');
            if (!end) break;
            *end = 0;
            
            if (strlen(start) > 0) {
                json_error_t err;
                json_t *req = json_loads(start, 0, &err);
                if (req) {
                    json_t *id = json_object_get(req, "id");
                    const char *method = json_string_value(json_object_get(req, "method"));
                    json_t *params = json_object_get(req, "params");
                    
                    if (method) {
                        if (strcmp(method, "mining.subscribe") == 0) handle_subscribe(c, id, params);
                        else if (strcmp(method, "mining.authorize") == 0) handle_authorize(c, id, params);
                        else if (strcmp(method, "mining.submit") == 0) handle_submit(c, id, params);
                        else if (strcmp(method, "mining.configure") == 0) send_reply_true(c->sock, id); 
                    }
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
        int cfd = accept(sfd, (struct sockaddr *)&c_addr, &l);
        if (cfd >= 0) {
            pthread_mutex_lock(&g_clients_lock);
            int idx = -1;
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (!g_clients[i].active) {
                    idx = i;
                    break;
                }
            }
            if (idx >= 0) {
                g_clients[idx].id = idx + 1;
                g_clients[idx].sock = cfd;
                g_clients[idx].addr = c_addr;
                g_clients[idx].active = true;
                g_clients[idx].is_authorized = false;
                g_clients[idx].total_shares = 0;
                g_clients[idx].shares_in_window = 0;
                g_clients[idx].best_diff = 0;
                g_clients[idx].hashrate_est = 0;
                g_clients[idx].last_submit_time = 0;
                g_clients[idx].coinbase_variant = CB_VARIANT_DEFAULT;
                pthread_create(&g_clients[idx].thread_id, NULL, client_thread, &g_clients[idx]);
                log_info("Client %d connected from %s", idx + 1, inet_ntoa(c_addr.sin_addr));
            } else {
                close(cfd);
                log_error("Too many clients, rejected");
            }
            pthread_mutex_unlock(&g_clients_lock);
        }
    }
    return NULL;
}

void stratum_broadcast_job(const Template *tmpl) {
    if (!tmpl->valid) return;
    
    // Pre-calculate JSON strings for variants
    char *notifies[MAX_COINBASE_VARIANTS];
    
    for (int v = 0; v < MAX_COINBASE_VARIANTS; v++) {
        json_t *nreq = json_object();
        json_object_set_new(nreq, "id", json_null());
        json_object_set_new(nreq, "method", json_string("mining.notify"));
        json_t *nparams = json_array();
        
        json_array_append_new(nparams, json_string(tmpl->job_id));
        json_array_append_new(nparams, json_string(tmpl->prev_hash_stratum));
        json_array_append_new(nparams, json_string(tmpl->coinb1[v]));
        json_array_append_new(nparams, json_string(tmpl->coinb2[v]));
        
        json_t *merkle = json_array();
        for (size_t i = 0; i < tmpl.merkle_count; i++) {
            json_array_append_new(merkle, json_string(tmpl->merkle_branch[i]));
        }
        json_array_append_new(nparams, merkle);
        
        json_array_append_new(nparams, json_string(tmpl->version_hex));
        json_array_append_new(nparams, json_string(tmpl->nbits_hex));
        json_array_append_new(nparams, json_string(tmpl->ntime_hex));
        json_array_append_new(nparams, json_boolean(tmpl->clean_jobs));
        
        json_object_set_new(nreq, "params", nparams);
        notifies[v] = json_dumps(nreq, 0);
        json_decref(nreq);
    }
    
    pthread_mutex_lock(&g_clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (g_clients[i].active && g_clients[i].is_authorized) {
            int v = g_clients[i].coinbase_variant;
            send_line(g_clients[i].sock, notifies[v]);
        }
    }
    pthread_mutex_unlock(&g_clients_lock);
    
    for (int v = 0; v < MAX_COINBASE_VARIANTS; v++) free(notifies[v]);
}

int stratum_start(void) {
    pthread_t t;
    return pthread_create(&t, NULL, server_thread, NULL);
}
