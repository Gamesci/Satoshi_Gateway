#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h> 
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#include <jansson.h>
#include "stratum.h"
#include "config.h"
#include "utils.h"

static Client g_clients[MAX_CLIENTS];
static pthread_mutex_t g_clients_lock = PTHREAD_MUTEX_INITIALIZER;

// --- 防重提交缓存 (简单环形 buffer) ---
#define SHARE_CACHE_SIZE 1024
typedef struct {
    char key[128]; // "jobid_nonce_extranonce2"
} ShareEntry;
static ShareEntry g_share_cache[SHARE_CACHE_SIZE];
static int g_share_head = 0;
static pthread_mutex_t g_cache_lock = PTHREAD_MUTEX_INITIALIZER;

bool is_duplicate_share(const char *key) {
    pthread_mutex_lock(&g_cache_lock);
    for(int i=0; i<SHARE_CACHE_SIZE; i++) {
        if(strcmp(g_share_cache[i].key, key) == 0) {
            pthread_mutex_unlock(&g_cache_lock);
            return true;
        }
    }
    // Add new
    strcpy(g_share_cache[g_share_head].key, key);
    g_share_head = (g_share_head + 1) % SHARE_CACHE_SIZE;
    pthread_mutex_unlock(&g_cache_lock);
    return false;
}

// ... init_clients, client_add, client_remove, send_json 保持不变 ...
// 请保留这些基础函数

// 辅助：发送单个任务
void stratum_send_mining_notify(int sock, Template *tmpl) {
    json_t *params = json_array();
    json_array_append_new(params, json_string(tmpl->job_id));
    json_array_append_new(params, json_string(tmpl->prev_hash_stratum)); // Use Stratum Format
    json_array_append_new(params, json_string(tmpl->coinb1));
    json_array_append_new(params, json_string(tmpl->coinb2));
    
    json_t *merkle = json_array();
    for(int i=0; i<tmpl->merkle_count; i++) {
        json_array_append_new(merkle, json_string(tmpl->merkle_branch[i]));
    }
    json_array_append_new(params, merkle);
    json_array_append_new(params, json_string(tmpl->version_hex)); // BE Hex
    json_array_append_new(params, json_string(tmpl->nbits_hex));
    json_array_append_new(params, json_string(tmpl->ntime_hex));
    json_array_append_new(params, json_boolean(tmpl->clean_jobs));
    
    json_t *req = json_object();
    json_object_set_new(req, "id", json_null());
    json_object_set_new(req, "method", json_string("mining.notify"));
    json_object_set_new(req, "params", params);
    
    send_json(sock, req);
    json_decref(req);
}

// ... stratum_broadcast_job 保持不变 ...

void *client_worker(void *arg) {
    Client *c = (Client*)arg;
    char buffer[4096];
    int read_pos = 0;

    log_info("Worker connected: ID=%d", c->id);
    
    // Timeout setup... (Keep original)

    while(c->active) {
        ssize_t n = recv(c->sock, buffer + read_pos, sizeof(buffer) - 1 - read_pos, 0);
        if(n <= 0) break;
        read_pos += n;
        buffer[read_pos] = 0;

        char *start = buffer;
        char *end;
        while((end = strchr(start, '\n')) != NULL) {
            *end = 0;
            if(strlen(start) > 0) {
                json_error_t err;
                json_t *req = json_loads(start, 0, &err);
                if(req) {
                    const char *method = json_string_value(json_object_get(req, "method"));
                    json_t *id = json_object_get(req, "id");
                    json_t *res = json_object();
                    json_object_set(res, "id", id);
                    
                    if(!method) { /* ignore */ }
                    else if(strcmp(method, "mining.subscribe") == 0) {
                        // Subscribe logic (Keep original)
                        json_object_set_new(res, "error", json_null());
                        json_t *arr = json_array();
                        json_t *subs = json_array();
                        json_array_append_new(subs, json_string("mining.set_difficulty"));
                        json_array_append_new(subs, json_string("1"));
                        json_array_append_new(subs, json_string("mining.notify"));
                        json_array_append_new(subs, json_string("1"));
                        json_array_append_new(arr, subs);
                        json_array_append_new(arr, json_string(c->extranonce1_hex)); 
                        json_array_append_new(arr, json_integer(g_config.extranonce2_size)); 
                        json_object_set_new(res, "result", arr);
                        send_json(c->sock, res);
                    }
                    else if(strcmp(method, "mining.authorize") == 0) {
                        // Auth logic (Keep original)
                        c->is_authorized = true;
                        json_object_set_new(res, "result", json_true());
                        json_object_set_new(res, "error", json_null());
                        send_json(c->sock, res);
                        
                        // Send Diff
                        json_t *dreq = json_object();
                        json_object_set_new(dreq, "method", json_string("mining.set_difficulty"));
                        json_t *dparams = json_array();
                        json_array_append_new(dparams, json_integer(g_config.initial_diff));
                        json_object_set_new(dreq, "params", dparams);
                        send_json(c->sock, dreq);
                        json_decref(dreq);
                        
                        // Send Latest Job
                        Template tmpl;
                        if(bitcoin_get_latest_job(&tmpl)) {
                            stratum_send_mining_notify(c->sock, &tmpl);
                        }
                    }
                    else if(strcmp(method, "mining.configure") == 0) {
                         // Configure logic (Keep original)
                         json_object_set_new(res, "result", json_true()); // Simplified result
                         json_object_set_new(res, "error", json_null());
                         send_json(c->sock, res);
                    }
                    else if(strcmp(method, "mining.submit") == 0) {
                        json_t *params = json_object_get(req, "params");
                        const char *job_id = json_string_value(json_array_get(params, 1));
                        const char *en2 = json_string_value(json_array_get(params, 2));
                        const char *ntime = json_string_value(json_array_get(params, 3));
                        const char *nonce_hex = json_string_value(json_array_get(params, 4));
                        
                        // Duplicate Check
                        char dup_key[128];
                        snprintf(dup_key, sizeof(dup_key), "%s_%s_%s", job_id, en2, nonce_hex);
                        
                        if (is_duplicate_share(dup_key)) {
                            log_info("Duplicate Share Rejected: %s", dup_key);
                            json_object_set_new(res, "result", json_false());
                            json_t *err_arr = json_array();
                            json_array_append_new(err_arr, json_integer(22));
                            json_array_append_new(err_arr, json_string("Duplicate share"));
                            json_object_set_new(res, "error", err_arr);
                        } else {
                            uint32_t ver_mask = 0;
                            if(json_array_size(params) >= 6) {
                                const char *ver_hex = json_string_value(json_array_get(params, 5));
                                if(ver_hex) ver_mask = strtoul(ver_hex, NULL, 16);
                            }
                            
                            uint32_t nonce = (uint32_t)strtoul(nonce_hex, NULL, 16);
                            char full_extra[64];
                            snprintf(full_extra, sizeof(full_extra), "%s%s", c->extranonce1_hex, en2);
                            
                            int ret = bitcoin_validate_and_submit(job_id, full_extra, ntime, nonce, ver_mask);
                            
                            if (ret == 0) {
                                // Stale or Invalid Job ID
                                json_object_set_new(res, "result", json_false());
                                json_t *err_arr = json_array();
                                json_array_append_new(err_arr, json_integer(21));
                                json_array_append_new(err_arr, json_string("Job not found (=stale)"));
                                json_object_set_new(res, "error", err_arr);
                            } else {
                                // Valid (Low Diff or High Diff) -> Accept
                                json_object_set_new(res, "result", json_true());
                                json_object_set_new(res, "error", json_null());
                                if(ret == 2) log_info(">>> BLOCK FOUND! <<<");
                                else log_info("Share Accepted (Job %s)", job_id);
                            }
                        }
                        send_json(c->sock, res);
                    }
                    
                    json_decref(res);
                    json_decref(req);
                }
            }
            start = end + 1;
        }
        if(start < buffer + read_pos) {
            size_t rem = buffer + read_pos - start;
            memmove(buffer, start, rem);
            read_pos = rem;
        } else {
            read_pos = 0;
        }
    }
    
    client_remove(c);
    return NULL;
}
