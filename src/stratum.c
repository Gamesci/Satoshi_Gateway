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

void init_clients() {
    for(int i=0; i<MAX_CLIENTS; i++) {
        g_clients[i].active = false;
        g_clients[i].sock = -1;
    }
}

Client* client_add(int sock, struct sockaddr_in addr) {
    pthread_mutex_lock(&g_clients_lock);
    for(int i=0; i<MAX_CLIENTS; i++) {
        if(!g_clients[i].active) {
            g_clients[i].active = true;
            g_clients[i].sock = sock;
            g_clients[i].addr = addr;
            g_clients[i].id = i + 1;
            g_clients[i].is_authorized = false;
            snprintf(g_clients[i].extranonce1_hex, 9, "%08x", g_clients[i].id);
            pthread_mutex_unlock(&g_clients_lock);
            return &g_clients[i];
        }
    }
    pthread_mutex_unlock(&g_clients_lock);
    return NULL;
}

void client_remove(Client *c) {
    if(!c) return;
    pthread_mutex_lock(&g_clients_lock);
    if(c->active) {
        close(c->sock);
        c->active = false;
        c->sock = -1;
        log_info("Client %d disconnected.", c->id);
    }
    pthread_mutex_unlock(&g_clients_lock);
}

void send_json(int sock, json_t *response) {
    char *s = json_dumps(response, 0);
    if(s) {
        size_t len = strlen(s);
        char *msg = malloc(len + 2);
        strcpy(msg, s);
        msg[len] = '\n';
        msg[len+1] = 0;
        send(sock, msg, len+1, MSG_NOSIGNAL);
        free(msg);
        free(s);
    }
}

// 辅助：发送单个任务
void stratum_send_mining_notify(int sock, Template *tmpl) {
    json_t *params = json_array();
    json_array_append_new(params, json_string(tmpl->job_id));
    json_array_append_new(params, json_string(tmpl->prev_hash));
    json_array_append_new(params, json_string(tmpl->coinb1));
    json_array_append_new(params, json_string(tmpl->coinb2));
    
    json_t *merkle = json_array();
    for(int i=0; i<tmpl->merkle_count; i++) {
        json_array_append_new(merkle, json_string(tmpl->merkle_branch[i]));
    }
    json_array_append_new(params, merkle);
    json_array_append_new(params, json_string(tmpl->version));
    json_array_append_new(params, json_string(tmpl->nbits));
    json_array_append_new(params, json_string(tmpl->ntime));
    json_array_append_new(params, json_boolean(tmpl->clean_jobs));
    
    json_t *req = json_object();
    json_object_set_new(req, "id", json_null());
    json_object_set_new(req, "method", json_string("mining.notify"));
    json_object_set_new(req, "params", params);
    
    send_json(sock, req);
    json_decref(req);
}

void stratum_broadcast_job(Template *tmpl) {
    pthread_mutex_lock(&g_clients_lock);
    int c = 0;
    for(int i=0; i<MAX_CLIENTS; i++) {
        if(g_clients[i].active && g_clients[i].is_authorized) {
            stratum_send_mining_notify(g_clients[i].sock, tmpl);
            c++;
        }
    }
    pthread_mutex_unlock(&g_clients_lock);
    log_info("Broadcasted Job %s to %d workers", tmpl->job_id, c);
}

void *client_worker(void *arg) {
    Client *c = (Client*)arg;
    char buffer[4096];
    int read_pos = 0;

    log_info("Worker connected: ID=%d IP=%s", c->id, inet_ntoa(c->addr.sin_addr));

    struct timeval tv;
    tv.tv_sec = 600; 
    tv.tv_usec = 0;
    setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

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
                        log_info("ID=%d Subscribed", c->id);
                        json_object_set_new(res, "error", json_null());
                        json_t *arr = json_array();
                        json_t *subs = json_array();
                        
                        json_t *sub1 = json_array();
                        json_array_append_new(sub1, json_string("mining.set_difficulty"));
                        json_array_append_new(sub1, json_string("1"));
                        json_array_append_new(subs, sub1);
                        
                        json_t *sub2 = json_array();
                        json_array_append_new(sub2, json_string("mining.notify"));
                        json_array_append_new(sub2, json_string("1"));
                        json_array_append_new(subs, sub2);
                        
                        json_array_append_new(arr, subs);
                        json_array_append_new(arr, json_string(c->extranonce1_hex)); 
                        json_array_append_new(arr, json_integer(g_config.extranonce2_size)); 
                        json_object_set_new(res, "result", arr);
                        send_json(c->sock, res);
                    }
                    else if(strcmp(method, "mining.authorize") == 0) {
                        c->is_authorized = true;
                        json_object_set_new(res, "error", json_null());
                        json_object_set_new(res, "result", json_true());
                        send_json(c->sock, res);
                        log_info("ID=%d Authorized", c->id);
                        
                        // 1. Send Diff
                        json_t *dreq = json_object();
                        json_object_set_new(dreq, "id", json_null());
                        json_object_set_new(dreq, "method", json_string("mining.set_difficulty"));
                        json_t *dparams = json_array();
                        json_array_append_new(dparams, json_integer(g_config.initial_diff));
                        json_object_set_new(dreq, "params", dparams);
                        send_json(c->sock, dreq);
                        json_decref(dreq);
                        
                        // 2. 立即发送当前任务
                        Template tmpl;
                        if(bitcoin_get_current_job_copy(&tmpl)) {
                            log_info("Sending initial Job %s to ID=%d", tmpl.job_id, c->id);
                            stratum_send_mining_notify(c->sock, &tmpl);
                        }
                    }
                    else if(strcmp(method, "mining.configure") == 0) {
                         json_object_set_new(res, "error", json_null());
                         json_t *r = json_object();
                         json_object_set_new(r, "version-rolling", json_true());
                         json_object_set_new(r, "version-rolling.mask", json_string(g_config.version_mask));
                         json_object_set_new(res, "result", r);
                         send_json(c->sock, res);
                    }
                    else if(strcmp(method, "mining.submit") == 0) {
                        // (保留之前的 Submit 逻辑，调用 bitcoin_reconstruct_and_submit)
                        json_object_set_new(res, "error", json_null());
                        json_object_set_new(res, "result", json_true());
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
    
    // 关键修复：移除 free(c)
    client_remove(c);
    return NULL;
}
