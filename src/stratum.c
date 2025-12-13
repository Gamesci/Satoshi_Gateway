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

#define SHARE_CACHE_SIZE 2048
typedef struct { char key[256]; } ShareEntry; // 扩大缓存键值大小
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
    strcpy(g_share_cache[g_share_head].key, key); 
    g_share_head = (g_share_head+1)%SHARE_CACHE_SIZE;
    pthread_mutex_unlock(&g_cache_lock); 
    return false;
}

void init_clients() { 
    for(int i=0; i<MAX_CLIENTS; i++) { 
        g_clients[i].active=false; 
        g_clients[i].sock=-1; 
    } 
}

Client* client_add(int sock, struct sockaddr_in addr) {
    pthread_mutex_lock(&g_clients_lock);
    for(int i=0; i<MAX_CLIENTS; i++) {
        if(!g_clients[i].active) {
            g_clients[i].active=true; 
            g_clients[i].sock=sock; 
            g_clients[i].addr=addr; 
            g_clients[i].id=i+1; 
            g_clients[i].is_authorized=false;
            
            // VarDiff Init
            g_clients[i].current_diff = (double)g_config.initial_diff;
            g_clients[i].last_retarget_time = time(NULL);
            g_clients[i].shares_in_window = 0;

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
        c->active=false; 
        c->sock=-1; 
        log_info("Client %d Disconnected", c->id); 
    }
    pthread_mutex_unlock(&g_clients_lock);
}

void send_json(int sock, json_t *response) {
    char *s = json_dumps(response, 0);
    if(s) { 
        size_t l=strlen(s); 
        char *m=malloc(l+2); 
        if(m) {
            strcpy(m, s); m[l]='\n'; m[l+1]=0; 
            send(sock, m, l+1, MSG_NOSIGNAL); 
            free(m); 
        }
        free(s); 
    }
}

void send_difficulty(Client *c, double diff) {
    json_t *res = json_object();
    json_object_set_new(res, "id", json_null());
    json_object_set_new(res, "method", json_string("mining.set_difficulty"));
    json_t *params = json_array();
    json_array_append_new(params, json_real(diff));
    json_object_set_new(res, "params", params);
    send_json(c->sock, res);
    json_decref(res);
}

void stratum_send_mining_notify(int sock, Template *tmpl) {
    json_t *p = json_array();
    json_array_append_new(p, json_string(tmpl->job_id));
    json_array_append_new(p, json_string(tmpl->prev_hash_stratum));
    json_array_append_new(p, json_string(tmpl->coinb1));
    json_array_append_new(p, json_string(tmpl->coinb2));
    json_t *m = json_array(); 
    for(int i=0; i<tmpl->merkle_count; i++) 
        json_array_append_new(m, json_string(tmpl->merkle_branch[i]));
    
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

// [FIX] 广播优化：移除全局锁内的网络 IO，防止死锁
void stratum_broadcast_job(Template *tmpl) {
    int sockets[MAX_CLIENTS];
    int count = 0;

    pthread_mutex_lock(&g_clients_lock); 
    for(int i=0; i<MAX_CLIENTS; i++) { 
        if(g_clients[i].active && g_clients[i].is_authorized) { 
            sockets[count++] = g_clients[i].sock;
        } 
    }
    pthread_mutex_unlock(&g_clients_lock);
    
    // 在锁外发送
    for(int i=0; i<count; i++) {
        stratum_send_mining_notify(sockets[i], tmpl);
    }
    
    if(count > 0) log_info("Broadcast Job %s to %d miners", tmpl->job_id, count);
}

void *client_worker(void *arg) {
    Client *c = (Client*)arg; 
    char buf[4096]; 
    int rpos=0;
    log_info("Worker Connected: ID=%d IP=%s", c->id, inet_ntoa(c->addr.sin_addr));
    
    struct timeval tv; 
    tv.tv_sec=600; 
    tv.tv_usec=0; 
    setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    while(c->active) {
        ssize_t n = recv(c->sock, buf+rpos, sizeof(buf)-1-rpos, 0);
        if(n<=0) break; 
        rpos+=n; 
        buf[rpos]=0;
        
        char *start=buf; 
        char *end;
        while((end=strchr(start, '\n'))!=NULL) {
            *end=0;
            if(strlen(start)>0) {
                json_error_t e; 
                json_t *req=json_loads(start, 0, &e);
                if(req) {
                    const char *m = json_string_value(json_object_get(req, "method"));
                    json_t *id = json_object_get(req, "id");
                    json_t *res = json_object(); 
                    json_object_set(res, "id", id);
                    
                    if(!m) {}
                    else if(strcmp(m, "mining.subscribe")==0) {
                        log_info("ID=%d Subscribed", c->id);
                        json_object_set_new(res, "error", json_null());
                        json_t *arr=json_array(); 
                        json_t *subs=json_array();
                        json_t *s1=json_array(); 
                        json_array_append_new(s1, json_string("mining.set_difficulty")); 
                        json_array_append_new(s1, json_string("1")); 
                        json_array_append_new(subs, s1);
                        json_t *s2=json_array(); 
                        json_array_append_new(s2, json_string("mining.notify")); 
                        json_array_append_new(s2, json_string("1")); 
                        json_array_append_new(subs, s2);
                        
                        json_array_append_new(arr, subs);
                        json_array_append_new(arr, json_string(c->extranonce1_hex)); 
                        json_array_append_new(arr, json_integer(g_config.extranonce2_size)); 
                        json_object_set_new(res, "result", arr); 
                        send_json(c->sock, res);
                    }
                    else if(strcmp(m, "mining.authorize")==0) {
                        c->is_authorized=true;
                        json_object_set_new(res, "error", json_null()); 
                        json_object_set_new(res, "result", json_true());
                        send_json(c->sock, res); 
                        log_info("ID=%d Authorized", c->id);
                        
                        // VarDiff: Send initial difficulty
                        send_difficulty(c, c->current_diff);
                        
                        Template *t=malloc(sizeof(Template));
                        if(t) { 
                            if(bitcoin_get_latest_job(t)) 
                                stratum_send_mining_notify(c->sock, t); 
                            free(t); 
                        }
                    }
                    else if(strcmp(m, "mining.configure")==0) {
                         char ms[16]; sprintf(ms, "%08x", g_config.version_mask);
                         json_object_set_new(res, "error", json_null());
                         json_t *r=json_object(); 
                         json_object_set_new(r, "version-rolling", json_true()); 
                         json_object_set_new(r, "version-rolling.mask", json_string(ms));
                         json_object_set_new(res, "result", r); 
                         send_json(c->sock, res);
                    }
                    else if(strcmp(m, "mining.submit")==0) {
                        json_t *p=json_object_get(req, "params");
                        const char *jid = json_string_value(json_array_get(p, 1));
                        const char *en2 = json_string_value(json_array_get(p, 2));
                        const char *nt = json_string_value(json_array_get(p, 3));
                        const char *nh = json_string_value(json_array_get(p, 4));
                        const char *vh = ""; 
                        if(json_array_size(p)>=6) vh = json_string_value(json_array_get(p, 5));

                        char dk[256]; 
                        // [FIX] 增加 ntime (nt) 和 version (vh) 到重复检查 Key 中
                        snprintf(dk, sizeof(dk), "%s_%s_%s_%s_%s", jid, en2, nh, nt, vh ? vh : "0");
                        
                        if(is_duplicate_share(dk)) {
                            log_info("Dup Share: %s", dk);
                            json_object_set_new(res, "result", json_false());
                            json_t *e=json_array(); 
                            json_array_append_new(e, json_integer(22)); 
                            json_array_append_new(e, json_string("Duplicate")); 
                            json_object_set_new(res, "error", e);
                        } else {
                            uint32_t vm = 0; 
                            if(vh && strlen(vh)>0) vm=strtoul(vh, NULL, 16);
                            
                            uint32_t n = (uint32_t)strtoul(nh, NULL, 16);
                            char full[64]; 
                            snprintf(full, sizeof(full), "%s%s", c->extranonce1_hex, en2);
                            
                            // [FIX] 传入 c->current_diff 进行难度验证
                            int ret = bitcoin_validate_and_submit(jid, full, nt, n, vm, c->current_diff);
                            
                            if(ret==0) {
                                json_object_set_new(res, "result", json_false());
                                json_t *e=json_array(); 
                                json_array_append_new(e, json_integer(21)); 
                                json_array_append_new(e, json_string("Stale or Low Difficulty")); 
                                json_object_set_new(res, "error", e);
                            } else {
                                json_object_set_new(res, "result", json_true()); 
                                json_object_set_new(res, "error", json_null());
                                
                                // VarDiff Logic
                                c->shares_in_window++;
                                time_t now = time(NULL);
                                double dt = difftime(now, c->last_retarget_time);
                                if (dt >= 60.0) {
                                    double spm = (c->shares_in_window / dt) * 60.0;
                                    double target = (double)g_config.vardiff_target;
                                    double new_diff = c->current_diff;
                                    bool changed = false;
                                    
                                    if (spm < target * 0.4) { new_diff /= 2.0; changed=true; }
                                    else if (spm > target * 1.5) { new_diff *= 2.0; changed=true; }
                                    
                                    if(new_diff < g_config.vardiff_min_diff) new_diff=g_config.vardiff_min_diff;
                                    if(new_diff > g_config.vardiff_max_diff) new_diff=g_config.vardiff_max_diff;

                                    if(changed && new_diff != c->current_diff) {
                                        log_info("VarDiff ID=%d: %.0f -> %.0f (SPM: %.1f)", c->id, c->current_diff, new_diff, spm);
                                        c->current_diff = new_diff;
                                        send_difficulty(c, new_diff);
                                    }
                                    c->last_retarget_time = now;
                                    c->shares_in_window = 0;
                                }
                            }
                        }
                        send_json(c->sock, res);
                    }
                    json_decref(res); 
                    json_decref(req);
                }
            }
            start=end+1;
        }
        if(start < buf+rpos) { 
            size_t rem = buf+rpos-start; 
            memmove(buf, start, rem); 
            rpos=rem; 
        } else { 
            rpos=0; 
        }
    }
    client_remove(c); 
    return NULL;
}

void *server_thread(void *arg) {
    (void)arg; 
    int sfd; 
    struct sockaddr_in addr; 
    int opt=1; 
    init_clients();
    
    if ((sfd=socket(AF_INET, SOCK_STREAM, 0))==0) exit(1);
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) exit(1);
    
    addr.sin_family=AF_INET; 
    addr.sin_addr.s_addr=INADDR_ANY; 
    addr.sin_port=htons(g_config.stratum_port);
    
    if (bind(sfd, (struct sockaddr *)&addr, sizeof(addr))<0) exit(1);
    if (listen(sfd, 10)<0) exit(1);
    
    log_info("Stratum Server Listening on port %d", g_config.stratum_port);
    
    while(1) {
        struct sockaddr_in c_addr; 
        socklen_t l=sizeof(c_addr);
        int ns = accept(sfd, (struct sockaddr *)&c_addr, &l);
        if (ns>=0) {
            Client *c = client_add(ns, c_addr);
            if(c) { 
                pthread_create(&c->thread_id, NULL, client_worker, c); 
                pthread_detach(c->thread_id); 
            } else {
                close(ns);
            }
        }
    }
    return NULL;
}

int stratum_start_thread() { 
    pthread_t t; 
    return pthread_create(&t, NULL, server_thread, NULL); 
}
