#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <jansson.h>
#include "stratum.h"
#include "config.h"

static int g_client_sock = 0;
static pthread_mutex_t g_sock_lock = PTHREAD_MUTEX_INITIALIZER;

void stratum_broadcast_job(Template *tmpl) {
    if (g_client_sock == 0) return;
    
    // mining.notify
    json_t *params = json_array();
    json_array_append_new(params, json_string(tmpl->job_id));
    json_array_append_new(params, json_string(tmpl->prev_hash));
    json_array_append_new(params, json_string(tmpl->coinb1));
    json_array_append_new(params, json_string(tmpl->coinb2));
    
    json_t *merkle = json_array();
    // Fill merkle branch
    json_array_append_new(params, merkle);
    
    json_array_append_new(params, json_string(tmpl->version));
    json_array_append_new(params, json_string(tmpl->nbits));
    json_array_append_new(params, json_string(tmpl->ntime));
    json_array_append_new(params, json_boolean(tmpl->clean_jobs));
    
    json_t *req = json_object();
    json_object_set_new(req, "id", json_null());
    json_object_set_new(req, "method", json_string("mining.notify"));
    json_object_set_new(req, "params", params);
    
    char *s = json_dumps(req, 0);
    strcat(s, "\n");
    send(g_client_sock, s, strlen(s), 0);
    free(s);
    json_decref(req);
    printf("[STRATUM] Sent Job %s\n", tmpl->job_id);
}

void *client_worker(void *arg) {
    int sock = *(int*)arg;
    free(arg);
    char buffer[4096];
    
    // 设置全局 Socket (简化版只支持单矿机)
    pthread_mutex_lock(&g_sock_lock);
    g_client_sock = sock;
    pthread_mutex_unlock(&g_sock_lock);

    while(1) {
        ssize_t n = recv(sock, buffer, sizeof(buffer)-1, 0);
        if(n <= 0) break;
        buffer[n] = 0;
        
        // 简单处理粘包: 假设每条消息以 \n 结尾，只处理第一条
        char *ptr = strtok(buffer, "\n");
        while(ptr) {
            json_error_t err;
            json_t *req = json_loads(ptr, 0, &err);
            if(req) {
                const char *m = json_string_value(json_object_get(req, "method"));
                json_t *id = json_object_get(req, "id");
                json_t *res = json_object();
                json_object_set(res, "id", id);
                json_object_set_new(res, "error", json_null());
                
                if(strcmp(m, "mining.subscribe") == 0) {
                    json_t *arr = json_array();
                    json_t *subs = json_array();
                    json_array_append_new(subs, json_string("mining.set_difficulty"));
                    json_array_append_new(subs, json_string("1"));
                    json_array_append_new(subs, json_string("mining.notify"));
                    json_array_append_new(subs, json_string("1"));
                    json_array_append_new(arr, subs);
                    json_array_append_new(arr, json_string("00000001")); // ExtraNonce1
                    json_array_append_new(arr, json_integer(g_config.extranonce2_size));
                    json_object_set_new(res, "result", arr);
                } 
                else if(strcmp(m, "mining.authorize") == 0) {
                    json_object_set_new(res, "result", json_true());
                    // Auth 后立即发送难度
                    // 实际应该单独发 notify
                }
                else if(strcmp(m, "mining.configure") == 0) {
                    // Bitaxe 关键配置
                    json_t *r = json_object();
                    json_object_set_new(r, "version-rolling", json_true());
                    json_object_set_new(r, "version-rolling.mask", json_string(g_config.version_mask));
                    json_object_set_new(res, "result", r);
                }
                else if(strcmp(m, "mining.submit") == 0) {
                    printf("[STRATUM] Share submitted! (Validating...)\n");
                    // 这里需要验证 Share 并提交 submitblock
                    // 为简化，直接打印日志
                    json_object_set_new(res, "result", json_true());
                }
                
                char *s = json_dumps(res, 0);
                send(sock, s, strlen(s), 0);
                send(sock, "\n", 1, 0);
                free(s);
                json_decref(res);
                json_decref(req);
            }
            ptr = strtok(NULL, "\n");
        }
    }
    close(sock);
    return NULL;
}

void *server_thread_func(void *arg) {
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    (void)arg;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(g_config.stratum_port);
    
    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);
    
    while((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) >= 0) {
        pthread_t t;
        int *p = malloc(sizeof(int));
        *p = new_socket;
        pthread_create(&t, NULL, client_worker, p);
    }
    return NULL;
}

int stratum_start_thread() {
    pthread_t t;
    return pthread_create(&t, NULL, server_thread_func, NULL);
}
