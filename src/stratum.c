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

// 简单的客户端列表
#define MAX_CLIENTS 10
static int client_sockets;
static pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;

void *client_handler(void *arg) {
    int sock = *(int*)arg;
    free(arg);
    char buffer;
    
    while (1) {
        ssize_t n = recv(sock, buffer, sizeof(buffer)-1, 0);
        if (n <= 0) break;
        buffer[n] = 0;

        // 简单的 JSON 解析 (注意：TCP可能粘包，生产环境需要缓冲处理)
        json_error_t error;
        json_t *req = json_loads(buffer, 0, &error);
        if (!req) continue;

        const char *method = json_string_value(json_object_get(req, "method"));
        json_t *id = json_object_get(req, "id");
        json_t *params = json_object_get(req, "params");

        json_t *response = json_object();
        json_object_set(response, "id", id);
        json_object_set_new(response, "error", json_null());

        if (strcmp(method, "mining.subscribe") == 0) {
            // 返回: [ ["mining.set_difficulty", "subid"], ["mining.notify", "subid"], "extranonce1", extranonce2_size ]
            json_t *res_arr = json_array();
            json_t *subs = json_array();
            json_array_append_new(subs, json_array()); // Empty sub details
            json_array_append_new(res_arr, subs);
            json_array_append_new(res_arr, json_string("00000001")); // Extranonce1 (Hex)
            json_array_append_new(res_arr, json_integer(4));         // Extranonce2 Size
            json_object_set_new(response, "result", res_arr);
            
            // 立即发送响应
            char *s = json_dumps(response, 0);
            send(sock, s, strlen(s), 0);
            send(sock, "\n", 1, 0);
            free(s);
            
            // 发送难度
            // mining.set_difficulty
            // 发送第一个任务
            // stratum_send_job(sock, current_template);
            continue; 

        } else if (strcmp(method, "mining.authorize") == 0) {
            json_object_set_new(response, "result", json_true());
        } else if (strcmp(method, "mining.configure") == 0) {
            // Version Rolling 协商 (Bitaxe 必需)
            json_t *res_obj = json_object();
            json_object_set_new(res_obj, "version-rolling", json_true());
            json_object_set_new(res_obj, "version-rolling.mask", json_string("1fffe000"));
            json_object_set_new(response, "result", res_obj);
        } else if (strcmp(method, "mining.submit") == 0) {
            // 验证 Share
            // 1. 重构区块头
            // 2. 双重 SHA256
            // 3. 检查 Hash < Target
            printf(" Share submitted by miner!\n");
            // 如果满足网络难度 -> bitcoin_submit_block(hex);
            json_object_set_new(response, "result", json_true());
        }

        char *s = json_dumps(response, 0);
        send(sock, s, strlen(s), 0);
        send(sock, "\n", 1, 0);
        free(s);
        json_decref(req);
        json_decref(response);
    }

    close(sock);
    return NULL;
}

void *server_thread(void *arg) {
    (void)arg;
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(g_config.stratum_port);

    bind(server_fd, (struct sockaddr *)&address, sizeof(address));
    listen(server_fd, 3);

    while (1) {
        new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen);
        if (new_socket >= 0) {
            printf(" New miner connected.\n");
            int *pclient = malloc(sizeof(int));
            *pclient = new_socket;
            pthread_t t;
            pthread_create(&t, NULL, client_handler, pclient);
            
            pthread_mutex_lock(&clients_lock);
            for(int i=0; i<MAX_CLIENTS; i++) {
                if(client_sockets[i] == 0) {
                    client_sockets[i] = new_socket;
                    break;
                }
            }
            pthread_mutex_unlock(&clients_lock);
        }
    }
}

int stratum_start_thread() {
    pthread_t t;
    return pthread_create(&t, NULL, server_thread, NULL);
}

void stratum_broadcast_job(Template *tmpl) {
    // 构造 mining.notify
    // 参数: [job_id, prev_hash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]
    // 遍历 client_sockets 发送
    // 由于代码篇幅限制，此处逻辑略，核心是拼装 JSON 字符串并 send()
    printf(" Broadcasting Job ID: %s\n", tmpl->job_id);
}
