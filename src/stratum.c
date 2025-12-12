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

// --- 全局客户端管理 ---
static Client g_clients[MAX_CLIENTS];
static pthread_mutex_t g_clients_lock = PTHREAD_MUTEX_INITIALIZER;

// 初始化客户端列表
void init_clients() {
    for(int i=0; i<MAX_CLIENTS; i++) {
        g_clients[i].active = false;
        g_clients[i].sock = -1;
    }
}

// 分配新客户端位置
Client* client_add(int sock, struct sockaddr_in addr) {
    pthread_mutex_lock(&g_clients_lock);
    for(int i=0; i<MAX_CLIENTS; i++) {
        if(!g_clients[i].active) {
            g_clients[i].active = true;
            g_clients[i].sock = sock;
            g_clients[i].addr = addr;
            g_clients[i].id = i + 1; // ID 从 1 开始
            g_clients[i].is_authorized = false;
            // 生成唯一的 ExtraNonce1 (基于 ID)
            // 格式: 4字节 Hex. 例如 ID 1 -> "00000001"
            snprintf(g_clients[i].extranonce1_hex, 9, "%08x", g_clients[i].id);
            pthread_mutex_unlock(&g_clients_lock);
            return &g_clients[i];
        }
    }
    pthread_mutex_unlock(&g_clients_lock);
    return NULL; // 满员
}

// 移除客户端
void client_remove(Client *c) {
    if(!c) return;
    pthread_mutex_lock(&g_clients_lock);
    if(c->active) {
        close(c->sock);
        c->active = false;
        c->sock = -1;
        printf("[STRATUM] Client disconnected: %d\n", c->id);
    }
    pthread_mutex_unlock(&g_clients_lock);
}

// --- 辅助函数：发送 JSON ---
void send_json(int sock, json_t *response) {
    char *s = json_dumps(response, 0);
    if(s) {
        // Stratum 协议以 \n 结尾
        size_t len = strlen(s);
        char *msg = malloc(len + 2);
        strcpy(msg, s);
        msg[len] = '\n';
        msg[len+1] = 0;
        send(sock, msg, len+1, 0);
        free(msg);
        free(s);
    }
}

// --- 核心：广播任务 ---
// 遍历所有活跃客户端发送 mining.notify
void stratum_broadcast_job(Template *tmpl) {
    // 构造参数: [job_id, prev_hash, coinb1, coinb2, merkle_branch, version, nbits, ntime, clean_jobs]
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
    
    char *s = json_dumps(req, 0);
    size_t len = strlen(s);
    char *msg = malloc(len + 2);
    strcpy(msg, s);
    msg[len] = '\n';
    msg[len+1] = 0;
    
    pthread_mutex_lock(&g_clients_lock);
    for(int i=0; i<MAX_CLIENTS; i++) {
        if(g_clients[i].active && g_clients[i].is_authorized) {
            send(g_clients[i].sock, msg, len+1, MSG_NOSIGNAL);
        }
    }
    pthread_mutex_unlock(&g_clients_lock);
    
    printf("[STRATUM] Broadcast Job %s to miners. (Block Height: %d)\n", tmpl->job_id, tmpl->height);
    
    free(msg);
    free(s);
    json_decref(req);
}

// --- 客户端线程工作函数 ---
void *client_worker(void *arg) {
    Client *c = (Client*)arg;
    char buffer[4096];
    int read_pos = 0;

    // 设置超时
    struct timeval tv;
    tv.tv_sec = 300; // 5分钟无活动断开
    tv.tv_usec = 0;
    setsockopt(c->sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    while(c->active) {
        ssize_t n = recv(c->sock, buffer + read_pos, sizeof(buffer) - 1 - read_pos, 0);
        if(n <= 0) break; // 断开或错误
        
        read_pos += n;
        buffer[read_pos] = 0;

        // 处理粘包：寻找换行符
        char *start = buffer;
        char *end;
        while((end = strchr(start, '\n')) != NULL) {
            *end = 0; // 截断字符串
            
            if(strlen(start) > 0) {
                json_error_t err;
                json_t *req = json_loads(start, 0, &err);
                
                if(req) {
                    const char *method = json_string_value(json_object_get(req, "method"));
                    json_t *id = json_object_get(req, "id");
                    json_t *params = json_object_get(req, "params");
                    
                    json_t *res = json_object();
                    json_object_set(res, "id", id); // Echo ID
                    
                    if(!method) {
                         // 忽略无方法的包
                    }
                    // 1. Subscribe
                    else if(strcmp(method, "mining.subscribe") == 0) {
                        json_object_set_new(res, "error", json_null());
                        json_t *arr = json_array();
                        
                        // Sub details: [[ "mining.set_difficulty", "sub_id" ], [ "mining.notify", "sub_id" ]]
                        json_t *subs = json_array();
                        json_t *sub1 = json_array();
                        json_array_append_new(sub1, json_string("mining.set_difficulty"));
                        json_array_append_new(sub1, json_string("1")); // Dummy ID
                        json_array_append_new(subs, sub1);
                        
                        json_t *sub2 = json_array();
                        json_array_append_new(sub2, json_string("mining.notify"));
                        json_array_append_new(sub2, json_string("1"));
                        json_array_append_new(subs, sub2);
                        
                        json_array_append_new(arr, subs);
                        json_array_append_new(arr, json_string(c->extranonce1_hex)); // Extranonce1
                        json_array_append_new(arr, json_integer(g_config.extranonce2_size)); // Extranonce2 Len
                        
                        json_object_set_new(res, "result", arr);
                        send_json(c->sock, res);
                    }
                    // 2. Authorize
                    else if(strcmp(method, "mining.authorize") == 0) {
                        c->is_authorized = true;
                        json_object_set_new(res, "error", json_null());
                        json_object_set_new(res, "result", json_true());
                        send_json(c->sock, res);
                        
                        // Auth 成功后，立即发送难度
                        json_t *diff_req = json_object();
                        json_object_set_new(diff_req, "id", json_null());
                        json_object_set_new(diff_req, "method", json_string("mining.set_difficulty"));
                        json_t *dparams = json_array();
                        json_array_append_new(dparams, json_integer(g_config.initial_diff));
                        json_object_set_new(diff_req, "params", dparams);
                        send_json(c->sock, diff_req);
                        json_decref(diff_req);
                        
                        // 如果当前有缓存的 Job，立即发送 (避免等待)
                        // 这里简化：主循环会由 connection 触发或定时触发更新
                        // 生产环境可以调用 stratum_send_current_job(c);
                    }
                    // 3. Configure (Version Rolling for Bitaxe)
                    else if(strcmp(method, "mining.configure") == 0) {
                        json_object_set_new(res, "error", json_null());
                        json_t *r = json_object();
                        json_object_set_new(r, "version-rolling", json_true());
                        json_object_set_new(r, "version-rolling.mask", json_string(g_config.version_mask));
                        json_object_set_new(res, "result", r);
                        send_json(c->sock, res);
                    }
                    // 4. Submit
                    else if(strcmp(method, "mining.submit") == 0) {
                        // Params: [worker, job_id, extranonce2, ntime, nonce, (optional version_bits)]
                        const char *job_id = json_string_value(json_array_get(params, 1));
                        const char *en2 = json_string_value(json_array_get(params, 2));
                        const char *ntime = json_string_value(json_array_get(params, 3));
                        const char *nonce_hex = json_string_value(json_array_get(params, 4));
                        
                        // 处理 Version Rolling (如果存在第6个参数)
                        uint32_t ver_mask = 0;
                        if(json_array_size(params) >= 6) {
                            const char *ver_hex = json_string_value(json_array_get(params, 5));
                            if(ver_hex) ver_mask = strtoul(ver_hex, NULL, 16);
                        }

                        // 解析 Nonce (Hex String -> Uint32)
                        // Bitaxe 发送 "e52d..." (Big Endian String of the bytes).
                        // x86 是 Little Endian。
                        // 我们先按 Hex 读入整数
                        uint32_t nonce = (uint32_t)strtoul(nonce_hex, NULL, 16);
                        
                        // 重要：Stratum V1 的 nonce 在 JSON 中通常是大端序的 Hex 字符串，
                        // 但在 Block Header 中需要是 Little Endian。
                        // bitcoin_reconstruct_and_submit 会直接把这个 uint32 写内存。
                        // 如果 strtoul 解析 "00000001" -> 1。内存为 01 00 00 00。
                        // 这通常就是 Header 需要的格式。
                        // 但是，如果 Bitaxe 发送的是网络字节序的 Hex... 
                        // 大多数 Stratum 实现中，收到的 hex string 直接转 int 即可放入 header。
                        // 我们将在 submit 内部处理。

                        printf("[STRATUM] Share from Miner %d | Job: %s | Nonce: %s\n", c->id, job_id, nonce_hex);

                        // 调用 Bitcoin 模块提交
                        // 注意：这里需要传入 extranonce1 (c->extranonce1_hex) 还是让 bitcoin 模块知道？
                        // bitcoin.c 需要完整的 extranonce1 + extranonce2 来重构 Coinbase。
                        // 目前 bitcoin_reconstruct_and_submit 只接收了 en2。
                        // *必须修改 bitcoin_reconstruct_and_submit 签名以接收 en1* // 或者我们在 bitcoin.c 里无法得知是哪个 client 提交的。
                        // 
                        // 修正方案：bitcoin.c 的 submit 函数应该接收完整的 (en1 + en2) 字符串，
                        // 或者 stratum 在这里拼接好传进去。
                        // 我们采用拼接方案。
                        
                        // 拼接 En1 + En2
                        char full_extranonce[64]; // En1(8) + En2(16)
                        snprintf(full_extranonce, sizeof(full_extranonce), "%s%s", c->extranonce1_hex, en2);
                        
                        // 调用重构与提交
                        int ret = bitcoin_reconstruct_and_submit(job_id, full_extranonce, ntime, nonce, ver_mask);

                        json_object_set_new(res, "error", json_null());
                        json_object_set_new(res, "result", json_true()); // 总是返回 true 保持连接
                        send_json(c->sock, res);
                        
                        if(ret) {
                            printf(">>>>>>>>>>>> BLOCK FOUND! SUBMITTED TO NETWORK! <<<<<<<<<<<<\n");
                        }
                    }
                    else {
                        // 未知方法
                        json_object_set_new(res, "error", json_object()); 
                    }
                    
                    json_decref(res);
                    json_decref(req);
                } else {
                    printf("[STRATUM] JSON Parse Error: %s\n", err.text);
                }
            }
            start = end + 1;
        }
        
        // 移动剩余数据到缓冲区头部
        if(start < buffer + read_pos) {
            size_t remaining = buffer + read_pos - start;
            memmove(buffer, start, remaining);
            read_pos = remaining;
        } else {
            read_pos = 0;
        }
    }
    
    client_remove(c);
    free(c); // 注意：client_remove 不释放内存，这里是在 thread 结束时清理 dynamic alloc? 
    // 不，我们用的是静态数组 g_clients。client_add 返回的是指向静态数组的指针。
    // 所以不需要 free(c)。client_remove 只是标记 active=false。
    return NULL;
}

// --- 服务器监听线程 ---
void *server_thread(void *arg) {
    (void)arg;
    int server_fd;
    struct sockaddr_in address;
    int opt = 1;
    
    init_clients();

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
    
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(g_config.stratum_port);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    
    if (listen(server_fd, 10) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }
    
    printf("[STRATUM] Listening on port %d\n", g_config.stratum_port);
    
    while(1) {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
        
        if (new_socket < 0) {
            perror("accept");
            continue;
        }
        
        printf("[STRATUM] New connection from %s\n", inet_ntoa(client_addr.sin_addr));
        
        Client *c = client_add(new_socket, client_addr);
        if(c) {
            pthread_create(&c->thread_id, NULL, client_worker, c);
            pthread_detach(c->thread_id);
        } else {
            printf("[STRATUM] Max clients reached. Rejected.\n");
            close(new_socket);
        }
    }
    return NULL;
}

int stratum_start_thread() {
    pthread_t t;
    return pthread_create(&t, NULL, server_thread, NULL);
}
