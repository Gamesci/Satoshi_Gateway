#ifndef STRATUM_H
#define STRATUM_H

#include "bitcoin.h"
#include <netinet/in.h>

// 定义最大客户端连接数 (Solo 模式下 64 足够)
#define MAX_CLIENTS 64

typedef struct {
    int sock;
    struct sockaddr_in addr;
    int id;
    char extranonce1_hex[16]; // 分配给该矿机的唯一 ID
    bool is_authorized;
    bool active;
    pthread_t thread_id;
} Client;

int stratum_start_thread();
void stratum_broadcast_job(Template *tmpl);

#endif
