#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <pthread.h>
#include <sys/select.h>
#include <netdb.h> // 必须包含：用于 Docker 容器名解析

#include "p2p.h"
#include "bitcoin.h"
#include "utils.h"
#include "sha256.h"

#define P2P_RECV_BUF_SIZE (4 * 1024 * 1024) // 4MB 缓冲区，防止粘包溢出
#define P2P_CONNECT_TIMEOUT 5

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    char     command[12];
    uint32_t length;
    uint32_t checksum;
} p2p_hdr_t;
#pragma pack(pop)

static volatile bool g_p2p_running = true;

// 连接辅助函数：支持 IP 和 Docker 容器名/域名
static int p2p_connect(const char* host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    // 设置非阻塞
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    // DNS / IP 解析逻辑
    struct hostent *he;
    // 1. 尝试直接解析 IP (如 127.0.0.1)
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        // 2. 如果不是 IP，尝试解析域名/容器名 (如 bitcoind)
        if ((he = gethostbyname(host)) == NULL) {
            log_error("P2P: Failed to resolve hostname: %s", host);
            close(sock);
            return -1;
        }
        memcpy(&addr.sin_addr, he->h_addr_list[0], he->h_length);
    }

    int res = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (res < 0 && errno != EINPROGRESS) {
        close(sock);
        return -1;
    }

    // 等待连接建立 (Select)
    struct timeval tv = {P2P_CONNECT_TIMEOUT, 0};
    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);
    
    res = select(sock + 1, NULL, &wset, NULL, &tv);
    if (res <= 0) { // 超时或错误
        close(sock);
        return -1;
    }

    // 检查 socket 错误状态
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
        close(sock);
        return -1;
    }

    // 恢复为阻塞模式，并设置读写超时
    fcntl(sock, F_SETFL, flags);
    struct timeval rtv = {60, 0}; // 60秒心跳/读超时
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&rtv, sizeof(rtv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&rtv, sizeof(rtv));

    return sock;
}

static void p2p_send_msg(int sock, uint32_t magic, const char* cmd, const void* payload, uint32_t len) {
    p2p_hdr_t hdr;
    hdr.magic = magic;
    memset(hdr.command, 0, 12);
    strncpy(hdr.command, cmd, 12);
    hdr.length = len;
    
    // 计算校验和: sha256d(payload) 的前4字节
    uint8_t hash[32];
    sha256_double(payload, len, hash);
    memcpy(&hdr.checksum, hash, 4);

    if (send(sock, &hdr, sizeof(hdr), MSG_NOSIGNAL) != sizeof(hdr)) return;
    if (len > 0) {
        if (send(sock, payload, len, MSG_NOSIGNAL) != (ssize_t)len) return;
    }
}

static void p2p_send_version(int sock, uint32_t magic, int32_t start_height) {
    uint8_t payload[86];
    memset(payload, 0, sizeof(payload));
    
    // 使用较新协议版本 70016 (明确支持 Segwit)
    int32_t version = 70016; 
    uint64_t services = 0; // 我们是轻客户端，不提供服务
    int64_t ts = time(NULL);
    uint64_t nonce = 0x5a705a705a705a70;

    memcpy(payload, &version, 4);
    memcpy(payload + 4, &services, 8);
    memcpy(payload + 12, &ts, 8);
    memcpy(payload + 72, &nonce, 8);
    // 其余部分 (addr_recv, addr_from, user_agent) 留空为 0
    
    // [重要] 填充 start_height (偏移量 81)
    // 告知节点我们已同步的高度，防止被当作 IBD 节点而拒绝推送
    memcpy(payload + 81, &start_height, 4);
    
    // relay flag (偏移量 85) 默认为 0

    p2p_send_msg(sock, magic, "version", payload, 85);
}

static void p2p_send_sendcmpct(int sock, uint32_t magic) {
    // 发送 Version 1 支持
    uint8_t payload[9];
    payload[0] = 1; // High Bandwidth (启用主动推送)
    uint64_t v1 = 1; 
    memcpy(payload + 1, &v1, 8);
    p2p_send_msg(sock, magic, "sendcmpct", payload, 9);

    // [新增] 同时发送 Version 2 支持 (新版 Bitcoin Core 偏好 v2)
    uint64_t v2 = 2;
    memcpy(payload + 1, &v2, 8);
    p2p_send_msg(sock, magic, "sendcmpct", payload, 9);
}

static void p2p_handle_message(const char* cmd, const uint8_t* payload, uint32_t len) {
    const uint8_t *header_ptr = NULL;

    if (strcmp(cmd, "cmpctblock") == 0 && len >= 80) {
        // [Header 80b] [Nonce 8b] ...
        header_ptr = payload;
    } 
    else if (strcmp(cmd, "headers") == 0 && len > 80) {
        // [Count VarInt] [Header 80b] ...
        if (payload[0] > 0) { // 简单解析，假设 count > 0
            header_ptr = payload + 1;
        }
    }
    else if (strcmp(cmd, "block") == 0 && len >= 80) {
        header_ptr = payload;
    }
    // [调试] 监控 INV 消息，用于诊断是否被限流
    else if (strcmp(cmd, "inv") == 0) {
        // 如果收到 Block 类型的 INV，说明节点没有主动推送 Block 数据
        // 这通常意味着我们被当作低带宽或未同步节点对待
        if (len > 0) {
            uint64_t count = payload[0]; 
            if (count > 0 && len >= 1 + 36) {
                uint32_t type;
                memcpy(&type, payload + 1, 4);
                if (type == 2) { // MSG_BLOCK
                    log_info("P2P Warning: Received INV for Block (Node is NOT Pushing!). Height config issue?");
                }
            }
        }
    }

    if (header_ptr) {
        // 触发 bitcoin.c 中的快速切块逻辑
        bitcoin_fast_new_block(header_ptr);
    }
}

static void *p2p_thread_func(void *arg) {
    struct { char host[64]; int port; uint32_t magic; int32_t start_height; } *cfg = arg;
    
    log_info("P2P: Listener starting on %s:%d (Magic: 0x%08x, Initial Height: %d)", 
             cfg->host, cfg->port, cfg->magic, cfg->start_height);
    
    uint8_t *recv_buf = malloc(P2P_RECV_BUF_SIZE);
    if (!recv_buf) return NULL;
    
    while (g_p2p_running) {
        // [优化] 自动更新握手高度
        // 每次重连前，获取当前最新的挖矿高度。
        // 防止网关运行很久后重连时，仍使用启动时的旧高度导致被判定为 IBD。
        uint32_t current_h = 0;
        bitcoin_get_telemetry(&current_h, NULL, NULL);
        if (current_h > (uint32_t)cfg->start_height) {
            cfg->start_height = (int32_t)current_h;
            log_info("P2P: Updated handshake height to %d", cfg->start_height);
        }

        int sock = p2p_connect(cfg->host, cfg->port);
        if (sock < 0) {
            log_error("P2P: Connect to %s failed, retrying in 5s...", cfg->host);
            sleep(5);
            continue;
        }

        log_info("P2P: Connected. Handshaking with Height %d...", cfg->start_height);
        
        // 1. 发送 Version (带高度)
        p2p_send_version(sock, cfg->magic, cfg->start_height);
        // 2. 发送 Verack
        p2p_send_msg(sock, cfg->magic, "verack", NULL, 0);
        // 3. 发送 SendCmpct (激活推送)
        p2p_send_sendcmpct(sock, cfg->magic);
        
        int buf_len = 0;
        bool handshake_done = false;

        while (g_p2p_running) {
            ssize_t n = recv(sock, recv_buf + buf_len, P2P_RECV_BUF_SIZE - buf_len, 0);
            if (n <= 0) {
                log_error("P2P: Socket disconnected");
                break;
            }
            buf_len += n;

            // 处理缓冲区中的消息
            while (buf_len >= 24) { // 最小包头长度
                p2p_hdr_t *hdr = (p2p_hdr_t*)recv_buf;
                if (hdr->magic != cfg->magic) {
                    log_error("P2P: Invalid magic, disconnecting");
                    goto reconnect;
                }

                if (buf_len < 24 + hdr->length) {
                    break; // 等待更多数据
                }

                // 安全获取命令字
                char cmd[13] = {0};
                memcpy(cmd, hdr->command, 12);
                
                if (!handshake_done && strcmp(cmd, "verack") == 0) {
                    handshake_done = true;
                    log_info("P2P: Handshake complete! (Push Activated)");
                }

                // 响应 Ping/Pong (保活)
                if (strcmp(cmd, "ping") == 0 && hdr->length == 8) {
                    p2p_send_msg(sock, cfg->magic, "pong", recv_buf + 24, 8);
                }

                // 处理业务消息
                p2p_handle_message(cmd, recv_buf + 24, hdr->length);

                // 移除已处理消息
                uint32_t total_len = 24 + hdr->length;
                memmove(recv_buf, recv_buf + total_len, buf_len - total_len);
                buf_len -= total_len;
            }
        }

    reconnect:
        close(sock);
        sleep(2);
    }
    
    free(recv_buf);
    free(cfg);
    return NULL;
}

int p2p_start_thread(const char *host, int port, uint32_t magic, int32_t start_height) {
    pthread_t t;
    void *arg = malloc(128 + 4); // 预留足够空间
    char *host_ptr = (char*)arg;
    strncpy(host_ptr, host, 64);
    
    int *port_ptr = (int*)(host_ptr + 64);
    *port_ptr = port;
    
    uint32_t *magic_ptr = (uint32_t*)(host_ptr + 68);
    *magic_ptr = magic;

    int32_t *height_ptr = (int32_t*)(host_ptr + 72);
    *height_ptr = start_height;

    return pthread_create(&t, NULL, p2p_thread_func, arg);
}
