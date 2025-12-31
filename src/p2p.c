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
#include <netdb.h> 

#include "p2p.h"
#include "bitcoin.h"
#include "utils.h"
#include "sha256.h"

#define P2P_RECV_BUF_SIZE (4 * 1024 * 1024) 
#define P2P_CONNECT_TIMEOUT 5
#define GETHEADERS_INTERVAL 30  // [新增] 每30秒发送一次 getheaders 保活

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    char     command[12];
    uint32_t length;
    uint32_t checksum;
} p2p_hdr_t;
#pragma pack(pop)

static volatile bool g_p2p_running = true;

// 连接辅助函数
static int p2p_connect(const char* host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    struct hostent *he;
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
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

    struct timeval tv = {P2P_CONNECT_TIMEOUT, 0};
    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);
    
    res = select(sock + 1, NULL, &wset, NULL, &tv);
    if (res <= 0) { 
        close(sock);
        return -1;
    }

    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
        close(sock);
        return -1;
    }

    fcntl(sock, F_SETFL, flags);
    // [调整] 将接收超时改为 1 秒，以便主循环能更频繁地检查是否需要发送 getheaders
    struct timeval rtv = {1, 0}; 
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
    
    int32_t version = 70016; 
    // [保留] 启用 NODE_WITNESS (8)，配合 Compact Block V2
    uint64_t services = 8; 
    
    int64_t ts = time(NULL);
    uint64_t nonce = 0x5a705a705a705a70;

    memcpy(payload, &version, 4);
    memcpy(payload + 4, &services, 8);
    memcpy(payload + 12, &ts, 8);
    memcpy(payload + 72, &nonce, 8);
    
    memcpy(payload + 81, &start_height, 4);
    
    // [保留] 显式开启 Relay
    uint8_t relay = 1;
    memcpy(payload + 85, &relay, 1);

    p2p_send_msg(sock, magic, "version", payload, 86);
}

static void p2p_send_sendcmpct(int sock, uint32_t magic) {
    uint8_t payload[9];
    
    // Version 1
    payload[0] = 1; // High Bandwidth
    uint64_t v1 = 1; 
    memcpy(payload + 1, &v1, 8);
    p2p_send_msg(sock, magic, "sendcmpct", payload, 9);

    // Version 2 (首选)
    payload[0] = 1; // High Bandwidth
    uint64_t v2 = 2;
    memcpy(payload + 1, &v2, 8);
    p2p_send_msg(sock, magic, "sendcmpct", payload, 9);
}

// [新增] 发送 getheaders 以保持活跃并维持 Synced 状态
static void p2p_send_getheaders(int sock, uint32_t magic) {
    // 获取当前已知的最新 Job，从中提取 PrevHash
    // 这保证了我们向节点汇报的 "我们有的区块" 与 bitcoin.c 中的挖矿任务是完全一致的
    Template tmpl;
    if (!bitcoin_get_latest_job(&tmpl)) {
        return; // 还没有 Job (可能还在初始化)，暂时不发
    }
    
    // 构造 payload
    // Version (4) + VarInt Count (1) + Hash (32) + StopHash (32) = 69 bytes
    uint8_t payload[69]; 
    memset(payload, 0, sizeof(payload));
    
    int32_t version = 70016;
    memcpy(payload, &version, 4);
    
    payload[4] = 1; // VarInt: Count = 1
    
    // 关键点：使用 prevhash_le (Little Endian)
    // 这是 bitcoin.c 维护的原始小端序哈希，完全符合 P2P 协议标准
    // 注意：不要使用 prev_hash_stratum (那是 Swap 过的)
    memcpy(payload + 5, tmpl.prevhash_le, 32);
    
    // StopHash 全 0 (memset已处理)

    p2p_send_msg(sock, magic, "getheaders", payload, 69);
    
    // 释放 Job 内存 (bitcoin_get_latest_job 会做深拷贝)
    bitcoin_free_job(&tmpl);
}

static void p2p_handle_message(const char* cmd, const uint8_t* payload, uint32_t len) {
    const uint8_t *header_ptr = NULL;

    if (strcmp(cmd, "cmpctblock") == 0 && len >= 80) {
        header_ptr = payload;
    } 
    else if (strcmp(cmd, "block") == 0 && len >= 80) {
        header_ptr = payload;
    }
    else if (strcmp(cmd, "headers") == 0 && len > 0) {
        uint64_t count = payload[0]; 
        if (count > 0 && len >= 81) {
             header_ptr = payload + 1;
        }
    }
    else if (strcmp(cmd, "inv") == 0) {
        if (len > 0) {
            uint64_t count = payload[0]; 
            if (count > 0 && len >= 1 + 36) {
                uint32_t type;
                memcpy(&type, payload + 1, 4);
                if (type == 2) { 
                    // 收到 INV 意味着推送机制暂时未生效。
                    // 现在的 getheaders 机制应该能逐渐消除这个警告。
                    log_info("P2P Warning: Received INV for Block (Fallback mode).");
                }
            }
        }
    }

    if (header_ptr) {
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

        log_info("P2P: Connected. Handshaking...");
        
        // --- 握手序列 (保留优化后的顺序) ---
        p2p_send_version(sock, cfg->magic, cfg->start_height);
        p2p_send_msg(sock, cfg->magic, "wtxidrelay", NULL, 0); // 必须在 Verack 前
        p2p_send_sendcmpct(sock, cfg->magic); // 请求 High Bandwidth
        p2p_send_msg(sock, cfg->magic, "verack", NULL, 0);
        
        int buf_len = 0;
        bool handshake_done = false;
        
        // [新增] 计时器
        time_t last_getheaders_time = 0;

        while (g_p2p_running) {
            // [新增] 定期发送 getheaders 保活 (逻辑A方案)
            time_t now = time(NULL);
            if (handshake_done && (now - last_getheaders_time >= GETHEADERS_INTERVAL)) {
                p2p_send_getheaders(sock, cfg->magic);
                last_getheaders_time = now;
                // 可选：打印日志确认保活
                // log_info("P2P: Sent periodic getheaders to keep high-bandwidth mode");
            }

            // 接收数据 (1秒超时，保证上面的定时器能被及时触发)
            ssize_t n = recv(sock, recv_buf + buf_len, P2P_RECV_BUF_SIZE - buf_len, 0);
            
            if (n <= 0) {
                // 检查是否是超时 (EAGAIN/EWOULDBLOCK)
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue; // 只是超时，继续循环检查定时器
                }
                log_error("P2P: Socket disconnected");
                break;
            }
            buf_len += n;

            while (buf_len >= 24) {
                p2p_hdr_t *hdr = (p2p_hdr_t*)recv_buf;
                if (hdr->magic != cfg->magic) {
                    log_error("P2P: Invalid magic, disconnecting");
                    goto reconnect;
                }

                if (buf_len < 24 + hdr->length) {
                    break;
                }

                char cmd[13] = {0};
                memcpy(cmd, hdr->command, 12);
                
                if (!handshake_done && strcmp(cmd, "verack") == 0) {
                    handshake_done = true;
                    log_info("P2P: Handshake complete! (Push Activated)");
                    
                    // 握手完成后立即发送一次 getheaders，加速状态同步
                    p2p_send_getheaders(sock, cfg->magic);
                    last_getheaders_time = time(NULL);
                }

                if (strcmp(cmd, "ping") == 0 && hdr->length == 8) {
                    p2p_send_msg(sock, cfg->magic, "pong", recv_buf + 24, 8);
                }

                p2p_handle_message(cmd, recv_buf + 24, hdr->length);

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
    void *arg = malloc(128 + 4); 
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
