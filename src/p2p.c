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

#define P2P_RECV_BUF_SIZE (4 * 1024 * 1024) // 4MB Buffer
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

static int p2p_connect(const char* host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    // Set non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    struct hostent *he;
    // 尝试将其视为 IP 地址
    if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
        // 如果不是 IP，尝试作为域名/主机名解析
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

    // Wait for connection
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

    // Set back to blocking with timeout
    fcntl(sock, F_SETFL, flags);
    struct timeval rtv = {60, 0}; // 60s timeout
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
    
    // Checksum: first 4 bytes of sha256d(payload)
    uint8_t hash[32];
    sha256_double(payload, len, hash);
    memcpy(&hdr.checksum, hash, 4);

    if (send(sock, &hdr, sizeof(hdr), MSG_NOSIGNAL) != sizeof(hdr)) return;
    if (len > 0) {
        if (send(sock, payload, len, MSG_NOSIGNAL) != (ssize_t)len) return;
    }
}

static void p2p_send_version(int sock, uint32_t magic) {
    uint8_t payload[86];
    memset(payload, 0, sizeof(payload));
    
    int32_t version = 70015; 
    uint64_t services = 0;
    int64_t ts = time(NULL);
    uint64_t nonce = 0x5a705a705a705a70;

    memcpy(payload, &version, 4);
    memcpy(payload + 4, &services, 8);
    memcpy(payload + 12, &ts, 8);
    memcpy(payload + 72, &nonce, 8);
    
    p2p_send_msg(sock, magic, "version", payload, 85);
}

static void p2p_send_sendcmpct(int sock, uint32_t magic) {
    uint8_t payload[9];
    payload[0] = 1; 
    uint64_t version = 1; 
    memcpy(payload + 1, &version, 8);
    p2p_send_msg(sock, magic, "sendcmpct", payload, 9);
}

static void p2p_handle_message(const char* cmd, const uint8_t* payload, uint32_t len) {
    const uint8_t *header_ptr = NULL;

    if (strcmp(cmd, "cmpctblock") == 0 && len >= 80) {
        header_ptr = payload;
    } 
    else if (strcmp(cmd, "headers") == 0 && len > 80) {
        if (payload[0] > 0) {
            header_ptr = payload + 1;
        }
    }
    else if (strcmp(cmd, "block") == 0 && len >= 80) {
        header_ptr = payload;
    }

    if (header_ptr) {
        bitcoin_fast_new_block(header_ptr);
    }
}

static void *p2p_thread_func(void *arg) {
    struct { char host[64]; int port; uint32_t magic; } *cfg = arg;
    
    log_info("P2P: Listener starting on %s:%d (Magic: 0x%08x)", cfg->host, cfg->port, cfg->magic);
    
    uint8_t *recv_buf = malloc(P2P_RECV_BUF_SIZE);
    if (!recv_buf) return NULL;
    
    while (g_p2p_running) {
        int sock = p2p_connect(cfg->host, cfg->port);
        if (sock < 0) {
            log_error("P2P: Connect to %s failed, retrying in 5s...", cfg->host);
            sleep(5);
            continue;
        }

        log_info("P2P: Connected to %s. Sending Handshake...", cfg->host);
        
        p2p_send_version(sock, cfg->magic);
        p2p_send_msg(sock, cfg->magic, "verack", NULL, 0);
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

            while (buf_len >= 24) {
                p2p_hdr_t *hdr = (p2p_hdr_t*)recv_buf;
                if (hdr->magic != cfg->magic) {
                    log_error("P2P: Invalid magic, disconnecting");
                    goto reconnect;
                }

                if (buf_len < 24 + hdr->length) break; 

                char cmd[13] = {0};
                memcpy(cmd, hdr->command, 12);
                
                if (!handshake_done && strcmp(cmd, "verack") == 0) {
                    handshake_done = true;
                    log_info("P2P: Handshake complete! Ready for blocks.");
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

int p2p_start_thread(const char *host, int port, uint32_t magic) {
    pthread_t t;
    void *arg = malloc(128);
    char *host_ptr = (char*)arg;
    strncpy(host_ptr, host, 64);
    
    int *port_ptr = (int*)(host_ptr + 64);
    *port_ptr = port;
    
    uint32_t *magic_ptr = (uint32_t*)(host_ptr + 68);
    *magic_ptr = magic;

    return pthread_create(&t, NULL, p2p_thread_func, arg);
}
