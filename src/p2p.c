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
#include <poll.h>

#include "p2p.h"
#include "bitcoin.h"
#include "utils.h"
#include "sha256.h"

#define P2P_RECV_BUF_SIZE   (4 * 1024 * 1024)
#define P2P_CONNECT_TIMEOUT 5
#define GETHEADERS_INTERVAL 40  // 秒级定时发送 getheaders

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;
    char     command[12];
    uint32_t length;
    uint32_t checksum;
} p2p_hdr_t;
#pragma pack(pop)

typedef struct {
    char     host[64];
    int      port;
    uint32_t magic;
    int32_t  start_height;
} p2p_cfg_t;

static volatile bool g_p2p_running = true;

/* 连接辅助函数：带超时的阻塞连接 */
static int p2p_connect(const char* host, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        log_error("P2P: socket() failed: %s", strerror(errno));
        return -1;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) {
        log_error("P2P: fcntl(F_GETFL) failed: %s", strerror(errno));
        close(sock);
        return -1;
    }
    if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) < 0) {
        log_error("P2P: fcntl(F_SETFL, O_NONBLOCK) failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);

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
        log_error("P2P: connect() failed immediately: %s", strerror(errno));
        close(sock);
        return -1;
    }

    struct timeval tv = { P2P_CONNECT_TIMEOUT, 0 };
    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);

    res = select(sock + 1, NULL, &wset, NULL, &tv);
    if (res <= 0) {
        log_error("P2P: connect timeout or select error");
        close(sock);
        return -1;
    }

    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) < 0 || err != 0) {
        log_error("P2P: connect getsockopt error: %s", strerror(err));
        close(sock);
        return -1;
    }

    // 恢复成阻塞模式：后续用 poll() 控制超时
    if (fcntl(sock, F_SETFL, flags & ~O_NONBLOCK) < 0) {
        log_error("P2P: fcntl(F_SETFL, blocking) failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

static void p2p_send_msg(int sock, uint32_t magic, const char* cmd,
                         const void* payload, uint32_t len) {
    p2p_hdr_t hdr;
    hdr.magic = magic;
    memset(hdr.command, 0, sizeof(hdr.command));
    strncpy(hdr.command, cmd, sizeof(hdr.command));
    hdr.length = len;

    uint8_t hash[32];
    sha256_double(payload, len, hash);
    memcpy(&hdr.checksum, hash, 4);

    ssize_t n = send(sock, &hdr, sizeof(hdr), MSG_NOSIGNAL);
    if (n != (ssize_t)sizeof(hdr)) {
        log_error("P2P: send header failed (%s)", strerror(errno));
        return;
    }

    if (len > 0 && payload != NULL) {
        n = send(sock, payload, len, MSG_NOSIGNAL);
        if (n != (ssize_t)len) {
            log_error("P2P: send payload failed (%s)", strerror(errno));
            return;
        }
    }
}

static void p2p_send_version(int sock, uint32_t magic, int32_t start_height) {
    uint8_t payload[86];
    memset(payload, 0, sizeof(payload));

    int32_t  version  = 70016;
    uint64_t services = 8;  // NODE_WITNESS
    int64_t  ts       = time(NULL);
    uint64_t nonce    = 0x5a705a705a705a70;

    memcpy(payload + 0,  &version,  4);
    memcpy(payload + 4,  &services, 8);
    memcpy(payload + 12, &ts,       8);
    memcpy(payload + 72, &nonce,    8);
    memcpy(payload + 81, &start_height, 4);

    uint8_t relay = 1;
    memcpy(payload + 85, &relay, 1);

    p2p_send_msg(sock, magic, "version", payload, sizeof(payload));
}

static void p2p_send_sendcmpct(int sock, uint32_t magic) {
    uint8_t payload[9];

    // V1
    memset(payload, 0, sizeof(payload));
    payload[0] = 1;  // high bandwidth
    uint64_t v1 = 1;
    memcpy(payload + 1, &v1, 8);
    p2p_send_msg(sock, magic, "sendcmpct", payload, sizeof(payload));

    // V2
    memset(payload, 0, sizeof(payload));
    payload[0] = 1;  // high bandwidth
    uint64_t v2 = 2;
    memcpy(payload + 1, &v2, 8);
    p2p_send_msg(sock, magic, "sendcmpct", payload, sizeof(payload));
}

/* 周期性 getheaders，保持高带宽 & 同步状态 */
static void p2p_send_getheaders(int sock, uint32_t magic) {
    Template tmpl;
    if (!bitcoin_get_latest_job(&tmpl)) {
        return;
    }

    uint8_t payload[69];
    memset(payload, 0, sizeof(payload));

    int32_t version = 70016;
    memcpy(payload + 0, &version, 4);

    payload[4] = 1;  // VarInt: count = 1
    memcpy(payload + 5, tmpl.prevhash_le, 32);
    // StopHash 已经是 0

    p2p_send_msg(sock, magic, "getheaders", payload, sizeof(payload));

    bitcoin_free_job(&tmpl);
}

static void p2p_handle_message(const char* cmd,
                               const uint8_t* payload,
                               uint32_t len) {
    const uint8_t *header_ptr = NULL;

    if (strcmp(cmd, "cmpctblock") == 0 && len >= 80) {
        header_ptr = payload;
    } else if (strcmp(cmd, "block") == 0 && len >= 80) {
        header_ptr = payload;
    } else if (strcmp(cmd, "headers") == 0 && len > 0) {
        uint64_t count = payload[0];
        if (count > 0 && len >= 81) {
            header_ptr = payload + 1;
        }
    } else if (strcmp(cmd, "inv") == 0) {
        if (len > 0) {
            uint64_t count = payload[0];
            if (count > 0 && len >= 1 + 36) {
                uint32_t type;
                memcpy(&type, payload + 1, 4);
                if (type == 2) {
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
    p2p_cfg_t *cfg = (p2p_cfg_t*)arg;

    log_info("P2P: Listener starting on %s:%d (Magic: 0x%08x, Initial Height: %d)",
             cfg->host, cfg->port, cfg->magic, cfg->start_height);

    uint8_t *recv_buf = malloc(P2P_RECV_BUF_SIZE);
    if (!recv_buf) {
        log_error("P2P: malloc recv_buf failed");
        free(cfg);
        return NULL;
    }

    while (g_p2p_running) {
        uint32_t current_h = 0;
        bitcoin_get_telemetry(&current_h, NULL, NULL);
        if (current_h > (uint32_t)cfg->start_height) {
            cfg->start_height = (int32_t)current_h;
            log_info("P2P: Updated handshake height to %d", cfg->start_height);
        }

        int sock = p2p_connect(cfg->host, cfg->port);
        if (sock < 0) {
            log_error("P2P: Connect to %s:%d failed, retrying in 5s...",
                      cfg->host, cfg->port);
            sleep(5);
            continue;
        }

        log_info("P2P: Connected. Handshaking...");

        p2p_send_version(sock, cfg->magic, cfg->start_height);
        p2p_send_msg(sock, cfg->magic, "wtxidrelay", NULL, 0);
        p2p_send_sendcmpct(sock, cfg->magic);
        p2p_send_msg(sock, cfg->magic, "verack", NULL, 0);

        int   buf_len        = 0;
        bool  handshake_done = false;
        time_t last_getheaders_time = 0;

        struct pollfd pfd;
        memset(&pfd, 0, sizeof(pfd));
        pfd.fd     = sock;
        pfd.events = POLLIN;

        while (g_p2p_running) {
            // poll 超时：1 秒，用来驱动定时器和断线检测
            int timeout_ms = 1000;
            int pret = poll(&pfd, 1, timeout_ms);

            time_t now = time(NULL);

            // 定期发送 getheaders 保活
            if (handshake_done &&
                (now - last_getheaders_time >= GETHEADERS_INTERVAL)) {
                p2p_send_getheaders(sock, cfg->magic);
                last_getheaders_time = now;
            }

            if (pret < 0) {
                if (errno == EINTR) {
                    continue;
                }
                log_error("P2P: poll error: %s", strerror(errno));
                break;
            }

            if (pret == 0) {
                // 超时，无数据，仅仅是为了驱动上面的定时器逻辑
                continue;
            }

            if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
                log_error("P2P: poll revents error (0x%x), disconnecting",
                          pfd.revents);
                break;
            }

            if (!(pfd.revents & POLLIN)) {
                // 没有可读事件，继续下一轮
                continue;
            }

            ssize_t n = recv(sock, recv_buf + buf_len,
                             P2P_RECV_BUF_SIZE - buf_len, 0);
            if (n <= 0) {
                if (n < 0) {
                    log_error("P2P: recv error: %s", strerror(errno));
                } else {
                    log_error("P2P: peer closed connection");
                }
                break;
            }

            buf_len += n;

            while (buf_len >= (int)sizeof(p2p_hdr_t)) {
                p2p_hdr_t *hdr = (p2p_hdr_t*)recv_buf;

                if (hdr->magic != cfg->magic) {
                    log_error("P2P: Invalid magic (0x%08x), disconnecting", hdr->magic);
                    goto reconnect;
                }

                uint32_t msg_len = hdr->length;
                uint32_t total_len = sizeof(p2p_hdr_t) + msg_len;

                if (msg_len > P2P_RECV_BUF_SIZE) {
                    log_error("P2P: Message too large (%u), disconnecting", msg_len);
                    goto reconnect;
                }

                if (buf_len < (int)total_len) {
                    // 数据未完整
                    break;
                }

                char cmd[13] = {0};
                memcpy(cmd, hdr->command, 12);

                if (!handshake_done && strcmp(cmd, "verack") == 0) {
                    handshake_done = true;
                    log_info("P2P: Handshake complete! (Push Activated)");
                    p2p_send_getheaders(sock, cfg->magic);
                    last_getheaders_time = time(NULL);
                }

                if (strcmp(cmd, "ping") == 0 && msg_len == 8) {
                    p2p_send_msg(sock, cfg->magic, "pong",
                                 recv_buf + sizeof(p2p_hdr_t), 8);
                }

                p2p_handle_message(cmd,
                                   recv_buf + sizeof(p2p_hdr_t),
                                   msg_len);

                memmove(recv_buf,
                        recv_buf + total_len,
                        buf_len - total_len);
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

int p2p_start_thread(const char *host, int port,
                     uint32_t magic, int32_t start_height) {
    pthread_t t;
    p2p_cfg_t *cfg = (p2p_cfg_t*)calloc(1, sizeof(p2p_cfg_t));
    if (!cfg) {
        return -1;
    }

    strncpy(cfg->host, host, sizeof(cfg->host) - 1);
    cfg->port         = port;
    cfg->magic        = magic;
    cfg->start_height = start_height;

    int ret = pthread_create(&t, NULL, p2p_thread_func, cfg);
    if (ret != 0) {
        free(cfg);
        return -1;
    }

    pthread_detach(t);
    return 0;
}
