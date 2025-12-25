#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <jansson.h>

#include "web.h"
#include "stratum.h"
#include "utils.h"

// 默认 Web 文件夹位置（Docker内）
#define WEB_ROOT "/app/web"

static void handle_client(int client_sock) {
    char buf[4096];
    ssize_t n = recv(client_sock, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { close(client_sock); return; }
    buf[n] = 0;

    // 简单解析 Method 和 Path
    char method[16], path[256], protocol[16];
    sscanf(buf, "%s %s %s", method, path, protocol);

    // API 请求：/api/stats
    if (strcmp(path, "/api/stats") == 0) {
        json_t *root = stratum_get_stats();
        if (root) {
            json_object_set_new(root, "pool", json_string("Satoshi Gateway"));
            
            // [FIX] json_dumps returns NULL on error (e.g. Inf/NaN values)
            char *json_str = json_dumps(root, JSON_COMPACT);
            
            if (json_str) {
                char header[512];
                snprintf(header, sizeof(header), 
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: application/json\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "Content-Length: %zu\r\n\r\n", strlen(json_str));
                
                send(client_sock, header, strlen(header), 0);
                send(client_sock, json_str, strlen(json_str), 0);
                free(json_str);
            } else {
                // 序列化失败（通常是因为 double 包含了 Infinity 或 NaN）
                const char *err_msg = "{\"error\": \"JSON serialization failed (Possible Inf/NaN in stats)\"}";
                char header[512];
                snprintf(header, sizeof(header), 
                    "HTTP/1.1 500 Internal Server Error\r\n"
                    "Content-Type: application/json\r\n"
                    "Access-Control-Allow-Origin: *\r\n"
                    "Content-Length: %zu\r\n\r\n", strlen(err_msg));
                send(client_sock, header, strlen(header), 0);
                send(client_sock, err_msg, strlen(err_msg), 0);
                log_error("Web API Error: json_dumps returned NULL (Check for Infinity/NaN in stats)");
            }
            json_decref(root);
        } else {
             const char *err_msg = "{\"error\": \"Failed to retrieve stats\"}";
             send(client_sock, err_msg, strlen(err_msg), 0);
        }
    } 
    // 静态文件请求：默认返回 index.html
    else {
        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/index.html", WEB_ROOT);

        int fd = open(filepath, O_RDONLY);
        if (fd < 0) {
            const char *not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
            send(client_sock, not_found, strlen(not_found), 0);
        } else {
            struct stat st;
            fstat(fd, &st);
            size_t filesize = st.st_size;

            char header[512];
            snprintf(header, sizeof(header), 
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "Content-Length: %zu\r\n\r\n", filesize);
            send(client_sock, header, strlen(header), 0);

            while (1) {
                ssize_t bytes = read(fd, buf, sizeof(buf));
                if (bytes <= 0) break;
                send(client_sock, buf, bytes, 0);
            }
            close(fd);
        }
    }
    close(client_sock);
}

static void *web_thread(void *arg) {
    int port = *(int*)arg;
    free(arg);

    int server_fd;
    struct sockaddr_in address;
    int opt = 1;

    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);
    
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        log_error("Web server failed to bind port %d", port);
        return NULL;
    }
    listen(server_fd, 10);
    log_info("Web Dashboard listening on http://0.0.0.0:%d", port);

    while (1) {
        struct sockaddr_in c_addr;
        socklen_t l = sizeof(c_addr);
        int ns = accept(server_fd, (struct sockaddr *)&c_addr, &l);
        if (ns >= 0) {
            handle_client(ns);
        }
    }
    return NULL;
}

int web_server_start(int port) {
    pthread_t t;
    int *p = malloc(sizeof(int));
    *p = port;
    return pthread_create(&t, NULL, web_thread, p);
}
