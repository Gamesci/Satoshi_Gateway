// src/main.c
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "config.h"
#include "bitcoin.h"
#include "stratum.h"

volatile sig_atomic_t g_block_notify = 0;

void handle_signal(int sig) {
    if (sig == SIGUSR1) {
        g_block_notify = 1;
    }
}

int main(int argc, char *argv[]) {
    const char *config_file = "config.json"; // 默认文件名
    
    // 简单的参数解析，支持 -c 指定配置文件
    if (argc > 1) {
        if (strcmp(argv[1], "-c") == 0 && argc > 2) {
            config_file = argv[2];
        } else {
            config_file = argv[1]; // 允许直接传文件名
        }
    }

    // 1. 加载配置
    if (load_config(config_file) != 0) {
        fprintf(stderr, "[FATAL] Cannot load config file: %s\n", config_file);
        return 1;
    }

    // 2. 注册信号 (Block Notify)
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGUSR1, &sa, NULL);

    // 3. 初始化模块
    if (bitcoin_init() != 0) {
        fprintf(stderr, "[FATAL] Failed to init Bitcoin RPC\n");
        return 1;
    }

    if (stratum_start_thread() != 0) {
        fprintf(stderr, "[FATAL] Failed to start Stratum server\n");
        return 1;
    }

    printf("[INFO] Satoshi Gateway running on port %d. Waiting for Bitaxe...\n", g_config.stratum_port);

    // 4. 主循环
    static time_t last_check = 0;
    
    // 启动时立即获取一次模板
    bitcoin_update_template(true); 

    while (1) {
        // 信号触发（来自节点的 blocknotify）
        if (g_block_notify) {
            printf("[EVENT] New Block Detected (Signal)! Refreshing...\n");
            g_block_notify = 0;
            bitcoin_update_template(true); // clean_jobs=true
            last_check = time(NULL);
        }

        // 定时轮询兜底
        time_t now = time(NULL);
        if (now - last_check >= g_config.poll_interval_sec) {
            // printf("[DEBUG] Polling template update...\n");
            bitcoin_update_template(false); // clean_jobs=false
            last_check = now;
        }

        usleep(100000); // 100ms 休眠
    }

    return 0;
}
