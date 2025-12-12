#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include "config.h"
#include "bitcoin.h"
#include "stratum.h"

// 全局配置实例
AppConfig g_config;
volatile sig_atomic_t g_block_notify = 0;

void handle_signal(int sig) {
    if (sig == SIGUSR1) {
        g_block_notify = 1;
    }
}

void load_config(const char *filename) {
    // 简化的配置加载，实际使用时建议使用 jansson 解析 JSON 文件
    // 这里为了展示核心逻辑，使用硬编码默认值，你可以扩展为读取 satoshi.conf
    strcpy(g_config.rpc_url, "http://127.0.0.1:8332");
    strcpy(g_config.rpc_user, "user");
    strcpy(g_config.rpc_pass, "password");
    strcpy(g_config.payout_addr, "bc1q..."); // 你的挖矿地址
    g_config.stratum_port = 23334;
    g_config.initial_diff = 2048; 
    
    printf(" Config loaded. Target Node: %s\n", g_config.rpc_url);
}

int main(int argc, char *argv) {
    if (argc > 1 && strcmp(argv[1], "-c") == 0 && argv[2]) {
        load_config(argv[2]);
    } else {
        load_config("satoshi.conf");
    }

    // 注册信号
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGUSR1, &sa, NULL);

    // 初始化 Bitcoin RPC
    if (bitcoin_init()!= 0) {
        fprintf(stderr, " Failed to init Bitcoin RPC\n");
        return 1;
    }

    // 启动 Stratum 服务器线程
    if (stratum_start_thread()!= 0) {
        fprintf(stderr, " Failed to start Stratum server\n");
        return 1;
    }

    printf("[INFO] Satoshi Gateway running. Waiting for miners...\n");
    printf("[INFO] Tip: Run 'killall -USR1 satoshi_gateway' when new block arrives.\n");

    // 主循环
    while (1) {
        if (g_block_notify) {
            printf(" New Block Detected! Refreshing template...\n");
            g_block_notify = 0;
            bitcoin_update_template(true); // 强制更新
        }
        
        // 定期轮询兜底 (每30秒)
        static time_t last_check = 0;
        time_t now = time(NULL);
        if (now - last_check > 30) {
            bitcoin_update_template(false);
            last_check = now;
        }

        usleep(100000); // 100ms sleep
    }

    return 0;
}
