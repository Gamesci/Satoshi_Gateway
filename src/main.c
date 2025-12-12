#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "config.h"
#include "bitcoin.h"
#include "stratum.h"
#include "utils.h" 

volatile sig_atomic_t g_block_notify = 0;

// 信号处理函数：当 bitcoind 发现新块时发送 SIGUSR1
void handle_signal(int sig) { 
    if(sig == SIGUSR1) g_block_notify = 1; 
}

int main(int argc, char *argv[]) {
    // 禁用 stdout 缓冲，确保 Docker logs 实时显示
    setbuf(stdout, NULL);
    
    const char *conf_file = "config.json";
    if(argc > 2 && strcmp(argv[1], "-c") == 0) conf_file = argv[2];
    
    log_info("Starting Satoshi Gateway...");
    
    // 1. 加载配置
    if(load_config(conf_file) != 0) {
        log_error("Config load failed. Check %s", conf_file);
        return 1;
    }
    
    // 2. 注册信号
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGUSR1, &sa, NULL);
    signal(SIGPIPE, SIG_IGN); // 防止 broken pipe 导致退出
    
    // 3. 初始化模块
    if(bitcoin_init() != 0) {
        log_error("Bitcoin module init failed");
        return 1;
    }
    
    // 4. 启动 Stratum 服务器线程
    if(stratum_start_thread() != 0) {
        log_error("Stratum server init failed");
        return 1;
    }
    
    log_info("Gateway ready on port %d", g_config.stratum_port);
    log_info("Target Node: %s", g_config.rpc_url);
    log_info("Payout Address: %s", g_config.payout_addr);
    
    // 5. 首次获取任务 (Force Clean)
    bitcoin_update_template(true);
    time_t last_check = time(NULL);
    
    // 6. 主循环
    while(1) {
        // 检查信号标志 (Bitcoind Block Notify)
        if(g_block_notify) {
            log_info("Signal received: New Block detected!");
            g_block_notify = 0;
            bitcoin_update_template(true); // 强制刷新
            last_check = time(NULL);
        }
        
        // 定期轮询 (Poll Interval)
        time_t now = time(NULL);
        if(now - last_check >= g_config.poll_interval_sec) {
            // 普通轮询，force_clean=false (内部会自动判断是否需要clean)
            bitcoin_update_template(false);
            last_check = now;
        }
        
        usleep(100000); // 100ms 休眠，避免 CPU 空转
    }
    return 0;
}
