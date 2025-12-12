#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    // Network & RPC
    char network[32];           // "mainnet"
    char rpc_url[256];          // 拼接后的完整 URL: http://host:port
    char rpc_user[128];
    char rpc_pass[128];
    char zmq_pub_hashblock[128]; // 保留字段，暂未实现ZMQ监听，仍使用 polling/signal

    // Mining
    char payout_addr[128];      // reward_address
    char coinbase_tag[64];      // pool_tag
    
    // Stratum
    int stratum_port;           // listen_port
    int poll_interval_sec;      // poll_interval (解析 "30s" -> 30)
    
    // Hardware (Bitaxe)
    uint32_t initial_diff;      // diff_asic
    int extranonce2_size;       
    char version_mask[32];      // 用于 ASICBoost

} AppConfig;

extern AppConfig g_config;

// 声明加载函数
int load_config(const char *filename);

#endif
