#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char rpc_url[256];          // 拼接后的完整 URL (http://...)
    char rpc_user[128];
    char rpc_pass[128];
    char payout_addr[128];      // reward_address
    char coinbase_tag[64];      // pool_tag
    int stratum_port;           // listen_port
    int poll_interval_sec;      // poll_interval
    uint32_t initial_diff;      // diff_asic
    int extranonce2_size;       
    char version_mask[32];      // 默认为 "1fffe000"
} AppConfig;

extern AppConfig g_config;

int load_config(const char *filename);

#endif
