#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char rpc_url[256];
    char rpc_user[128];
    char rpc_pass[128];
    char zmq_addr[256];
    char payout_addr[128];
    char coinbase_tag[64];
    int stratum_port;
    int poll_interval_sec;
    
    // 难度与 VarDiff 配置
    int initial_diff;       // 对应 config.json 中的 diff_asic
    int vardiff_target;     // 对应 config.json 中的 vardiff_target_shares_min
    int vardiff_min_diff;   // 动态难度下限
    int vardiff_max_diff;   // 动态难度上限
    
    int extranonce2_size;
    uint32_t version_mask;  // Version Rolling Mask
} Config;

extern Config g_config;

int load_config(const char *filename);

#endif
