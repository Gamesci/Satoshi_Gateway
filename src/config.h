#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    // RPC
    char rpc_url[256];
    char rpc_user[128];
    char rpc_pass[128];
    
    // Mining
    char payout_addr[128];
    char coinbase_tag[64];
    
    // Stratum
    int stratum_port;
    int poll_interval_sec;
    
    // Hardware / ASIC
    uint32_t initial_diff;
    int extranonce2_size;
    uint32_t version_mask; // 用于 Version Rolling (ASICBoost)
    
} AppConfig;

extern AppConfig g_config;

int load_config(const char *filename);

#endif
