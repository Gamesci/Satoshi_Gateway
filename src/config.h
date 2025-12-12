#ifndef CONFIG_H
#define CONFIG_H
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char rpc_url[256];
    char rpc_user[128];
    char rpc_pass[128];
    char zmq_addr[256];     // 新增: ZMQ 地址
    
    char payout_addr[128];
    char coinbase_tag[64];
    
    int stratum_port;
    int poll_interval_sec;
    uint32_t initial_diff;
    int extranonce2_size;
    uint32_t version_mask;
} AppConfig;

extern AppConfig g_config;
int load_config(const char *filename);
#endif
