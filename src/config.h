#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    char rpc_url[256];
    char rpc_user[128];
    char rpc_pass[128];
    char zmq_addr[256];
    
    // [NEW] P2P Config
    char p2p_host[128];
    int p2p_port;
    uint32_t p2p_magic;

    char payout_addr[128];
    char coinbase_tag[64];
    int stratum_port;
    int poll_interval_sec;

    double initial_diff;
    int vardiff_target;
    double vardiff_min_diff;
    double vardiff_max_diff;

    int extranonce2_size;
    uint32_t version_mask;
} Config;

extern Config g_config;

int load_config(const char *filename);

#endif
