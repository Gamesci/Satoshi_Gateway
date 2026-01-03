#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdbool.h>

typedef struct {
    // Stratum Config
    int stratum_port;
    int diff_retarget_interval; // seconds
    
    // RPC Config (Local Node Data Source)
    char rpc_url[128];
    char rpc_user[64];
    char rpc_pass[64];
    
    // ZMQ Config (Local Node Backup Signal)
    char zmq_addr[128];
    
    // P2P Config - Fast Node (Primary Signal Source)
    char p2p_host[64];
    int p2p_port;
    
    // [NEW] P2P Config - Local Node (Secondary Signal Source / Bridge)
    char local_p2p_host[64];
    int local_p2p_port;

    // P2P Magic (Network ID)
    uint32_t p2p_magic;
    
    // Mining Config
    char payout_addr[64];
    char coinbase_tag[64];
    uint32_t version_mask;
    int extranonce2_size;
    
    // Diff & Vardiff
    double initial_diff;
    int vardiff_target;
    double vardiff_min_diff;
    double vardiff_max_diff;
    int poll_interval_sec;

} Config;

extern Config g_config;

int load_config(const char *filename);

#endif
