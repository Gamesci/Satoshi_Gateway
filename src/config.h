#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>

typedef struct {
    char rpc_url;
    char rpc_user;
    char rpc_pass;
    char payout_addr;
    int stratum_port;
    uint32_t initial_diff;
} AppConfig;

extern AppConfig g_config;

#endif
