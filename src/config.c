#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "config.h"

AppConfig g_config;

// 辅助函数：处理字符串或整数输入
static void parse_int_field(json_t *root, const char *key, int *dest, int default_val) {
    json_t *item = json_object_get(root, key);
    if (!item) {
        *dest = default_val;
    } else if (json_is_integer(item)) {
        *dest = (int)json_integer_value(item);
    } else if (json_is_string(item)) {
        *dest = atoi(json_string_value(item));
    } else {
        *dest = default_val;
    }
}

static void parse_string_field(json_t *root, const char *key, char *dest, size_t size, const char *default_val) {
    json_t *item = json_object_get(root, key);
    if (item && json_is_string(item)) {
        strncpy(dest, json_string_value(item), size - 1);
        dest[size - 1] = '\0';
    } else {
        strncpy(dest, default_val, size - 1);
    }
}

int load_config(const char *filename) {
    json_error_t error;
    json_t *root = json_load_file(filename, 0, &error);
    
    if (!root) {
        fprintf(stderr, "[ERROR] Config load failed: %s (line %d)\n", error.text, error.line);
        return -1;
    }

    // 1. Network
    parse_string_field(root, "network", g_config.network, sizeof(g_config.network), "mainnet");
    
    // 2. RPC Logic: 处理 rpc_host 自动添加 http:// 前缀
    char rpc_host[128];
    parse_string_field(root, "rpc_host", rpc_host, sizeof(rpc_host), "127.0.0.1:8332");
    if (strncmp(rpc_host, "http", 4) != 0) {
        snprintf(g_config.rpc_url, sizeof(g_config.rpc_url), "http://%s", rpc_host);
    } else {
        strncpy(g_config.rpc_url, rpc_host, sizeof(g_config.rpc_url));
    }

    parse_string_field(root, "rpc_user", g_config.rpc_user, sizeof(g_config.rpc_user), "");
    parse_string_field(root, "rpc_pass", g_config.rpc_pass, sizeof(g_config.rpc_pass), "");
    parse_string_field(root, "zmq_pub_hashblock", g_config.zmq_pub_hashblock, sizeof(g_config.zmq_pub_hashblock), "");

    // 3. Mining
    parse_string_field(root, "reward_address", g_config.payout_addr, sizeof(g_config.payout_addr), "");
    parse_string_field(root, "pool_tag", g_config.coinbase_tag, sizeof(g_config.coinbase_tag), "/SatoshiGateway/");

    // 4. Stratum
    parse_int_field(root, "listen_port", &g_config.stratum_port, 3333);
    
    // 解析 poll_interval ("30s" -> 30)
    char poll_str[32];
    parse_string_field(root, "poll_interval", poll_str, sizeof(poll_str), "30s");
    g_config.poll_interval_sec = atoi(poll_str);
    if (g_config.poll_interval_sec <= 0) g_config.poll_interval_sec = 10;

    // 5. ASIC / Hardware
    int diff_val;
    parse_int_field(root, "diff_asic", &diff_val, 2048);
    g_config.initial_diff = (uint32_t)diff_val;
    
    parse_int_field(root, "extranonce2_size", &g_config.extranonce2_size, 4);
    parse_string_field(root, "version_mask", g_config.version_mask, sizeof(g_config.version_mask), "1fffe000");

    printf("[INFO] Config Loaded:\n");
    printf("  Target Node: %s\n", g_config.rpc_url);
    printf("  Payout Address: %s\n", g_config.payout_addr);
    printf("  Stratum Port: %d\n", g_config.stratum_port);
    printf("  ASIC Diff: %d\n", g_config.initial_diff);
    printf("  Version Mask: %s\n", g_config.version_mask);

    json_decref(root);
    return 0;
}
