#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "config.h"

AppConfig g_config;

static void parse_string(json_t *root, const char *key, char *dest, size_t size, const char *def) {
    json_t *item = json_object_get(root, key);
    const char *val = (item && json_is_string(item)) ? json_string_value(item) : def;
    strncpy(dest, val, size - 1);
    dest[size - 1] = '\0';
}

static int parse_int_loose(json_t *root, const char *key, int def) {
    json_t *item = json_object_get(root, key);
    if (!item) return def;
    if (json_is_integer(item)) return (int)json_integer_value(item);
    if (json_is_string(item)) return atoi(json_string_value(item)); // 处理 "3333" 这种字符串
    return def;
}

int load_config(const char *filename) {
    json_error_t error;
    json_t *root = json_load_file(filename, 0, &error);
    if (!root) {
        fprintf(stderr, "[CONFIG] Load failed: %s (Line %d)\n", error.text, error.line);
        return -1;
    }

    // 1. RPC Host 处理 (自动补全 http://)
    char raw_host[128];
    parse_string(root, "rpc_host", raw_host, sizeof(raw_host), "127.0.0.1:8332");
    if (strncmp(raw_host, "http", 4) != 0) snprintf(g_config.rpc_url, sizeof(g_config.rpc_url), "http://%s", raw_host);
    else strncpy(g_config.rpc_url, raw_host, sizeof(g_config.rpc_url));

    parse_string(root, "rpc_user", g_config.rpc_user, sizeof(g_config.rpc_user), "");
    parse_string(root, "rpc_pass", g_config.rpc_pass, sizeof(g_config.rpc_pass), "");
    
    // 2. 挖矿相关
    parse_string(root, "reward_address", g_config.payout_addr, sizeof(g_config.payout_addr), "");
    parse_string(root, "pool_tag", g_config.coinbase_tag, sizeof(g_config.coinbase_tag), "/SatoshiGateway/");
    
    // 3. 端口与轮询
    g_config.stratum_port = parse_int_loose(root, "listen_port", 3333);
    
    char poll_str[32];
    parse_string(root, "poll_interval", poll_str, sizeof(poll_str), "30s");
    g_config.poll_interval_sec = atoi(poll_str);
    if(g_config.poll_interval_sec <= 0) g_config.poll_interval_sec = 30;

    // 4. 硬件参数
    g_config.initial_diff = parse_int_loose(root, "diff_asic", 1000);
    g_config.extranonce2_size = parse_int_loose(root, "extranonce2_size", 8);
    
    // Bitaxe 默认掩码
    parse_string(root, "version_mask", g_config.version_mask, sizeof(g_config.version_mask), "1fffe000");

    json_decref(root);
    return 0;
}
