#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "config.h"
#include "utils.h" // for log_error

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
    if (json_is_string(item)) return atoi(json_string_value(item));
    return def;
}

int load_config(const char *filename) {
    json_error_t error;
    json_t *root = json_load_file(filename, 0, &error);
    if (!root) {
        log_error("Config load error: %s (Line %d)", error.text, error.line);
        return -1;
    }

    // 1. RPC (Auto prepend http://)
    char raw_host[128];
    parse_string(root, "rpc_host", raw_host, sizeof(raw_host), "127.0.0.1:8332");
    if (strncmp(raw_host, "http", 4) != 0) snprintf(g_config.rpc_url, sizeof(g_config.rpc_url), "http://%s", raw_host);
    else strncpy(g_config.rpc_url, raw_host, sizeof(g_config.rpc_url));

    parse_string(root, "rpc_user", g_config.rpc_user, sizeof(g_config.rpc_user), "");
    parse_string(root, "rpc_pass", g_config.rpc_pass, sizeof(g_config.rpc_pass), "");
    
    // 2. Mining Config
    parse_string(root, "reward_address", g_config.payout_addr, sizeof(g_config.payout_addr), "");
    parse_string(root, "pool_tag", g_config.coinbase_tag, sizeof(g_config.coinbase_tag), "/SatoshiGateway/");
    
    // 3. Stratum Config
    g_config.stratum_port = parse_int_loose(root, "listen_port", 3333);
    
    char poll_str[32];
    parse_string(root, "poll_interval", poll_str, sizeof(poll_str), "10s");
    g_config.poll_interval_sec = atoi(poll_str);
    if(g_config.poll_interval_sec <= 0) g_config.poll_interval_sec = 10;

    // 4. ASIC / Hardware
    g_config.initial_diff = parse_int_loose(root, "diff_asic", 2048);
    g_config.extranonce2_size = parse_int_loose(root, "extranonce2_size", 8);
    
    // Version Mask (Default 0x1fffe000 for standard ASICBoost)
    // 配置文件可能写 "1fffe000" 或 "0x1fffe000"
    char mask_str[32];
    parse_string(root, "version_mask", mask_str, sizeof(mask_str), "1fffe000");
    g_config.version_mask = (uint32_t)strtoul(mask_str, NULL, 16);

    json_decref(root);
    return 0;
}
