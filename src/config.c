#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "config.h"
#include "utils.h"

AppConfig g_config;

static void parse_string(json_t *root, const char *key, char *dest, size_t size, const char *def) {
    json_t *item = json_object_get(root, key);
    const char *val = (item && json_is_string(item)) ? json_string_value(item) : def;
    strncpy(dest, val, size - 1); dest[size - 1] = '\0';
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
    if (!root) { log_error("Config load error: %s", error.text); return -1; }

    char raw_host[128];
    parse_string(root, "rpc_host", raw_host, sizeof(raw_host), "127.0.0.1:8332");
    if (strncmp(raw_host, "http", 4) != 0) snprintf(g_config.rpc_url, sizeof(g_config.rpc_url), "http://%s", raw_host);
    else strncpy(g_config.rpc_url, raw_host, sizeof(g_config.rpc_url));

    parse_string(root, "rpc_user", g_config.rpc_user, sizeof(g_config.rpc_user), "");
    parse_string(root, "rpc_pass", g_config.rpc_pass, sizeof(g_config.rpc_pass), "");
    
    // 加载 ZMQ 地址 (例如 tcp://127.0.0.1:28332)
    parse_string(root, "zmq_pub_hashblock", g_config.zmq_addr, sizeof(g_config.zmq_addr), "");

    parse_string(root, "reward_address", g_config.payout_addr, sizeof(g_config.payout_addr), "");
    parse_string(root, "pool_tag", g_config.coinbase_tag, sizeof(g_config.coinbase_tag), "/SatoshiGateway/");
    
    g_config.stratum_port = parse_int_loose(root, "listen_port", 3333);
    char poll_str[32]; parse_string(root, "poll_interval", poll_str, sizeof(poll_str), "30s");
    g_config.poll_interval_sec = atoi(poll_str); if(g_config.poll_interval_sec <= 0) g_config.poll_interval_sec = 30;

    g_config.initial_diff = parse_int_loose(root, "diff_asic", 2048);
    g_config.extranonce2_size = parse_int_loose(root, "extranonce2_size", 8);
    
    char mask_str[32]; parse_string(root, "version_mask", mask_str, sizeof(mask_str), "1fffe000");
    g_config.version_mask = (uint32_t)strtoul(mask_str, NULL, 16);

    json_decref(root);
    return 0;
}
