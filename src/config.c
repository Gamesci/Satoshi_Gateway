#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "config.h"
#include "utils.h"

Config g_config;

// 辅助函数：安全读取字符串，防止 NULL 导致 crash
static void safe_read_string(json_t *root, const char *key, char *dest, size_t dest_size) {
    json_t *obj = json_object_get(root, key);
    if (!obj) return; // 键不存在，保持默认值或空
    
    const char *val = json_string_value(obj);
    if (val) {
        strncpy(dest, val, dest_size - 1);
        dest[dest_size - 1] = '\0'; // 确保 NULL 结尾
    }
}

int load_config(const char *filename) {
    json_error_t error;
    json_t *root = json_load_file(filename, 0, &error);
    if (!root) {
        log_error("Config Error: %s line %d", error.text, error.line);
        return -1;
    }

    // 1. RPC URL 处理 (优先 rpc_url，其次用 rpc_host 拼接)
    const char *url = json_string_value(json_object_get(root, "rpc_url"));
    if (url) {
        strncpy(g_config.rpc_url, url, sizeof(g_config.rpc_url) - 1);
    } else {
        // 兼容旧配置 rpc_host
        const char *host = json_string_value(json_object_get(root, "rpc_host"));
        if (host) {
            snprintf(g_config.rpc_url, sizeof(g_config.rpc_url), "http://%s", host);
        } else {
            // 如果两个都没有，这是一个严重错误
            log_error("Config Error: Missing 'rpc_url' or 'rpc_host'!");
            json_decref(root);
            return -1;
        }
    }

    // 2. 其他字符串字段 (使用安全读取函数)
    safe_read_string(root, "rpc_user", g_config.rpc_user, sizeof(g_config.rpc_user));
    safe_read_string(root, "rpc_pass", g_config.rpc_pass, sizeof(g_config.rpc_pass));
    safe_read_string(root, "zmq_pub_hashblock", g_config.zmq_addr, sizeof(g_config.zmq_addr));
    safe_read_string(root, "reward_address", g_config.payout_addr, sizeof(g_config.payout_addr));
    safe_read_string(root, "pool_tag", g_config.coinbase_tag, sizeof(g_config.coinbase_tag));

    // 3. 端口 (支持字符串或整数)
    json_t *port = json_object_get(root, "listen_port");
    if (port) {
        if (json_is_string(port)) g_config.stratum_port = atoi(json_string_value(port));
        else if (json_is_integer(port)) g_config.stratum_port = json_integer_value(port);
    }
    if (g_config.stratum_port <= 0) g_config.stratum_port = 3333;

    // 4. 难度与 VarDiff
    json_t *diff = json_object_get(root, "diff_asic");
    if (diff) g_config.initial_diff = json_integer_value(diff);
    else g_config.initial_diff = 1024;

    json_t *vd_target = json_object_get(root, "vardiff_target_shares_min");
    if (vd_target) g_config.vardiff_target = json_integer_value(vd_target);
    else g_config.vardiff_target = 20;

    // 自动设定 VarDiff 范围
    g_config.vardiff_min_diff = g_config.initial_diff / 4;
    if (g_config.vardiff_min_diff < 1) g_config.vardiff_min_diff = 1;
    g_config.vardiff_max_diff = g_config.initial_diff * 4096;

    // 5. 轮询间隔 (支持 "30s" 这种带单位的字符串)
    json_t *poll = json_object_get(root, "poll_interval");
    if (poll) {
        if (json_is_string(poll)) g_config.poll_interval_sec = atoi(json_string_value(poll));
        else if (json_is_integer(poll)) g_config.poll_interval_sec = json_integer_value(poll);
    }
    if (g_config.poll_interval_sec <= 0) g_config.poll_interval_sec = 30;

    // 6. 其他配置
    json_t *en2 = json_object_get(root, "extranonce2_size");
    g_config.extranonce2_size = (en2 && json_is_integer(en2)) ? json_integer_value(en2) : 8;

    g_config.version_mask = 0;
    json_t *vm = json_object_get(root, "version_mask");
    if (vm && json_is_string(vm)) {
        g_config.version_mask = strtoul(json_string_value(vm), NULL, 16);
    }

    json_decref(root);
    return 0;
}
