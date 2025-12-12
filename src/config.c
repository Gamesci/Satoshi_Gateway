#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "config.h"
#include "utils.h"

Config g_config;

int load_config(const char *filename) {
    json_error_t error;
    json_t *root = json_load_file(filename, 0, &error);
    if (!root) {
        log_error("Config Error: %s line %d", error.text, error.line);
        return -1;
    }

    // RPC & Network
    strncpy(g_config.rpc_url, json_string_value(json_object_get(root, "rpc_url")), sizeof(g_config.rpc_url)-1);
    const char *rpc_host = json_string_value(json_object_get(root, "rpc_host")); // 兼容旧配置
    if(rpc_host) snprintf(g_config.rpc_url, sizeof(g_config.rpc_url), "http://%s", rpc_host);
    
    strncpy(g_config.rpc_user, json_string_value(json_object_get(root, "rpc_user")), sizeof(g_config.rpc_user)-1);
    strncpy(g_config.rpc_pass, json_string_value(json_object_get(root, "rpc_pass")), sizeof(g_config.rpc_pass)-1);
    
    const char *zmq = json_string_value(json_object_get(root, "zmq_pub_hashblock"));
    if(zmq) strncpy(g_config.zmq_addr, zmq, sizeof(g_config.zmq_addr)-1);
    else g_config.zmq_addr[0] = 0;

    // Mining Info
    const char *reward = json_string_value(json_object_get(root, "reward_address"));
    if(reward) strncpy(g_config.payout_addr, reward, sizeof(g_config.payout_addr)-1);
    
    const char *tag = json_string_value(json_object_get(root, "pool_tag"));
    if(tag) strncpy(g_config.coinbase_tag, tag, sizeof(g_config.coinbase_tag)-1);

    // Stratum Settings
    json_t *port = json_object_get(root, "listen_port");
    if(json_is_string(port)) g_config.stratum_port = atoi(json_string_value(port));
    else g_config.stratum_port = json_integer_value(port);

    // Difficulty & VarDiff
    // 读取 diff_asic 作为初始难度
    json_t *diff = json_object_get(root, "diff_asic");
    if(diff) g_config.initial_diff = json_integer_value(diff);
    else g_config.initial_diff = 1024; // 默认值

    // 读取 vardiff_target_shares_min
    json_t *vd_target = json_object_get(root, "vardiff_target_shares_min");
    if(vd_target) g_config.vardiff_target = json_integer_value(vd_target);
    else g_config.vardiff_target = 20; // 默认每分钟 20 Shares

    // 自动设定最小/最大难度范围
    g_config.vardiff_min_diff = g_config.initial_diff / 4; 
    if (g_config.vardiff_min_diff < 1) g_config.vardiff_min_diff = 1;
    g_config.vardiff_max_diff = g_config.initial_diff * 4096; 

    // Others
    json_t *poll = json_object_get(root, "poll_interval");
    if(poll && json_is_string(poll)) g_config.poll_interval_sec = atoi(json_string_value(poll));
    else g_config.poll_interval_sec = 30;

    json_t *en2 = json_object_get(root, "extranonce2_size");
    g_config.extranonce2_size = en2 ? json_integer_value(en2) : 8;

    g_config.version_mask = 0; // 默认不做 version rolling
    json_t *vm = json_object_get(root, "version_mask");
    if(vm) g_config.version_mask = strtoul(json_string_value(vm), NULL, 16);

    json_decref(root);
    return 0;
}
