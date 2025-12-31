#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include "config.h"
#include "utils.h"

Config g_config;

static void safe_read_string(json_t *root, const char *key, char *dest, size_t dest_size) {
    json_t *obj = json_object_get(root, key);
    if (!obj) return;
    const char *val = json_string_value(obj);
    if (!val) return;
    strncpy(dest, val, dest_size - 1);
    dest[dest_size - 1] = '\0';
}

static void normalize_rpc_url(void) {
    if (strlen(g_config.rpc_url) == 0) return;
    if (strncmp(g_config.rpc_url, "http://", 7) == 0) return;
    if (strncmp(g_config.rpc_url, "https://", 8) == 0) return;
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "http://%s", g_config.rpc_url);
    strncpy(g_config.rpc_url, tmp, sizeof(g_config.rpc_url) - 1);
    g_config.rpc_url[sizeof(g_config.rpc_url) - 1] = '\0';
}

int load_config(const char *filename) {
    memset(&g_config, 0, sizeof(g_config));

    json_error_t error;
    json_t *root = json_load_file(filename, 0, &error);
    if (!root) {
        log_error("Config Error: %s line %d", error.text, error.line);
        return -1;
    }

    const char *url = json_string_value(json_object_get(root, "rpc_url"));
    if (url) {
        strncpy(g_config.rpc_url, url, sizeof(g_config.rpc_url) - 1);
        g_config.rpc_url[sizeof(g_config.rpc_url) - 1] = '\0';
    } else {
        const char *host = json_string_value(json_object_get(root, "rpc_host"));
        if (host) {
            snprintf(g_config.rpc_url, sizeof(g_config.rpc_url), "http://%s", host);
        } else {
            log_error("Config Error: Missing 'rpc_url'!");
            json_decref(root);
            return -1;
        }
    }
    normalize_rpc_url();

    safe_read_string(root, "rpc_user", g_config.rpc_user, sizeof(g_config.rpc_user));
    safe_read_string(root, "rpc_pass", g_config.rpc_pass, sizeof(g_config.rpc_pass));
    safe_read_string(root, "zmq_pub_hashblock", g_config.zmq_addr, sizeof(g_config.zmq_addr));
    
    // [NEW] P2P Config Loader
    safe_read_string(root, "p2p_host", g_config.p2p_host, sizeof(g_config.p2p_host));
    if (strlen(g_config.p2p_host) == 0) strcpy(g_config.p2p_host, "127.0.0.1"); // Default
    
    json_t *p2p_p = json_object_get(root, "p2p_port");
    g_config.p2p_port = (p2p_p && json_is_integer(p2p_p)) ? (int)json_integer_value(p2p_p) : 8333;

    json_t *p2p_m = json_object_get(root, "p2p_magic");
    if (p2p_m && json_is_string(p2p_m)) {
        g_config.p2p_magic = (uint32_t)strtoul(json_string_value(p2p_m), NULL, 16);
    } else {
        g_config.p2p_magic = 0xD9B4BEF9; // Default Mainnet
    }

    safe_read_string(root, "reward_address", g_config.payout_addr, sizeof(g_config.payout_addr));
    safe_read_string(root, "pool_tag", g_config.coinbase_tag, sizeof(g_config.coinbase_tag));

    json_t *port = json_object_get(root, "listen_port");
    g_config.stratum_port = (port && json_is_integer(port)) ? (int)json_integer_value(port) : 3333;

    json_t *diff = json_object_get(root, "diff_asic");
    if (diff) {
        if (json_is_integer(diff)) g_config.initial_diff = (double)json_integer_value(diff);
        else if (json_is_real(diff)) g_config.initial_diff = json_real_value(diff);
        else g_config.initial_diff = 1024.0;
    } else g_config.initial_diff = 1024.0;

    json_t *vd_target = json_object_get(root, "vardiff_target_shares_min");
    g_config.vardiff_target = (vd_target && json_is_integer(vd_target)) ? (int)json_integer_value(vd_target) : 20;

    g_config.vardiff_min_diff = g_config.initial_diff / 256.0;
    if (g_config.vardiff_min_diff < 1.0) g_config.vardiff_min_diff = 1.0;
    g_config.vardiff_max_diff = g_config.initial_diff * 4096.0;

    json_t *poll = json_object_get(root, "poll_interval");
    g_config.poll_interval_sec = (poll && json_is_integer(poll)) ? (int)json_integer_value(poll) : 30;

    json_t *en2 = json_object_get(root, "extranonce2_size");
    g_config.extranonce2_size = (en2 && json_is_integer(en2)) ? (int)json_integer_value(en2) : 8;

    g_config.version_mask = 0;
    json_t *vm = json_object_get(root, "version_mask");
    if (vm && json_is_string(vm)) {
        g_config.version_mask = (uint32_t)strtoul(json_string_value(vm), NULL, 16);
    }

    char script_hex[256];
    if (!address_to_script_checked(g_config.payout_addr, script_hex, sizeof(script_hex))) {
        log_error("Config Error: invalid reward_address: %s", g_config.payout_addr);
        json_decref(root);
        return -1;
    }

    json_decref(root);
    return 0;
}
