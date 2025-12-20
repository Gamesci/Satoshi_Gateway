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
    // Accept:
    //  - "127.0.0.1:8332"  -> "http://127.0.0.1:8332"
    //  - "http://..." or "https://..." kept
    if (strlen(g_config.rpc_url) == 0) return;
    if (strncmp(g_config.rpc_url, "http://", 7) == 0) return;
    if (strncmp(g_config.rpc_url, "https://", 8) == 0) return;

    // Increased buffer size to 512 to prevent truncation warnings
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
            log_error("Config Error: Missing 'rpc_url' or 'rpc_host'!");
            json_decref(root);
            return -1;
        }
    }
    normalize_rpc_url();

    safe_read_string(root, "rpc_user", g_config.rpc_user, sizeof(g_config.rpc_user));
    safe_read_string(root, "rpc_pass", g_config.rpc_pass, sizeof(g_config.rpc_pass));
    safe_read_string(root, "zmq_pub_hashblock", g_config.zmq_addr, sizeof(g_config.zmq_addr));
    safe_read_string(root, "reward_address", g_config.payout_addr, sizeof(g_config.payout_addr));
    safe_read_string(root, "pool_tag", g_config.coinbase_tag, sizeof(g_config.coinbase_tag));

    json_t *port = json_object_get(root, "listen_port");
    if (port) {
        if (json_is_string(port)) g_config.stratum_port = atoi(json_string_value(port));
        else if (json_is_integer(port)) g_config.stratum_port = (int)json_integer_value(port);
    }
    if (g_config.stratum_port <= 0) g_config.stratum_port = 3333;

    json_t *diff = json_object_get(root, "diff_asic");
    g_config.initial_diff = (diff && json_is_integer(diff)) ? (int)json_integer_value(diff) : 1024;
    if (g_config.initial_diff < 1) g_config.initial_diff = 1;

    json_t *vd_target = json_object_get(root, "vardiff_target_shares_min");
    g_config.vardiff_target = (vd_target && json_is_integer(vd_target)) ? (int)json_integer_value(vd_target) : 20;
    if (g_config.vardiff_target < 1) g_config.vardiff_target = 1;

    g_config.vardiff_min_diff = g_config.initial_diff / 4;
    if (g_config.vardiff_min_diff < 1) g_config.vardiff_min_diff = 1;
    g_config.vardiff_max_diff = g_config.initial_diff * 4096;

    json_t *poll = json_object_get(root, "poll_interval");
    if (poll) {
        if (json_is_string(poll)) g_config.poll_interval_sec = atoi(json_string_value(poll));
        else if (json_is_integer(poll)) g_config.poll_interval_sec = (int)json_integer_value(poll);
    }
    if (g_config.poll_interval_sec <= 0) g_config.poll_interval_sec = 30;

    json_t *en2 = json_object_get(root, "extranonce2_size");
    g_config.extranonce2_size = (en2 && json_is_integer(en2)) ? (int)json_integer_value(en2) : 8;
    // Safety bounds (scriptSig push + typical miners)
    if (g_config.extranonce2_size < 4) g_config.extranonce2_size = 4;
    if (g_config.extranonce2_size > 32) g_config.extranonce2_size = 32;

    g_config.version_mask = 0;
    json_t *vm = json_object_get(root, "version_mask");
    if (vm && json_is_string(vm)) {
        g_config.version_mask = (uint32_t)strtoul(json_string_value(vm), NULL, 16);
    }

    // Validate payout address early
    char script_hex[256];
    if (!address_to_script_checked(g_config.payout_addr, script_hex, sizeof(script_hex))) {
        log_error("Config Error: invalid reward_address: %s", g_config.payout_addr);
        json_decref(root);
        return -1;
    }

    json_decref(root);
    return 0;
}
