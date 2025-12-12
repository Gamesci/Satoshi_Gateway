#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <jansson.h>
#include <unistd.h>
#include <pthread.h>
#include "bitcoin.h"
#include "config.h"
#include "stratum.h"
#include "utils.h"
#include "sha256.h"

static Template g_current_tmpl = {0};
static pthread_mutex_t g_tmpl_lock = PTHREAD_MUTEX_INITIALIZER;

// 前置声明
void address_to_script(const char *addr, char *script_hex);

struct MemoryStruct { char *memory; size_t size; };
static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if(!ptr) return 0;
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

static json_t* rpc_call(const char *method, json_t *params) {
    CURL *curl;
    struct MemoryStruct chunk = {0};
    chunk.memory = malloc(1);
    chunk.size = 0;
    curl = curl_easy_init();
    if (!curl) {
        log_error("Failed to init CURL");
        return NULL;
    }
    
    json_t *req = json_object();
    json_object_set_new(req, "jsonrpc", json_string("1.0"));
    json_object_set_new(req, "id", json_string("satoshi_gw"));
    json_object_set_new(req, "method", json_string(method));
    json_object_set_new(req, "params", params ? params : json_array());
    
    char *post_data = json_dumps(req, 0);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "content-type: text/plain;");
    
    curl_easy_setopt(curl, CURLOPT_URL, g_config.rpc_url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_USERNAME, g_config.rpc_user);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, g_config.rpc_pass);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L); 
    
    CURLcode res = curl_easy_perform(curl);
    json_t *response = NULL;
    
    if (res == CURLE_OK) {
        json_error_t err;
        response = json_loads(chunk.memory, 0, &err);
        if (!response) {
            log_error("RPC JSON Parse Error. Raw: %.100s...", chunk.memory);
        }
    } else {
        log_error("RPC Connection Failed: %s", curl_easy_strerror(res));
    }
    
    free(post_data);
    free(chunk.memory);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_decref(req);
    return response;
}

int bitcoin_init() {
    return curl_global_init(CURL_GLOBAL_ALL);
}

void bitcoin_cleanup_template(Template *t) {
    if (t->tx_hexs) {
        for (int i = 0; i < t->tx_count; i++) {
            if (t->tx_hexs[i]) free(t->tx_hexs[i]);
        }
        free(t->tx_hexs);
        t->tx_hexs = NULL;
    }
    t->tx_count = 0;
}

bool bitcoin_get_current_job_copy(Template *out) {
    pthread_mutex_lock(&g_tmpl_lock);
    if (strlen(g_current_tmpl.job_id) == 0) {
        pthread_mutex_unlock(&g_tmpl_lock);
        return false;
    }
    strcpy(out->job_id, g_current_tmpl.job_id);
    strcpy(out->prev_hash, g_current_tmpl.prev_hash);
    strcpy(out->coinb1, g_current_tmpl.coinb1);
    strcpy(out->coinb2, g_current_tmpl.coinb2);
    strcpy(out->version, g_current_tmpl.version);
    strcpy(out->nbits, g_current_tmpl.nbits);
    strcpy(out->ntime, g_current_tmpl.ntime);
    out->height = g_current_tmpl.height;
    out->clean_jobs = false;
    out->merkle_count = g_current_tmpl.merkle_count;
    for(int i=0; i<out->merkle_count; i++) {
        strcpy(out->merkle_branch[i], g_current_tmpl.merkle_branch[i]);
    }
    pthread_mutex_unlock(&g_tmpl_lock);
    return true;
}

void build_coinbase(uint32_t height, int64_t value, const char *msg, char *c1, char *c2, const char *default_witness) {
    // Part 1
    sprintf(c1, "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff");
    uint8_t h_le[4];
    h_le[0]=height&0xff; h_le[1]=(height>>8)&0xff; h_le[2]=(height>>16)&0xff; h_le[3]=(height>>24)&0xff;
    
    char tag_hex[128] = {0};
    for(int i=0; msg[i] && i<20; i++) sprintf(tag_hex + i*2, "%02x", (unsigned char)msg[i]);
    
    char script_sig[256];
    sprintf(script_sig, "2003%02x%02x%02x14%s", h_le[0], h_le[1], h_le[2], tag_hex);
    strcat(c1, script_sig);

    // Part 2
    sprintf(c2, "ffffffff02"); 
    char val_hex[17];
    sprintf(val_hex, "%016lx", value);
    uint8_t val_bin[8];
    hex2bin(val_hex, val_bin, 8);
    reverse_bytes(val_bin, 8);
    char val_hex_le[17];
    bin2hex(val_bin, 8, val_hex_le);
    strcat(c2, val_hex_le);

    char script_pubkey[256];
    address_to_script(g_config.payout_addr, script_pubkey);
    int script_len = strlen(script_pubkey) / 2;
    char len_hex[3];
    sprintf(len_hex, "%02x", script_len);
    strcat(c2, len_hex);
    strcat(c2, script_pubkey);

    strcat(c2, "0000000000000000"); 
    if (default_witness && strlen(default_witness) > 0) {
        int w_len = strlen(default_witness) / 2;
        char w_len_hex[3];
        sprintf(w_len_hex, "%02x", w_len);
        strcat(c2, w_len_hex);
        strcat(c2, default_witness);
    } else {
        strcat(c2, "266a24aa21a9ed0000000000000000000000000000000000000000000000000000000000000000");
    }
    strcat(c2, "00000000");
}

void calculate_merkle_branch(json_t *txs, Template *tmpl) {
    size_t count = json_array_size(txs);
    tmpl->tx_count = count;
    size_t total_leaves = count + 1; 
    uint8_t (*leaves)[32] = malloc(total_leaves * 32);
    tmpl->tx_hexs = malloc(count * sizeof(char*));
    
    for (size_t i = 0; i < count; i++) {
        json_t *tx = json_array_get(txs, i);
        const char *txid_hex = json_string_value(json_object_get(tx, "txid"));
        const char *data_hex = json_string_value(json_object_get(tx, "data"));
        
        if(!txid_hex || !data_hex) {
             tmpl->tx_hexs[i] = strdup(""); 
             memset(leaves[i+1], 0, 32);
             continue;
        }
        tmpl->tx_hexs[i] = strdup(data_hex);
        uint8_t bin[32];
        hex2bin(txid_hex, bin, 32);
        memcpy(leaves[i + 1], bin, 32);
    }
    
    int level_count = total_leaves;
    int branch_idx = 0;
    while (level_count > 1) {
        if (level_count > 1) {
            char hex[65];
            bin2hex(leaves[1], 32, hex);
            strcpy(tmpl->merkle_branch[branch_idx++], hex);
        }
        int next_level_count = 0;
        for (int i = 0; i < level_count; i += 2) {
            uint8_t *left = leaves[i];
            uint8_t *right = (i + 1 < level_count) ? leaves[i + 1] : leaves[i];
            uint8_t buffer[64];
            memcpy(buffer, left, 32);
            memcpy(buffer + 32, right, 32);
            sha256_double(buffer, 64, leaves[next_level_count]);
            next_level_count++;
        }
        level_count = next_level_count;
    }
    tmpl->merkle_count = branch_idx;
    free(leaves);
}

int encode_varint(uint8_t *buf, uint64_t n) {
    if (n < 0xfd) { buf[0] = n; return 1; }
    else if (n <= 0xffff) { buf[0] = 0xfd; *(uint16_t*)(buf+1) = (uint16_t)n; return 3; }
    else if (n <= 0xffffffff) { buf[0] = 0xfe; *(uint32_t*)(buf+1) = (uint32_t)n; return 5; }
    else { buf[0] = 0xff; *(uint64_t*)(buf+1) = n; return 9; }
}

int bitcoin_submit_block(const char *hex_data) {
    json_t *params = json_array();
    json_array_append_new(params, json_string(hex_data));
    json_t *resp = rpc_call("submitblock", params);
    
    int success = 0;
    if(resp) {
        json_t *res = json_object_get(resp, "result");
        if(json_is_null(res)) {
            success = 1;
        } else {
            log_error("Submit Block Rejected: %s", json_string_value(res));
        }
        json_decref(resp);
    } else {
        log_error("Submit Block Failed (RPC error)");
    }
    return success;
}

int bitcoin_reconstruct_and_submit(const char *job_id, const char *full_extranonce, const char *ntime, uint32_t nonce, uint32_t version_mask) {
    pthread_mutex_lock(&g_tmpl_lock);
    
    if (strcmp(job_id, g_current_tmpl.job_id) != 0) {
        pthread_mutex_unlock(&g_tmpl_lock);
        return 0; 
    }

    char coinbase_hex[8192];
    sprintf(coinbase_hex, "%s%s%s", g_current_tmpl.coinb1, full_extranonce, g_current_tmpl.coinb2);
    
    size_t total_size = 80 + 2048 + 2048; 
    for(int i=0; i<g_current_tmpl.tx_count; i++) total_size += strlen(g_current_tmpl.tx_hexs[i]);
    char *block_hex = malloc(total_size * 2);
    char *p = block_hex;
    
    uint8_t header[80];
    uint32_t ver = (version_mask != 0) ? version_mask : g_current_tmpl.version_int;
    *(uint32_t*)(header) = ver; 
    
    uint8_t prev_bin[32];
    hex2bin(g_current_tmpl.prev_hash, prev_bin, 32);
    memcpy(header+4, prev_bin, 32);
    
    uint8_t coinbase_bin[4096];
    size_t cb_len = strlen(coinbase_hex) / 2;
    hex2bin(coinbase_hex, coinbase_bin, cb_len);
    
    uint8_t current_hash[32];
    sha256_double(coinbase_bin, cb_len, current_hash);
    
    for (int i=0; i<g_current_tmpl.merkle_count; i++) {
        uint8_t branch_bin[32];
        hex2bin(g_current_tmpl.merkle_branch[i], branch_bin, 32);
        
        uint8_t concat[64];
        memcpy(concat, current_hash, 32);
        memcpy(concat+32, branch_bin, 32);
        sha256_double(concat, 64, current_hash);
    }
    memcpy(header+36, current_hash, 32);
    
    uint32_t t_val = strtoul(ntime, NULL, 16);
    *(uint32_t*)(header+68) = swap_uint32(t_val); 
    *(uint32_t*)(header+72) = g_current_tmpl.nbits_int;
    *(uint32_t*)(header+76) = nonce; 
    
    bin2hex(header, 80, p); p += 160;
    
    uint8_t vi[9];
    int vi_len = encode_varint(vi, 1 + g_current_tmpl.tx_count);
    bin2hex(vi, vi_len, p); p += (vi_len * 2);
    
    strcpy(p, coinbase_hex); p += strlen(coinbase_hex);
    for(int i=0; i<g_current_tmpl.tx_count; i++) {
        strcpy(p, g_current_tmpl.tx_hexs[i]);
        p += strlen(g_current_tmpl.tx_hexs[i]);
    }
    
    int ret = bitcoin_submit_block(block_hex);
    free(block_hex);
    pthread_mutex_unlock(&g_tmpl_lock);
    return ret;
}

// -------------------------------------------------------------------
// 核心逻辑: 宽容的 GBT 解析
// -------------------------------------------------------------------
void bitcoin_update_template(bool clean_jobs) {
    log_info("Fetching Block Template...");
    json_t *rules = json_array();
    json_array_append_new(rules, json_string("segwit"));
    json_array_append_new(rules, json_string("csv")); 
    json_t *args = json_object();
    json_object_set_new(args, "rules", rules);
    json_t *params = json_array();
    json_array_append_new(params, args);
    
    json_t *resp = rpc_call("getblocktemplate", params);
    
    if(!resp) {
        log_error("RPC Call returned NULL.");
        return;
    }

    json_t *error = json_object_get(resp, "error");
    if (error && !json_is_null(error)) {
        json_t *msg = json_object_get(error, "message");
        log_error("Node Error: %s", json_is_string(msg) ? json_string_value(msg) : "Unknown");
        json_decref(resp);
        return;
    }

    json_t *res = json_object_get(resp, "result");
    if (!res || !json_is_object(res)) {
        log_error("Invalid RPC: result is missing");
        json_decref(resp);
        return;
    }
    
    // 移除强制的 Missing Fields 检查，改为尝试读取
    pthread_mutex_lock(&g_tmpl_lock);
    
    bitcoin_cleanup_template(&g_current_tmpl);
    
    static int job_counter = 0;
    snprintf(g_current_tmpl.job_id, 32, "%x", ++job_counter);
    g_current_tmpl.clean_jobs = clean_jobs;
    
    g_current_tmpl.height = json_integer_value(json_object_get(res, "height"));
    
    // Version 处理 (兼容 Libre Relay 可能不返回 versionHex)
    json_t *j_ver_hex = json_object_get(res, "versionHex");
    g_current_tmpl.version_int = json_integer_value(json_object_get(res, "version"));
    
    if (j_ver_hex) {
        const char *ver_hex = json_string_value(j_ver_hex);
        strncpy(g_current_tmpl.version, ver_hex, 8);
    } else {
        // 如果没有 Hex，用整数生成 BE Hex
        sprintf(g_current_tmpl.version, "%08x", swap_uint32(g_current_tmpl.version_int));
    }
    
    const char *bits = json_string_value(json_object_get(res, "bits"));
    if(bits) strncpy(g_current_tmpl.nbits, bits, 8);
    else strcpy(g_current_tmpl.nbits, "1d00ffff"); // Fallback
    g_current_tmpl.nbits_int = strtoul(g_current_tmpl.nbits, NULL, 16);
    
    g_current_tmpl.ntime_int = json_integer_value(json_object_get(res, "curtime"));
    sprintf(g_current_tmpl.ntime, "%08x", swap_uint32(g_current_tmpl.ntime_int));
    
    // PrevHash 处理
    const char *prev = json_string_value(json_object_get(res, "previousblockhash"));
    if(prev) {
        uint8_t prev_bin[32];
        hex2bin(prev, prev_bin, 32);
        reverse_bytes(prev_bin, 32); 
        bin2hex(prev_bin, 32, g_current_tmpl.prev_hash);
    } else {
        // 如果连 PrevHash 都没有，可能是创世块或者严重错误
        log_error("PrevHash missing! Check Node.");
        memset(g_current_tmpl.prev_hash, '0', 64);
    }
    
    int64_t coin_val = json_integer_value(json_object_get(res, "coinbasevalue"));
    const char *def_wit = json_string_value(json_object_get(res, "default_witness_commitment"));
    build_coinbase(g_current_tmpl.height, coin_val, g_config.coinbase_tag, 
                   g_current_tmpl.coinb1, g_current_tmpl.coinb2, def_wit);
    
    json_t *txs = json_object_get(res, "transactions");
    if(txs) calculate_merkle_branch(txs, &g_current_tmpl);
    else g_current_tmpl.merkle_count = 0;
    
    log_info("New Job #%s Height:%d Txs:%d Ver:%s", g_current_tmpl.job_id, g_current_tmpl.height, g_current_tmpl.tx_count, g_current_tmpl.version);
    
    stratum_broadcast_job(&g_current_tmpl);
    
    pthread_mutex_unlock(&g_tmpl_lock);
    json_decref(resp);
}
