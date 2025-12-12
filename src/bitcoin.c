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

// --- 全局变量 ---
static Template g_current_tmpl = {0};
static pthread_mutex_t g_tmpl_lock = PTHREAD_MUTEX_INITIALIZER;

// --- 声明本地辅助函数 ---
void address_to_script(const char *addr, char *script_hex); // 定义在下方

// --- CURL 内存写入回调 ---
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

// --- RPC 调用封装 ---
static json_t* rpc_call(const char *method, json_t *params) {
    CURL *curl;
    struct MemoryStruct chunk = {0};
    chunk.memory = malloc(1);
    chunk.size = 0;
    curl = curl_easy_init();
    if (!curl) return NULL;
    
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
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L); // 增加超时防止大区块获取失败
    
    CURLcode res = curl_easy_perform(curl);
    json_t *response = NULL;
    
    if (res == CURLE_OK) {
        json_error_t err;
        response = json_loads(chunk.memory, 0, &err);
        if (!response) printf("[RPC] JSON Error: %s\n", err.text);
    } else {
        printf("[RPC] Curl Error: %s\n", curl_easy_strerror(res));
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

// --- 地址转换逻辑 (复用之前的逻辑) ---
void address_to_script(const char *addr, char *script_hex) {
    uint8_t buf[64];
    size_t len = 0;
    int witver;
    
    // 1. Bech32 (SegWit)
    if (segwit_addr_decode(&witver, buf, &len, "bc", addr) || 
        segwit_addr_decode(&witver, buf, &len, "tb", addr) || 
        segwit_addr_decode(&witver, buf, &len, "bcrt", addr)) {
        uint8_t op_ver = (witver == 0) ? 0x00 : (0x50 + witver);
        sprintf(script_hex, "%02x%02x", op_ver, (int)len);
        char prog_hex[128];
        bin2hex(buf, len, prog_hex);
        strcat(script_hex, prog_hex);
        return;
    }
    
    // 2. Base58 (Legacy)
    int ver = base58_decode_check(addr, buf, &len);
    if (ver >= 0) {
        if (ver == 0 || ver == 111) { // P2PKH
            strcpy(script_hex, "76a914");
            char hash_hex[41];
            bin2hex(buf, len, hash_hex);
            strcat(script_hex, hash_hex);
            strcat(script_hex, "88ac");
            return;
        } else if (ver == 5 || ver == 196) { // P2SH
            strcpy(script_hex, "a914");
            char hash_hex[41];
            bin2hex(buf, len, hash_hex);
            strcat(script_hex, hash_hex);
            strcat(script_hex, "87");
            return;
        }
    }
    
    // Fallback: OP_RETURN (防止崩溃)
    printf("[WARN] Invalid address format: %s. Using OP_RETURN.\n", addr);
    strcpy(script_hex, "6a04deadbeef"); 
}

// --- 构建 Coinbase ---
void build_coinbase(uint32_t height, int64_t value, const char *msg, char *c1, char *c2, const char *default_witness) {
    // Coinbase Part 1: Version + Input Count + PrevHash + Index
    sprintf(c1, "01000000" "01" "0000000000000000000000000000000000000000000000000000000000000000" "ffffffff");
    
    // BIP34 Height (Little Endian)
    uint8_t h_le[4];
    h_le[0]=height&0xff; h_le[1]=(height>>8)&0xff; h_le[2]=(height>>16)&0xff; h_le[3]=(height>>24)&0xff;
    
    // Tag Hex
    char tag_hex[128] = {0};
    for(int i=0; msg[i] && i<20; i++) sprintf(tag_hex + i*2, "%02x", (unsigned char)msg[i]);
    
    // ScriptSig 长度和内容: Len + HeightPush + Height + Padding + Tag
    // c1 结束于 Extranonce1 的位置
    // 格式: VarInt(TotalLen) + 03(Push) + H(3) + ...
    char script_sig[256];
    // 预留足够空间给 Extranonce (通常 8 字节 En1 + 4-8 字节 En2)
    // 这里我们构建前半部分: Push Height + Tag
    sprintf(script_sig, "20" "03%02x%02x%02x" "14%s", h_le[0], h_le[1], h_le[2], tag_hex);
    strcat(c1, script_sig);

    // Coinbase Part 2: 
    // Sequence + Output Count
    sprintf(c2, "ffffffff" "02"); 

    // Output 1: Reward
    char val_hex[17];
    sprintf(val_hex, "%016lx", value);
    uint8_t val_bin[8];
    hex2bin(val_hex, val_bin, 8);
    reverse_bytes(val_bin, 8); // LE
    char val_hex_le[17];
    bin2hex(val_bin, 8, val_hex_le);
    strcat(c2, val_hex_le);

    // Payout Script
    char script_pubkey[256];
    address_to_script(g_config.payout_addr, script_pubkey);
    int script_len = strlen(script_pubkey) / 2;
    char len_hex[3];
    sprintf(len_hex, "%02x", script_len);
    strcat(c2, len_hex);
    strcat(c2, script_pubkey);

    // Output 2: Witness Commitment (SegWit 必须)
    strcat(c2, "0000000000000000"); // 0 Value
    
    if (default_witness && strlen(default_witness) > 0) {
        // GBT 返回的 default_witness_commitment 已经是完整的 Script (含长度)
        // 但通常是 hex string。我们需要计算 VarInt 长度前缀吗？
        // getblocktemplate 返回的 default_witness_commitment 通常是 "6a24aa21a9ed..."
        // 我们需要加上 VarInt 长度
        int w_len = strlen(default_witness) / 2;
        char w_len_hex[3];
        sprintf(w_len_hex, "%02x", w_len);
        strcat(c2, w_len_hex);
        strcat(c2, default_witness);
    } else {
        // 兜底：空块承诺
        strcat(c2, "26" "6a24aa21a9ed" "0000000000000000000000000000000000000000000000000000000000000000");
    }

    strcat(c2, "00000000"); // Locktime
}

// --- Merkle Tree 计算 ---
void calculate_merkle_branch(json_t *txs, Template *tmpl) {
    size_t count = json_array_size(txs);
    tmpl->tx_count = count;
    
    size_t total_leaves = count + 1; // +1 for Coinbase
    uint8_t (*leaves)[32] = malloc(total_leaves * 32);
    tmpl->tx_hexs = malloc(count * sizeof(char*));
    
    // Transactions -> Leaves (Indicies 1..N)
    for (size_t i = 0; i < count; i++) {
        json_t *tx = json_array_get(txs, i);
        const char *txid_hex = json_string_value(json_object_get(tx, "txid"));
        const char *data_hex = json_string_value(json_object_get(tx, "data"));
        
        tmpl->tx_hexs[i] = strdup(data_hex); // 保存原始交易
        
        uint8_t bin[32];
        hex2bin(txid_hex, bin, 32);
        // RPC txid 是 Little Endian 显示，Merkle Leaves 需要 Internal Order (也是 LE)
        memcpy(leaves[i + 1], bin, 32);
    }
    
    // 计算 Index 0 (Coinbase) 的路径
    int level_count = total_leaves;
    int branch_idx = 0;
    
    while (level_count > 1) {
        // Coinbase 总是 Index 0。如果在这一层有兄弟 (Index 1)，则加入 Branch
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

// --- 变长整数编码 ---
int encode_varint(uint8_t *buf, uint64_t n) {
    if (n < 0xfd) { buf[0] = n; return 1; }
    else if (n <= 0xffff) { buf[0] = 0xfd; *(uint16_t*)(buf+1) = (uint16_t)n; return 3; }
    else if (n <= 0xffffffff) { buf[0] = 0xfe; *(uint32_t*)(buf+1) = (uint32_t)n; return 5; }
    else { buf[0] = 0xff; *(uint64_t*)(buf+1) = n; return 9; }
}

// --- 提交区块 ---
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
            printf("[SUBMIT] Node Rejected: %s\n", json_string_value(res));
        }
        json_decref(resp);
    } else {
        printf("[SUBMIT] RPC Call Failed\n");
    }
    return success;
}

// --- 重构区块 (核心逻辑) ---
int bitcoin_reconstruct_and_submit(const char *job_id, const char *full_extranonce, const char *ntime, uint32_t nonce, uint32_t version_mask) {
    pthread_mutex_lock(&g_tmpl_lock);
    
    // 校验 Job ID (简化版: 只比对最新)
    if (strcmp(job_id, g_current_tmpl.job_id) != 0) {
        pthread_mutex_unlock(&g_tmpl_lock);
        return 0; 
    }

    // 1. 重构 Coinbase (c1 + Extranonce + c2)
    char coinbase_hex[8192];
    sprintf(coinbase_hex, "%s%s%s", g_current_tmpl.coinb1, full_extranonce, g_current_tmpl.coinb2);
    
    // 2. 准备缓冲区
    size_t total_size = 80 + 2048 + 2048; // Header + Coinbase + Margin
    for(int i=0; i<g_current_tmpl.tx_count; i++) total_size += strlen(g_current_tmpl.tx_hexs[i]);
    char *block_hex = malloc(total_size * 2);
    char *p = block_hex;
    
    // 3. Header (80 bytes)
    uint8_t header[80];
    
    // Version: 如果 mask 不为 0，说明使用了 Version Rolling (ASICBoost)
    // 此时 nVersion = version_mask (Stratum 协议变种通常传递整个新 version)
    uint32_t ver = (version_mask != 0) ? version_mask : g_current_tmpl.version_int;
    *(uint32_t*)(header) = ver; // LE
    
    // PrevHash: 还原为 Internal/RPC Order
    uint8_t prev_bin[32];
    hex2bin(g_current_tmpl.prev_hash, prev_bin, 32);
    uint32_t *p32 = (uint32_t*)prev_bin;
    for(int i=0; i<8; i++) p32[i] = swap_uint32(p32[i]);
    memcpy(header+4, prev_bin, 32);
    
    // Merkle Root: 重新计算
    // Hash(Coinbase)
    uint8_t coinbase_bin[4096];
    size_t cb_len = strlen(coinbase_hex) / 2;
    hex2bin(coinbase_hex, coinbase_bin, cb_len);
    
    uint8_t current_hash[32];
    sha256_double(coinbase_bin, cb_len, current_hash);
    
    // Combine with Branches
    for (int i=0; i<g_current_tmpl.merkle_count; i++) {
        uint8_t branch_bin[32];
        hex2bin(g_current_tmpl.merkle_branch[i], branch_bin, 32);
        
        uint8_t concat[64];
        memcpy(concat, current_hash, 32);
        memcpy(concat+32, branch_bin, 32);
        sha256_double(concat, 64, current_hash);
    }
    memcpy(header+36, current_hash, 32);
    
    // Time
    uint32_t t_val = strtoul(ntime, NULL, 16);
    *(uint32_t*)(header+68) = t_val; // Assuming ntime is LE? Wait.
    // Stratum sends time as hex string. Usually Big Endian in JSON?
    // Bitaxe ntime usually needs swapping if it came as BE string.
    // Standard: header is LE. If string is "65a0b1c2", strtoul gives int.
    // Most stratum servers send BE ntime.
    // Let's swap it just in case to match header format.
    *(uint32_t*)(header+68) = swap_uint32(t_val);

    // Bits
    *(uint32_t*)(header+72) = g_current_tmpl.nbits_int; // Already parsed from RPC
    
    // Nonce
    *(uint32_t*)(header+76) = nonce; // Correctly passed from stratum.c
    
    // Write Header
    bin2hex(header, 80, p); p += 160;
    
    // 4. Tx Count (VarInt)
    uint8_t vi[9];
    int vi_len = encode_varint(vi, 1 + g_current_tmpl.tx_count);
    bin2hex(vi, vi_len, p); p += (vi_len * 2);
    
    // 5. Coinbase
    strcpy(p, coinbase_hex); p += strlen(coinbase_hex);
    
    // 6. Transactions
    for(int i=0; i<g_current_tmpl.tx_count; i++) {
        strcpy(p, g_current_tmpl.tx_hexs[i]);
        p += strlen(g_current_tmpl.tx_hexs[i]);
    }
    
    // 7. Submit
    int ret = bitcoin_submit_block(block_hex);
    
    free(block_hex);
    pthread_mutex_unlock(&g_tmpl_lock);
    return ret;
}

// --- 获取模板主逻辑 ---
void bitcoin_update_template(bool clean_jobs) {
    json_t *rules = json_array();
    json_array_append_new(rules, json_string("segwit"));
    json_t *args = json_object();
    json_object_set_new(args, "rules", rules);
    
    // 支持 SegWit 和 Version Rolling 提案
    json_array_append_new(rules, json_string("csv")); 
    
    json_t *params = json_array();
    json_array_append_new(params, args);
    
    json_t *resp = rpc_call("getblocktemplate", params);
    if(!resp || !json_object_get(resp, "result")) {
        if(resp) json_decref(resp);
        return;
    }
    json_t *res = json_object_get(resp, "result");
    
    pthread_mutex_lock(&g_tmpl_lock);
    
    bitcoin_cleanup_template(&g_current_tmpl);
    
    // Job ID
    static int job_counter = 0;
    snprintf(g_current_tmpl.job_id, 32, "%x", ++job_counter);
    g_current_tmpl.clean_jobs = clean_jobs;
    
    // Header Info
    g_current_tmpl.height = json_integer_value(json_object_get(res, "height"));
    g_current_tmpl.version_int = json_integer_value(json_object_get(res, "version"));
    sprintf(g_current_tmpl.version, "%08x", swap_uint32(g_current_tmpl.version_int));
    
    const char *bits = json_string_value(json_object_get(res, "bits"));
    strncpy(g_current_tmpl.nbits, bits, 8);
    g_current_tmpl.nbits_int = strtoul(bits, NULL, 16);
    g_current_tmpl.nbits_int = swap_uint32(g_current_tmpl.nbits_int); // RPC bits is usually BE string, but value is LE in header? 
    // Wait: RPC "bits" is "1d00ffff". Header needs 0x1d00ffff (LE: ff ff 00 1d).
    // strtoul("1d00ffff") -> 0x1d00ffff.
    // *(uint32*) = 0x1d00ffff -> Memory: ff ff 00 1d. Correct.
    // But swap_uint32 above?
    // Re-verify: Stratum expects BE Hex string for nbits? 
    // "1d00ffff" is the compact target. 
    // Let's stick to raw string copy for stratum, and int for reconstruction.
    
    g_current_tmpl.ntime_int = json_integer_value(json_object_get(res, "curtime"));
    sprintf(g_current_tmpl.ntime, "%08x", swap_uint32(g_current_tmpl.ntime_int));
    
    // PrevHash
    const char *prev = json_string_value(json_object_get(res, "previousblockhash"));
    uint8_t prev_bin[32];
    hex2bin(prev, prev_bin, 32);
    // Stratum V1 Prevhash: swap 32-bit words
    uint32_t *p32 = (uint32_t*)prev_bin;
    for(int i=0; i<8; i++) p32[i] = swap_uint32(p32[i]);
    bin2hex(prev_bin, 32, g_current_tmpl.prev_hash);
    
    // Coinbase
    int64_t coin_val = json_integer_value(json_object_get(res, "coinbasevalue"));
    const char *def_wit = json_string_value(json_object_get(res, "default_witness_commitment"));
    build_coinbase(g_current_tmpl.height, coin_val, g_config.coinbase_tag, 
                   g_current_tmpl.coinb1, g_current_tmpl.coinb2, def_wit);
    
    // Txs & Merkle
    json_t *txs = json_object_get(res, "transactions");
    calculate_merkle_branch(txs, &g_current_tmpl);
    
    stratum_broadcast_job(&g_current_tmpl);
    
    pthread_mutex_unlock(&g_tmpl_lock);
    json_decref(resp);
}
