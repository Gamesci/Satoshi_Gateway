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

// --- 任务历史环形缓冲 ---
static Template g_jobs[MAX_JOB_HISTORY];
static int g_job_head = 0; // 指向当前最新任务
static pthread_mutex_t g_tmpl_lock = PTHREAD_MUTEX_INITIALIZER;

// 前置声明
void address_to_script(const char *addr, char *script_hex);

// --- CURL 辅助 ---
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
    // 初始化任务槽
    for(int i=0; i<MAX_JOB_HISTORY; i++) {
        g_jobs[i].valid = false;
        g_jobs[i].tx_hexs = NULL;
        g_jobs[i].tx_count = 0;
    }
    return curl_global_init(CURL_GLOBAL_ALL);
}

void bitcoin_free_job(Template *t) {
    if (t->valid && t->tx_hexs) {
        for (int i = 0; i < t->tx_count; i++) {
            if (t->tx_hexs[i]) free(t->tx_hexs[i]);
        }
        free(t->tx_hexs);
        t->tx_hexs = NULL;
    }
    t->valid = false;
    t->tx_count = 0;
}

// 获取最新任务副本（线程安全）
bool bitcoin_get_latest_job(Template *out) {
    pthread_mutex_lock(&g_tmpl_lock);
    Template *curr = &g_jobs[g_job_head];
    
    if (!curr->valid) {
        pthread_mutex_unlock(&g_tmpl_lock);
        return false;
    }
    
    *out = *curr; // 结构体拷贝
    // 注意：tx_hexs 只是浅拷贝指针，但在 Stratum 发送任务时不需要用到 tx_hexs 的内容
    // 只要不去释放它就是安全的。
    
    pthread_mutex_unlock(&g_tmpl_lock);
    return true;
}

// --- 核心工具函数 ---

void build_coinbase(uint32_t height, int64_t value, const char *msg, char *c1, char *c2, const char *default_witness) {
    sprintf(c1, "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff");
    uint8_t h_le[4];
    h_le[0]=height&0xff; h_le[1]=(height>>8)&0xff; h_le[2]=(height>>16)&0xff; h_le[3]=(height>>24)&0xff;
    
    char tag_hex[128] = {0};
    for(int i=0; msg[i] && i<20; i++) sprintf(tag_hex + i*2, "%02x", (unsigned char)msg[i]);
    
    char script_sig[256];
    sprintf(script_sig, "2003%02x%02x%02x14%s", h_le[0], h_le[1], h_le[2], tag_hex);
    strcat(c1, script_sig);

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
            // 这里会打印具体的错误原因 (high-hash, bad-txns等)
            log_error("Submit Block Rejected: %s", json_string_value(res));
        }
        json_decref(resp);
    } else {
        log_error("Submit Block Failed (RPC error)");
    }
    return success;
}

// --- 验证 Share 的核心逻辑 (支持历史任务查找) ---
int bitcoin_validate_and_submit(const char *job_id, const char *full_extranonce, const char *ntime, uint32_t nonce, uint32_t version_mask) {
    pthread_mutex_lock(&g_tmpl_lock);
    
    // 1. 在历史记录中查找 Job
    Template *target_job = NULL;
    for(int i=0; i<MAX_JOB_HISTORY; i++) {
        if(g_jobs[i].valid && strcmp(g_jobs[i].job_id, job_id) == 0) {
            target_job = &g_jobs[i];
            break;
        }
    }
    
    if (!target_job) {
        pthread_mutex_unlock(&g_tmpl_lock);
        log_info("Stale Share: Job %s not found in history.", job_id);
        return 0; // 无效任务
    }

    // 2. 重构 Coinbase
    char coinbase_hex[8192];
    sprintf(coinbase_hex, "%s%s%s", target_job->coinb1, full_extranonce, target_job->coinb2);
    
    // 3. 准备 Block 缓冲区
    size_t total_size = 80 + 4096; 
    for(int i=0; i<target_job->tx_count; i++) total_size += strlen(target_job->tx_hexs[i]);
    char *block_hex = malloc(total_size * 2);
    char *p = block_hex;
    
    // 4. 重构 Block Header
    uint8_t header[80];
    
    // Version (LE)
    uint32_t ver = (version_mask != 0) ? version_mask : target_job->version_val;
    *(uint32_t*)(header) = ver; 
    
    // PrevHash (LE)
    // 直接使用内部存储的 BIN，已经是 Little Endian
    memcpy(header+4, target_job->prev_hash_bin, 32);
    
    // Merkle Root calculation
    uint8_t coinbase_bin[4096];
    size_t cb_len = strlen(coinbase_hex) / 2;
    hex2bin(coinbase_hex, coinbase_bin, cb_len);
    
    uint8_t current_hash[32];
    sha256_double(coinbase_bin, cb_len, current_hash);
    
    for (int i=0; i<target_job->merkle_count; i++) {
        uint8_t branch_bin[32];
        hex2bin(target_job->merkle_branch[i], branch_bin, 32);
        uint8_t concat[64];
        memcpy(concat, current_hash, 32);
        memcpy(concat+32, branch_bin, 32);
        sha256_double(concat, 64, current_hash);
    }
    memcpy(header+36, current_hash, 32);
    
    // Time & Bits & Nonce (LE)
    uint32_t t_val = strtoul(ntime, NULL, 16);
    *(uint32_t*)(header+68) = t_val; 
    *(uint32_t*)(header+72) = target_job->nbits_val;
    *(uint32_t*)(header+76) = nonce; 
    
    // 5. 本地 Hash 检查 (防止垃圾提交)
    uint8_t block_hash[32];
    sha256_double(header, 80, block_hash);
    reverse_bytes(block_hash, 32); // 转为 BE 用于打印和观察
    char hash_hex[65];
    bin2hex(block_hash, 32, hash_hex);
    
    // 简单检查前导零，Bitaxe 算力低，通常不会满足全网难度
    // 但为了逻辑完整，如果发现极低 Hash，则提交
    int zeros = 0;
    while(hash_hex[zeros] == '0') zeros++;
    
    int result = 1; // 默认视为低难度有效 Share
    
    // 如果 Hash 足够低 (例如前 12 位都是 0)，尝试提交给网络
    if (zeros >= 12) {
        log_info("High Diff Share found! Hash: %s", hash_hex);
        
        // 构建完整 Block
        bin2hex(header, 80, p); p += 160;
        uint8_t vi[9]; int vi_len = encode_varint(vi, 1 + target_job->tx_count);
        bin2hex(vi, vi_len, p); p += (vi_len * 2);
        strcpy(p, coinbase_hex); p += strlen(coinbase_hex);
        for(int i=0; i<target_job->tx_count; i++) {
            strcpy(p, target_job->tx_hexs[i]);
            p += strlen(target_job->tx_hexs[i]);
        }
        
        if (bitcoin_submit_block(block_hex)) {
            result = 2; // Block Found!
        }
    }
    
    free(block_hex);
    pthread_mutex_unlock(&g_tmpl_lock);
    return result;
}

// -------------------------------------------------------------------
// 核心逻辑: GBT 解析与多任务管理
// -------------------------------------------------------------------
void bitcoin_update_template(bool force_clean) {
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
    
    pthread_mutex_lock(&g_tmpl_lock);
    
    // --- 判断是否需要 Clean Jobs ---
    const char *new_prev = json_string_value(json_object_get(res, "previousblockhash"));
    
    bool clean_jobs = force_clean;
    Template *last_job = &g_jobs[g_job_head];
    
    // 将 RPC 的 BE Hex 转为 LE Bin 以便比较
    uint8_t new_prev_bin[32];
    if (new_prev) {
        hex2bin(new_prev, new_prev_bin, 32);
        reverse_bytes(new_prev_bin, 32);
    } else {
        memset(new_prev_bin, 0, 32);
    }
    
    // 如果上一个任务有效，且 PrevHash 变了，说明链高度变了，必须强制 Clean
    if (last_job->valid) {
        if (memcmp(last_job->prev_hash_bin, new_prev_bin, 32) != 0) {
            clean_jobs = true; 
            log_info("New Block Detected! Forcing Clean Jobs.");
        }
    }

    // --- 移动指针，使用新槽位 ---
    g_job_head = (g_job_head + 1) % MAX_JOB_HISTORY;
    Template *curr = &g_jobs[g_job_head];
    
    // 释放覆盖掉的旧任务内存
    bitcoin_free_job(curr);
    
    static int job_counter = 0;
    snprintf(curr->job_id, 32, "%x", ++job_counter);
    curr->valid = true;
    curr->clean_jobs = clean_jobs;
    
    // --- 填充数据 ---
    curr->height = json_integer_value(json_object_get(res, "height"));
    
    // 1. Version
    curr->version_val = json_integer_value(json_object_get(res, "version"));
    json_t *j_ver = json_object_get(res, "versionHex");
    if(j_ver) strncpy(curr->version_hex, json_string_value(j_ver), 8);
    else sprintf(curr->version_hex, "%08x", curr->version_val);
    
    // 2. PrevHash (保存 LE Bin 和 Stratum Hex)
    memcpy(curr->prev_hash_bin, new_prev_bin, 32);
    
    uint8_t swap_buf[32];
    memcpy(swap_buf, curr->prev_hash_bin, 32);
    swap32_buffer(swap_buf, 32); // 4字节字反转
    bin2hex(swap_buf, 32, curr->prev_hash_stratum);
    
    // 3. Bits
    const char *bits = json_string_value(json_object_get(res, "bits"));
    if(bits) strncpy(curr->nbits_hex, bits, 8);
    else strcpy(curr->nbits_hex, "1d00ffff");
    curr->nbits_val = strtoul(curr->nbits_hex, NULL, 16);
    
    // 4. Time
    curr->curtime_val = json_integer_value(json_object_get(res, "curtime"));
    sprintf(curr->ntime_hex, "%08x", curr->curtime_val);
    
    // 5. Coinbase
    int64_t coin_val = json_integer_value(json_object_get(res, "coinbasevalue"));
    const char *def_wit = json_string_value(json_object_get(res, "default_witness_commitment"));
    build_coinbase(curr->height, coin_val, g_config.coinbase_tag, 
                   curr->coinb1, curr->coinb2, def_wit);
    
    // 6. Merkle
    json_t *txs = json_object_get(res, "transactions");
    if(txs) calculate_merkle_branch(txs, curr);
    else curr->merkle_count = 0;
    
    log_info("Job %s: H=%d Txs=%d Clean=%d Ver=%s Time=%s", 
             curr->job_id, curr->height, curr->tx_count, clean_jobs,
             curr->version_hex, curr->ntime_hex);
    
    stratum_broadcast_job(curr);
    
    pthread_mutex_unlock(&g_tmpl_lock);
    json_decref(resp);
}
