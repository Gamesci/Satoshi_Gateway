#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <jansson.h>
#include <unistd.h>
#include "bitcoin.h"
#include "config.h"
#include "stratum.h"
#include "utils.h"
#include "sha256.h"

// 全局当前模板缓存
static Template g_current_tmpl = {0};
static pthread_mutex_t g_tmpl_lock = PTHREAD_MUTEX_INITIALIZER;

// --- CURL 基础部分 ---
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
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L); // 增加超时时间以应对大区块
    
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        printf("[RPC] Curl failed: %s\n", curl_easy_strerror(res));
        json_decref(req);
        free(post_data);
        free(chunk.memory);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return NULL;
    }
    
    json_error_t err;
    json_t *response = json_loads(chunk.memory, 0, &err);
    if (!response) {
        printf("[RPC] JSON Parse Error: %s\n", err.text);
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

// 释放旧模板占用的内存
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

// --- 地址与 Coinbase 构建 (复用之前的逻辑) ---
// 此处引用 utils.c 中的 address_to_script
void address_to_script(const char *addr, char *script_hex); // Forward declaration

void build_coinbase(uint32_t height, int64_t value, const char *msg, char *c1, char *c2, const char *default_witness) {
    // 1. Input: BIP34 Height
    char script_sig[256];
    sprintf(c1, "01000000" "01" "0000000000000000000000000000000000000000000000000000000000000000" "ffffffff");
    
    uint8_t h_le[4];
    h_le[0]=height&0xff; h_le[1]=(height>>8)&0xff; h_le[2]=(height>>16)&0xff; h_le[3]=(height>>24)&0xff;
    
    char tag_hex[128] = {0};
    for(int i=0; msg[i] && i<20; i++) sprintf(tag_hex + i*2, "%02x", (unsigned char)msg[i]);
    
    // ScriptSig: Push Height (3 bytes typically) + Tag
    // Format: Len(1) + Height(3) + 00 + PushTagLen + Tag
    sprintf(script_sig, "18" "03%02x%02x%02x" "062f534f4c4f2f" "10%s", h_le[0], h_le[1], h_le[2], tag_hex); // 插入 /SOLO/ 标记
    strcat(c1, script_sig);

    // 2. Output
    sprintf(c2, "ffffffff" "02"); // Seq + Count(2)

    // Output 1: Reward
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

    // Output 2: Witness Commitment
    strcat(c2, "0000000000000000"); // 0 Value
    
    // 使用 GBT 返回的 default_witness_commitment，如果没有则使用默认空块承诺
    if (default_witness && strlen(default_witness) > 0) {
        // GBT 返回的通常是整个 scriptPubKey (e.g., 6a24aa21a9ed...)
        // 我们需要计算长度并写入
        int w_len = strlen(default_witness) / 2;
        char w_len_hex[3];
        sprintf(w_len_hex, "%02x", w_len);
        strcat(c2, w_len_hex);
        strcat(c2, default_witness);
    } else {
        // Fallback (Only safe for empty blocks)
        strcat(c2, "26" "6a24aa21a9ed" "0000000000000000000000000000000000000000000000000000000000000000");
    }

    strcat(c2, "00000000"); // Locktime
}

// --- Merkle Tree 计算 (核心部分) ---
// 将 hex string 转换为 32字节 二进制，反转(RPC Little Endian -> Internal)，哈希，再转回
void calculate_merkle_branch(json_t *txs, Template *tmpl) {
    size_t count = json_array_size(txs);
    tmpl->tx_count = count;
    
    // 1. 准备叶子节点 (TxIDs)
    // 默克尔树包含: Coinbase (Index 0) + Transactions (Index 1..N)
    // RPC 返回的 txs 不包含 Coinbase，所以总叶子数 = count + 1
    size_t total_leaves = count + 1;
    
    // 分配内存存储所有叶子的 Hash (二进制)
    uint8_t (*leaves)[32] = malloc(total_leaves * 32);
    
    // Index 0 是 Coinbase，但 Stratum 协议中 Gateway 不知道具体的 Coinbase Hash
    // 因为 Coinbase 由 Miner 修改 ExtraNonce 生成。
    // 但是！计算 "Merkle Branch" 是为了给 Miner 提供路径。
    // Miner 计算 Hash(Coinbase)，然后与 Branch[0] 结合，再与 Branch[1] 结合...
    // 所以我们只需要计算 **Index 0 的路径**。
    // 在这个过程中，我们不需要知道 Index 0 的具体值，只需要知道它的 **兄弟节点** 的值。
    
    // 加载交易 Hash (Index 1 to N)
    // 同时缓存原始 Hex 用于 submitblock
    tmpl->tx_hexs = malloc(count * sizeof(char*));
    
    for (size_t i = 0; i < count; i++) {
        json_t *tx = json_array_get(txs, i);
        const char *txid_hex = json_string_value(json_object_get(tx, "txid")); // Little Endian Display
        const char *data_hex = json_string_value(json_object_get(tx, "data")); // Raw Hex
        
        // 缓存 Raw Data
        tmpl->tx_hexs[i] = strdup(data_hex);
        
        // 解析 TxID 到二进制 (Internal Order = RPC Little Endian)
        // 注意：Merkle 计算通常使用 Internal Byte Order (即 RPC 显示的顺序的反序? 不，TxID 显示通常是反转的)
        // 验证：Block Explorer 显示 TxID 是 RPC 顺序 (Little Endian)。
        // 内部 Merkle 计算使用的是 "Natural" order (即 Big Endian of the number)。
        // RPC "txid" 字段是 LE Hex。
        // 我们需要将其转为 32 byte array。
        // Stratum Branch 也是 32 byte Hex Strings。
        // 标准做法：把 RPC Hex 直接读入，不做字节序反转，直接作为二进制流进行 Double SHA256，
        // 最终发给 Stratum 的也是 RPC Hex 顺序。
        // 修正：Double SHA256 输入是二进制。
        // 让我们遵循 Stratum 协议惯例：TxID Hex -> Bin -> DoubleSHA256? No.
        // Merkle Tree 是对 TxID (32 byte) 进行 Hash。
        // RPC 给出的 TxID 已经是 Hash 结果。
        // 所以叶子节点就是这些 32 bytes。
        
        uint8_t bin[32];
        hex2bin(txid_hex, bin, 32);
        // 因为 RPC txid 是 LE 显示，而 Merkle Root 计算需要 LE 字节流。
        // 直接拷贝即可。
        memcpy(leaves[i + 1], bin, 32);
    }
    
    // 2. 计算路径
    // 我们需要 Index 0 的路径。
    // 每一层：如果当前层节点数 > 1，找到 Index 0 的兄弟 (即 Index 1)。
    // 将兄弟加入 Branch。
    // 然后计算下一层。
    
    int level_count = total_leaves;
    int branch_idx = 0;
    
    // 当这层不只一个节点时
    while (level_count > 1) {
        // 对于 Index 0，兄弟永远是 Index 1 (如果存在)
        if (level_count > 1) { // 兄弟存在 (即 Total >= 2)
            // 将兄弟 (Index 1) 加入 Branch
            // 此时 leaves[1] 就是我们要的 hash
            char hex[65];
            bin2hex(leaves[1], 32, hex);
            strcpy(tmpl->merkle_branch[branch_idx++], hex);
        } else {
            // 不可能发生，因为循环条件是 > 1。
            // 但如果 total_leaves 是奇数且 Index=Last，会自我复制，但我们只追踪 Index 0。
        }
        
        // 计算下一层 hashes
        int next_level_count = 0;
        for (int i = 0; i < level_count; i += 2) {
            uint8_t *left = leaves[i];
            uint8_t *right = (i + 1 < level_count) ? leaves[i + 1] : leaves[i]; // 奇数则复制自己
            
            // Concatenate 64 bytes
            uint8_t buffer[64];
            memcpy(buffer, left, 32);
            memcpy(buffer + 32, right, 32);
            
            // Hash (Double SHA256) -> 写入 next_level (复用 leaves 数组的前部)
            sha256_double(buffer, 64, leaves[next_level_count]);
            next_level_count++;
        }
        
        level_count = next_level_count;
    }
    
    tmpl->merkle_count = branch_idx;
    free(leaves);
}

void bitcoin_update_template(bool clean_jobs) {
    // 1. GBT Request
    json_t *rules = json_array();
    json_array_append_new(rules, json_string("segwit"));
    json_t *args = json_object();
    json_object_set_new(args, "rules", rules);
    json_t *params = json_array();
    json_array_append_new(params, args);
    
    json_t *resp = rpc_call("getblocktemplate", params);
    if(!resp || !json_object_get(resp, "result")) {
        if(resp) json_decref(resp);
        return; // GBT 失败通常意味着节点还在同步
    }
    json_t *res = json_object_get(resp, "result");
    
    pthread_mutex_lock(&g_tmpl_lock);
    
    // 清理旧数据
    bitcoin_cleanup_template(&g_current_tmpl);
    
    // 生成 Job ID
    static int job_counter = 0;
    snprintf(g_current_tmpl.job_id, 32, "%x", ++job_counter);
    g_current_tmpl.clean_jobs = clean_jobs;
    
    // 解析 Header 信息
    g_current_tmpl.height = json_integer_value(json_object_get(res, "height"));
    g_current_tmpl.version_int = json_integer_value(json_object_get(res, "version"));
    sprintf(g_current_tmpl.version, "%08x", swap_uint32(g_current_tmpl.version_int)); // Swap for Stratum
    
    // Bits
    const char *bits = json_string_value(json_object_get(res, "bits"));
    strncpy(g_current_tmpl.nbits, bits, 8);
    g_current_tmpl.nbits_int = strtoul(bits, NULL, 16); // Hex to int
    
    // Time
    g_current_tmpl.ntime_int = json_integer_value(json_object_get(res, "curtime"));
    sprintf(g_current_tmpl.ntime, "%08x", swap_uint32(g_current_tmpl.ntime_int));

    // PrevHash (RPC BE -> Stratum LE conversion)
    const char *prev = json_string_value(json_object_get(res, "previousblockhash"));
    uint8_t prev_bin[32];
    hex2bin(prev, prev_bin, 32);
    // Stratum V1 通常按照 32位 整数反转 (每4字节反转)
    uint32_t *p32 = (uint32_t*)prev_bin;
    for(int i=0; i<8; i++) p32[i] = swap_uint32(p32[i]);
    bin2hex(prev_bin, 32, g_current_tmpl.prev_hash);

    // Coinbase
    int64_t coin_val = json_integer_value(json_object_get(res, "coinbasevalue"));
    const char *def_wit = json_string_value(json_object_get(res, "default_witness_commitment"));
    build_coinbase(g_current_tmpl.height, coin_val, g_config.coinbase_tag, 
                   g_current_tmpl.coinb1, g_current_tmpl.coinb2, def_wit);
    
    // Merkle Tree & Transactions
    json_t *txs = json_object_get(res, "transactions");
    calculate_merkle_branch(txs, &g_current_tmpl);
    
    // 广播任务
    stratum_broadcast_job(&g_current_tmpl);
    
    pthread_mutex_unlock(&g_tmpl_lock);
    json_decref(resp);
}

// --- 变长整数 (VarInt) 编码辅助 ---
int encode_varint(uint8_t *buf, uint64_t n) {
    if (n < 0xfd) {
        buf[0] = n; return 1;
    } else if (n <= 0xffff) {
        buf[0] = 0xfd;
        *(uint16_t*)(buf+1) = (uint16_t)n; // 假设主机是 LE
        return 3;
    } else if (n <= 0xffffffff) {
        buf[0] = 0xfe;
        *(uint32_t*)(buf+1) = (uint32_t)n;
        return 5;
    } else {
        buf[0] = 0xff;
        *(uint64_t*)(buf+1) = n;
        return 9;
    }
}

// --- 区块重构与提交 ---
int bitcoin_reconstruct_and_submit(const char *job_id, const char *extranonce2, const char *ntime, uint32_t nonce, uint32_t version_mask) {
    pthread_mutex_lock(&g_tmpl_lock);
    
    // 简单校验 Job ID (实际应该保留历史 Job，这里简化只比对最新的)
    if (strcmp(job_id, g_current_tmpl.job_id) != 0) {
        pthread_mutex_unlock(&g_tmpl_lock);
        return 0; // Stale share
    }

    // 1. 重构 Coinbase
    // Stratum: Coinb1 + Extra1 + Extra2 + Coinb2
    // Extra1 是 "00000001" (server.c 硬编码)
    // Extra2 来自矿机
    char coinbase_hex[4096];
    sprintf(coinbase_hex, "%s%s%s%s", g_current_tmpl.coinb1, "00000001", extranonce2, g_current_tmpl.coinb2);
    
    // 2. 估算区块总大小并分配内存
    size_t total_size = 80 + 1024 + 1024; // Header + Coinbase buffer
    for(int i=0; i<g_current_tmpl.tx_count; i++) total_size += strlen(g_current_tmpl.tx_hexs[i]);
    
    char *block_hex = malloc(total_size * 2); // Safe margin
    char *p = block_hex;
    
    // 3. 构建 Header (80 bytes)
    // Version (LE)
    uint32_t ver = g_current_tmpl.version_int;
    // 应用 version mask (ASICBoost) - 这里的逻辑需要根据 nVersionRolling 调整
    // 假设矿机已经修改了 version，这里直接使用 version_int? 
    // 不，Stratum 提交中通常不包含 version，除非使用了 version rolling 扩展。
    // 如果启用了 Version Rolling，矿机提交的 params 里会有 nversion。
    // 这里简化：假设没有 rolling，或者直接用模板的 version。
    // *修正*：如果 submit 带有 version mask，需更新 ver。
    // (此处代码未接收 version 参数，暂用模板值)
    
    uint8_t buf[80];
    *(uint32_t*)(buf) = ver; // LE
    
    // PrevHash (Internal Order / RPC Order LE)
    // g_current_tmpl.prev_hash 是 Stratum Order (swapped)。我们需要还原。
    uint8_t prev_bin[32];
    hex2bin(g_current_tmpl.prev_hash, prev_bin, 32);
    uint32_t *p32 = (uint32_t*)prev_bin;
    for(int i=0; i<8; i++) p32[i] = swap_uint32(p32[i]); // Swap back to RPC LE
    memcpy(buf+4, prev_bin, 32);
    
    // Merkle Root
    // 我们必须重新计算 Merkle Root！因为 Coinbase 变了。
    // 步骤: Hash(Coinbase) -> 结合 Branch -> Root
    uint8_t coinbase_bin[2048];
    size_t cb_len = strlen(coinbase_hex) / 2;
    hex2bin(coinbase_hex, coinbase_bin, cb_len);
    
    uint8_t current_hash[32];
    sha256_double(coinbase_bin, cb_len, current_hash);
    
    for (int i=0; i<g_current_tmpl.merkle_count; i++) {
        uint8_t branch_bin[32];
        hex2bin(g_current_tmpl.merkle_branch[i], branch_bin, 32);
        
        uint8_t concat[64];
        memcpy(concat, current_hash, 32);     // Left (Current)
        memcpy(concat+32, branch_bin, 32);   // Right (Branch)
        // 注意：这是简化的。实际上通过 job_id 和 extranonce2 无法确定 coinbase 是左还是右节点？
        // 实际上 Coinbase 永远是 Index 0 (Leftmost)。所以它永远是 Left。
        sha256_double(concat, 64, current_hash);
    }
    memcpy(buf+36, current_hash, 32);
    
    // Time
    uint32_t t_val = strtoul(ntime, NULL, 16);
    *(uint32_t*)(buf+68) = swap_uint32(t_val); // ntime hex is usually BE in stratum message? 
    // Stratum "ntime" field is hex. Protocol says "32-bit integer, hex-encoded, big-endian".
    // Wait, typical Stratum sends ntime as is from block header.
    // Let's assume input ntime string is BE hex.
    
    // Bits
    *(uint32_t*)(buf+72) = swap_uint32(g_current_tmpl.nbits_int); // nbits_int parsed from RPC
    
    // Nonce
    *(uint32_t*)(buf+76) = nonce; // Native (LE on x86)
    
    // Write Header to Hex
    bin2hex(buf, 80, p); p += 160;
    
    // 4. Tx Count (VarInt)
    // Count = 1 (Coinbase) + tx_count
    uint8_t vi[9];
    int vi_len = encode_varint(vi, 1 + g_current_tmpl.tx_count);
    bin2hex(vi, vi_len, p); p += (vi_len * 2);
    
    // 5. Coinbase
    strcpy(p, coinbase_hex); p += strlen(coinbase_hex);
    
    // 6. Other Transactions
    for(int i=0; i<g_current_tmpl.tx_count; i++) {
        strcpy(p, g_current_tmpl.tx_hexs[i]);
        p += strlen(g_current_tmpl.tx_hexs[i]);
    }
    
    // Log Hex (Debug only)
    // printf("Submitting Block: %.60s...\n", block_hex);
    
    // 7. Submit
    int ret = bitcoin_submit_block(block_hex);
    
    free(block_hex);
    pthread_mutex_unlock(&g_tmpl_lock);
    return ret;
}
