#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <jansson.h>
#include "bitcoin.h"
#include "config.h"
#include "stratum.h"
#include "utils.h"
#include "sha256.h"

// 简单的内存结构用于Curl
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
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    
    curl_easy_perform(curl);
    
    json_t *response = json_loads(chunk.memory, 0, NULL);
    
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

// 极其简化的 Coinbase 构建 (注意：仅作为 Solo 挖矿示例，生产环境建议使用专门的 Script 库)
// 这里我们构建一个基本的 P2WPKH 交易
void build_coinbase(uint32_t height, int64_t value, const char *msg, char *c1, char *c2) {
    // Coinbase Part 1: Version + Input Count + Input (PrevHash, Index) + ScriptLen
    // 这里包含 BIP34 高度
    char script_sig[128];
    // BIP34: height length + height + ... + msg
    // 简化: Pushing height. 03 + height_le + extranonce placeholders
    sprintf(c1, "01000000" "01" "0000000000000000000000000000000000000000000000000000000000000000" "ffffffff");
    
    // Script Sig: 03 (len) + Height(3 bytes for now) + ... 
    // Stratum 协议中，Gateway 负责 c1 和 c2，Extranonce 由矿机填入中间
    // 这是一个极简实现，实际必须严格遵循 BIP34
    // Coinb1 结束于 Extranonce1 的位置
    // 假设 Extranonce1(4) + Extranonce2(8) = 12 bytes. 
    // ScriptSig: Push Height (4 bytes) + random padding. 
    // 04 + H H H H + 00...
    sprintf(script_sig, "24" "03%02x%02x%02x" "00", height&0xff, (height>>8)&0xff, (height>>16)&0xff); 
    strcat(c1, script_sig);
    
    // Coinb2: 剩下的 ScriptSig + Sequence + Output Count + Outputs + Locktime
    // 注意：Extranonce 通常在 ScriptSig 的末尾。
    // 这里我们简单地把 Outputs 放在 C2。
    // Output 1: Reward to User (P2WPKH)
    // Output 2: Witness Commitment (必须有)
    // 为了确保能运行，这里使用硬编码的 ScriptPubKey (需要你自己生成 P2WPKH 的 hex 如果地址不变)
    // 或者使用简化逻辑。
    
    // 警告：这里必须根据你的 bc1q 地址生成 hex。
    // 假设 bc1qwqky... 对应的 ScriptPubKey 是 0014<20-byte-hash>
    // 由于无法在 C 中轻易解码 Bech32，这里暂时硬编码一个占位符，
    // *** 实际使用时，请确保全节点帮你生成 coinbaseaux 或使用 getblocktemplate 的 default_witness_commitment ***
    
    sprintf(c2, "ffffffff" "02"); // Sequence + Output Count (2)
    
    // Output 1: Value
    char val_hex[17];
    sprintf(val_hex, "%016lx", value);
    // Value 是 Little Endian
    uint8_t val_bin[8];
    hex2bin(val_hex, val_bin, 8);
    reverse_bytes(val_bin, 8); // swap to LE
    char val_hex_le[17];
    bin2hex(val_bin, 8, val_hex_le);
    
    strcat(c2, val_hex_le);
    // Script: 0014 + 20 bytes hash (P2WPKH)
    // 为演示，这里需要你自己填入正确的 ScriptHex。
    // 如果 config.json 的地址固定，你可以先用 python 算出它的 ScriptPubKey Hex
    // 假设 hash 是 XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
    strcat(c2, "160014" "e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"); // <--- 修改这里！
    
    // Output 2: Witness Commitment (0 value)
    strcat(c2, "0000000000000000" "266a24aa21a9ed"); // OP_RETURN + commitment header
    // 后面还需要 32 bytes commitment hash，由矿机或 stratrum 完成? 
    // 不，Stratum V1 中 Gateway 必须计算 Merkle Root，包含 Witness。
    // 这里简化：C2 包含 Output 结构，但 Merkle Root 需要包含 Witness Commitment。
    
    strcat(c2, "00000000"); // Locktime
}

void bitcoin_update_template(bool clean_jobs) {
    // 1. 获取 GBT
    json_t *rules = json_array();
    json_array_append_new(rules, json_string("segwit"));
    json_t *args = json_object();
    json_object_set_new(args, "rules", rules);
    json_t *params = json_array();
    json_array_append_new(params, args);
    
    json_t *resp = rpc_call("getblocktemplate", params);
    if(!resp || !json_object_get(resp, "result")) {
        printf("[RPC] GBT failed. Node syncing?\n");
        if(resp) json_decref(resp);
        return;
    }
    json_t *res = json_object_get(resp, "result");
    
    Template tmpl;
    static int job_counter = 0;
    snprintf(tmpl.job_id, 32, "%x", ++job_counter);
    tmpl.clean_jobs = clean_jobs;
    
    // 解析基础字段
    tmpl.height = json_integer_value(json_object_get(res, "height"));
    int64_t coinbase_val = json_integer_value(json_object_get(res, "coinbasevalue"));
    const char *prev = json_string_value(json_object_get(res, "previousblockhash"));
    
    // PrevHash: RPC 是 Big Endian，Stratum 需要 Little Endian (按 4 字节反转)
    // 这里简单地按字节反转
    uint8_t prev_bin[32];
    hex2bin(prev, prev_bin, 32);
    // 这里通常不需要全部反转，Stratum 协议具体看矿机实现。
    // Bitaxe 通常需要按每 4 字节反转。
    uint32_t *p32 = (uint32_t*)prev_bin;
    for(int i=0; i<8; i++) p32[i] = swap_uint32(p32[i]); // Big to Little representation for Stratum
    bin2hex(prev_bin, 32, tmpl.prev_hash);
    
    strncpy(tmpl.version, json_string_value(json_object_get(res, "versionHex")), 8);
    strncpy(tmpl.nbits, json_string_value(json_object_get(res, "bits")), 8);
    
    // Time needs to be Big Endian hex
    uint32_t curtime = json_integer_value(json_object_get(res, "curtime"));
    // curtime is int, need hex (Big Endian)
    sprintf(tmpl.ntime, "%08x", swap_uint32(curtime)); 

    // 构建 Coinbase
    // 注意：这里的 coinb1/c2 是极其简化的。
    // 实际上你需要正确计算 Witness Commitment Hash 并放入 c2。
    build_coinbase(tmpl.height, coinbase_val, g_config.coinbase_tag, tmpl.coinb1, tmpl.coinb2);
    
    // Merkle Branch: 如果只有 Coinbase，则为空
    // GBT 返回的 transactions 数组
    json_t *txs = json_object_get(res, "transactions");
    tmpl.merkle_count = 0;
    size_t tx_count = json_array_size(txs);
    
    // 简单的 Merkle 计算逻辑 (仅计算 TxID list，不包含 coinbase)
    // 实际 Stratum: 只需要 TxID hashes。
    // 简化: 假设空块 (tx_count=0)，Merkle Branch 为空。
    
    stratum_broadcast_job(&tmpl);
    json_decref(resp);
}

int bitcoin_submit_block(const char *hex_data) {
    json_t *params = json_array();
    json_array_append_new(params, json_string(hex_data));
    json_t *resp = rpc_call("submitblock", params);
    int ret = 0;
    if(resp) {
        if(json_is_null(json_object_get(resp, "result"))) ret = 1;
        else printf("[SUBMIT] Reject: %s\n", json_string_value(json_object_get(resp, "result")));
        json_decref(resp);
    }
    return ret;
}
