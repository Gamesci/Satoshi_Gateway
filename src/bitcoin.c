#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <jansson.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <time.h>
#include "bitcoin.h"
#include "config.h"
#include "stratum.h"
#include "utils.h"
#include "sha256.h"

static Template g_jobs[MAX_JOB_HISTORY];
static int g_job_head = 0;
static pthread_mutex_t g_tmpl_lock = PTHREAD_MUTEX_INITIALIZER;

// --- 辅助工具函数 ---

// 32字节大端比较
static int cmp256(const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < 32; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

// 将 nbits 转为 256位 Target (Big Endian)
static void nbits_to_target(uint32_t nbits, uint8_t *target) {
    memset(target, 0, 32);
    int exponent = nbits >> 24;
    uint32_t mantissa = nbits & 0x00ffffff;
    
    if (exponent <= 3) {
        mantissa >>= 8 * (3 - exponent);
        target[31] = mantissa & 0xff;
        target[30] = (mantissa >> 8) & 0xff;
        target[29] = (mantissa >> 16) & 0xff;
    } else {
        int offset = 32 - exponent;
        if (offset < 0) offset = 0; 
        if (offset <= 29) {
            target[offset] = (mantissa >> 16) & 0xff;
            target[offset + 1] = (mantissa >> 8) & 0xff;
            target[offset + 2] = mantissa & 0xff;
        }
    }
}

// 区块备份到磁盘
void backup_block_to_disk(const char *block_hex) {
    #ifdef _WIN32
        _mkdir("backup");
    #else
        mkdir("backup", 0777);
    #endif

    char filename[128];
    snprintf(filename, sizeof(filename), "backup/block_%ld.hex", (long)time(NULL));
    
    FILE *f = fopen(filename, "w");
    if (f) {
        fprintf(f, "%s", block_hex);
        fclose(f);
        log_info("Block backup saved to %s", filename);
    } else {
        log_error("Failed to write block backup to %s", filename);
    }
}

// --- CURL 处理 ---

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
    CURL *curl; struct MemoryStruct chunk = {0}; chunk.memory = malloc(1); chunk.size = 0;
    curl = curl_easy_init(); if (!curl) { log_error("Init CURL Failed"); return NULL; }
    
    json_t *req = json_object();
    json_object_set_new(req, "jsonrpc", json_string("1.0"));
    json_object_set_new(req, "id", json_string("sgw"));
    json_object_set_new(req, "method", json_string(method));
    json_object_set_new(req, "params", params ? params : json_array());
    
    char *post_data = json_dumps(req, 0);
    struct curl_slist *headers = NULL; headers = curl_slist_append(headers, "content-type: text/plain;");
    
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
        json_error_t err; response = json_loads(chunk.memory, 0, &err);
        if (!response) log_error("JSON Parse Error: %.50s", chunk.memory);
    } else log_error("RPC Fail: %s", curl_easy_strerror(res));
    
    free(post_data); free(chunk.memory); curl_slist_free_all(headers); curl_easy_cleanup(curl); json_decref(req);
    return response;
}

int bitcoin_init() {
    for(int i=0; i<MAX_JOB_HISTORY; i++) { g_jobs[i].valid = false; g_jobs[i].tx_hexs = NULL; }
    return curl_global_init(CURL_GLOBAL_ALL);
}

void bitcoin_free_job(Template *t) {
    if (t->valid && t->tx_hexs) {
        // 修复：类型不匹配警告
        for (size_t i = 0; i < t->tx_count; i++) 
            if (t->tx_hexs[i]) free(t->tx_hexs[i]);
        free(t->tx_hexs); 
        t->tx_hexs = NULL;
    }
    t->valid = false;
}

bool bitcoin_get_latest_job(Template *out) {
    pthread_mutex_lock(&g_tmpl_lock);
    Template *curr = &g_jobs[g_job_head];
    if (!curr->valid) { pthread_mutex_unlock(&g_tmpl_lock); return false; }
    *out = *curr; 
    pthread_mutex_unlock(&g_tmpl_lock);
    return true;
}

// address_to_script defined in utils.h/utils.c

void build_coinbase(uint32_t height, int64_t value, const char *msg, char *c1, char *c2, const char *default_witness) {
    int tag_len = strlen(msg);
    if(tag_len > 60) tag_len = 60; // 强制截断保护
    
    int en1_size = 4;
    int en2_size = g_config.extranonce2_size;
    int en_total = en1_size + en2_size;
    
    int total_len = 4 + 1 + en_total + 1 + tag_len;
    if (total_len > 100) { total_len = 100; tag_len = 100 - (4 + 1 + en_total + 1); }
    
    sprintf(c1, "010000000100000000000000000000000000000000000000000000000000000000ffffffff");
    char len_hex[10]; sprintf(len_hex, "%02x", total_len); strcat(c1, len_hex);
    
    uint8_t h_le[4]; 
    h_le[0]=height&0xff; h_le[1]=(height>>8)&0xff; h_le[2]=(height>>16)&0xff; h_le[3]=(height>>24)&0xff;
    sprintf(c1 + strlen(c1), "03%02x%02x%02x", h_le[0], h_le[1], h_le[2]);
    
    sprintf(c1 + strlen(c1), "%02x", en_total); 
    
    sprintf(c2, "%02x", tag_len); 
    char tag_hex[128] = {0};
    for(int i=0; i<tag_len; i++) sprintf(tag_hex + i*2, "%02x", (unsigned char)msg[i]);
    strcat(c2, tag_hex);
    
    strcat(c2, "ffffffff02"); 
    
    char val_hex[17]; sprintf(val_hex, "%016lx", value);
    uint8_t val_bin[8]; hex2bin(val_hex, val_bin, 8); reverse_bytes(val_bin, 8);
    char val_le[17]; bin2hex(val_bin, 8, val_le); strcat(c2, val_le);

    char script_pub[256]; 
    address_to_script(g_config.payout_addr, script_pub);
    
    char sl_hex[10]; sprintf(sl_hex, "%02x", (int)strlen(script_pub)/2);
    strcat(c2, sl_hex); strcat(c2, script_pub);

    strcat(c2, "0000000000000000"); 
    if (default_witness && strlen(default_witness) > 0) {
        char w_len_hex[10]; sprintf(w_len_hex, "%02x", (int)strlen(default_witness)/2);
        strcat(c2, w_len_hex); strcat(c2, default_witness);
    } else {
        strcat(c2, "266a24aa21a9ed0000000000000000000000000000000000000000000000000000000000000000");
    }
    strcat(c2, "00000000");
}

void calculate_merkle_branch(json_t *txs, Template *tmpl) {
    size_t count = json_array_size(txs); tmpl->tx_count = count;
    size_t total = count + 1; uint8_t (*leaves)[32] = malloc(total * 32);
    tmpl->tx_hexs = malloc(count * sizeof(char*));
    
    for (size_t i = 0; i < count; i++) {
        json_t *tx = json_array_get(txs, i);
        const char *tid = json_string_value(json_object_get(tx, "txid"));
        const char *dat = json_string_value(json_object_get(tx, "data"));
        if(!tid || !dat) { tmpl->tx_hexs[i] = strdup(""); memset(leaves[i+1], 0, 32); continue; }
        
        tmpl->tx_hexs[i] = strdup(dat);
        
        // Merkle Branch LE
        hex2bin(tid, leaves[i+1], 32); 
    }
    
    int level = total; int idx = 0;
    while (level > 1) {
        if (level > 1) { char h[65]; bin2hex(leaves[1], 32, h); strcpy(tmpl->merkle_branch[idx++], h); }
        int next = 0;
        for (int i = 0; i < level; i += 2) {
            uint8_t *l = leaves[i]; uint8_t *r = (i+1 < level) ? leaves[i+1] : leaves[i];
            uint8_t buf[64]; memcpy(buf, l, 32); memcpy(buf+32, r, 32); sha256_double(buf, 64, leaves[next++]);
        }
        level = next;
    }
    tmpl->merkle_count = idx; free(leaves);
}

int encode_varint(uint8_t *buf, uint64_t n) {
    if (n < 0xfd) { buf[0] = n; return 1; } else if (n <= 0xffff) { buf[0] = 0xfd; *(uint16_t*)(buf+1) = n; return 3; }
    else if (n <= 0xffffffff) { buf[0] = 0xfe; *(uint32_t*)(buf+1) = n; return 5; } else { buf[0] = 0xff; *(uint64_t*)(buf+1) = n; return 9; }
}

int bitcoin_submit_block(const char *hex_data) {
    json_t *params = json_array(); json_array_append_new(params, json_string(hex_data));
    json_t *resp = rpc_call("submitblock", params);
    int success = 0;
    if(resp) {
        json_t *res = json_object_get(resp, "result");
        if(json_is_null(res)) { success = 1; } 
        else { log_error("Reject: %s", json_string_value(res)); }
        json_decref(resp);
    }
    return success;
}

int bitcoin_validate_and_submit(const char *job_id, const char *full_extranonce, const char *ntime, uint32_t nonce, uint32_t version_bits) {
    pthread_mutex_lock(&g_tmpl_lock);
    
    Template *job = NULL;
    for(int i=0; i<MAX_JOB_HISTORY; i++) {
        if(g_jobs[i].valid && strcmp(g_jobs[i].job_id, job_id) == 0) { job = &g_jobs[i]; break; }
    }
    if (!job) { pthread_mutex_unlock(&g_tmpl_lock); log_info("Stale: Job %s not found.", job_id); return 0; }

    // 修复：size_t 警告
    size_t sz = 80 + 4096; 
    for(size_t i=0; i<job->tx_count; i++) sz += strlen(job->tx_hexs[i]);
    
    char *block = malloc(sz * 2); 
    char *p = block;
    char coin[8192]; sprintf(coin, "%s%s%s", job->coinb1, full_extranonce, job->coinb2);
    
    uint8_t head[80];
    
    uint32_t ver = job->version_val;
    if (g_config.version_mask != 0) {
        ver = (ver & ~g_config.version_mask) | (version_bits & g_config.version_mask);
    }
    *(uint32_t*)(head) = ver; 
    
    memcpy(head+4, job->prev_hash_bin, 32);
    
    uint8_t cbin[4096]; size_t clen = strlen(coin)/2; hex2bin(coin, cbin, clen);
    uint8_t root[32]; sha256_double(cbin, clen, root);
    for (int i=0; i<job->merkle_count; i++) {
        uint8_t br[32]; hex2bin(job->merkle_branch[i], br, 32);
        uint8_t cat[64]; memcpy(cat, root, 32); memcpy(cat+32, br, 32); sha256_double(cat, 64, root);
    }
    memcpy(head+36, root, 32);
    
    uint32_t tv = strtoul(ntime, NULL, 16); *(uint32_t*)(head+68) = tv; 
    *(uint32_t*)(head+72) = job->nbits_val; 
    *(uint32_t*)(head+76) = nonce; 
    
    uint8_t h[32]; sha256_double(head, 80, h); 
    
    uint8_t h_be[32]; for(int i=0; i<32; i++) h_be[i] = h[31-i];
    char hh[65]; bin2hex(h_be, 32, hh);
    
    int result = 0; 

    if (h_be[0] == 0 && h_be[1] == 0 && h_be[2] == 0 && h_be[3] == 0) {
         result = 1;
    }

    uint8_t target[32];
    nbits_to_target(job->nbits_val, target);
    
    if (cmp256(h_be, target) <= 0) {
        log_info(">>> BLOCK FOUND! Hash: %s", hh);
        
        bin2hex(head, 80, p); p += 160;
        uint8_t vi[9]; int vl = encode_varint(vi, 1 + job->tx_count);
        bin2hex(vi, vl, p); p += vl * 2;
        strcpy(p, coin); p += strlen(coin);
        
        // 修复：size_t 警告
        for(size_t i=0; i<job->tx_count; i++) { 
            strcpy(p, job->tx_hexs[i]); 
            p += strlen(job->tx_hexs[i]); 
        }
        
        backup_block_to_disk(block);
        
        if (bitcoin_submit_block(block)) {
            result = 2;
            log_info("Block Submitted Successfully!");
        } else {
            log_error("Block Submission Rejected.");
        }
    } else if (result == 1) {
         log_info("Miner Share Accepted: %s", hh);
    }
    
    free(block); pthread_mutex_unlock(&g_tmpl_lock);
    return result;
}

void bitcoin_update_template(bool force_clean) {
    json_t *rules = json_array(); json_array_append_new(rules, json_string("segwit")); json_array_append_new(rules, json_string("csv")); 
    json_t *args = json_object(); json_object_set_new(args, "rules", rules);
    json_t *params = json_array(); json_array_append_new(params, args);
    json_t *resp = rpc_call("getblocktemplate", params);
    if(!resp) return;
    json_t *res = json_object_get(resp, "result");
    if(!res) { json_decref(resp); return; }
    
    pthread_mutex_lock(&g_tmpl_lock);
    const char *prev = json_string_value(json_object_get(res, "previousblockhash"));
    uint8_t prev_bin[32];
    if(prev) { hex2bin(prev, prev_bin, 32); reverse_bytes(prev_bin, 32); } else memset(prev_bin, 0, 32);
    
    bool clean = force_clean;
    Template *last = &g_jobs[g_job_head];
    if(last->valid && memcmp(last->prev_hash_bin, prev_bin, 32)!=0) { clean = true; log_info("New Block Detected!"); }
    
    g_job_head = (g_job_head + 1) % MAX_JOB_HISTORY;
    Template *curr = &g_jobs[g_job_head];
    bitcoin_free_job(curr);
    
    static int jid = 0; snprintf(curr->job_id, 32, "%x", ++jid);
    curr->valid = true; curr->clean_jobs = clean;
    curr->height = json_integer_value(json_object_get(res, "height"));
    
    curr->version_val = json_integer_value(json_object_get(res, "version"));
    json_t *jv = json_object_get(res, "versionHex");
    if(jv) { strncpy(curr->version_hex, json_string_value(jv), 8); curr->version_hex[8]='\0'; }
    else sprintf(curr->version_hex, "%08x", curr->version_val);
    
    memcpy(curr->prev_hash_bin, prev_bin, 32);
    uint8_t swap[32]; memcpy(swap, prev_bin, 32); swap32_buffer(swap, 32);
    bin2hex(swap, 32, curr->prev_hash_stratum);
    
    const char *bits = json_string_value(json_object_get(res, "bits"));
    if(bits) { strncpy(curr->nbits_hex, bits, 8); curr->nbits_hex[8]='\0'; } else strcpy(curr->nbits_hex, "1d00ffff");
    curr->nbits_val = strtoul(curr->nbits_hex, NULL, 16);
    
    curr->curtime_val = json_integer_value(json_object_get(res, "curtime"));
    sprintf(curr->ntime_hex, "%08x", curr->curtime_val);
    
    build_coinbase(curr->height, json_integer_value(json_object_get(res, "coinbasevalue")), g_config.coinbase_tag, curr->coinb1, curr->coinb2, json_string_value(json_object_get(res, "default_witness_commitment")));
    
    json_t *txs = json_object_get(res, "transactions");
    if(txs) calculate_merkle_branch(txs, curr); else curr->merkle_count = 0;
    
    log_info("Job %s [H:%d Tx:%d] Clean:%d", curr->job_id, curr->height, curr->tx_count, clean);
    stratum_broadcast_job(curr); // 修复：已在 stratum.h 声明
    
    pthread_mutex_unlock(&g_tmpl_lock);
    json_decref(resp);
}
