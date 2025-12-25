#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <curl/curl.h>
#include <jansson.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <time.h>
#include <errno.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>

#include "bitcoin.h"
#include "config.h"
#include "stratum.h"
#include "utils.h"
#include "sha256.h"

static Template g_jobs[MAX_JOB_HISTORY];
static int g_job_head = 0;
static pthread_mutex_t g_tmpl_lock = PTHREAD_MUTEX_INITIALIZER;

// ---------- helpers ----------
static int cmp256_be(const uint8_t a[32], const uint8_t b[32]) {
    for (int i = 0; i < 32; i++) {
        if (a[i] < b[i]) return -1;
        if (a[i] > b[i]) return 1;
    }
    return 0;
}

static void nbits_to_target_be(uint32_t nbits, uint8_t target_be[32]) {
    memset(target_be, 0, 32);
    uint32_t exp = nbits >> 24;
    uint32_t mant = nbits & 0x007fffffU; // ignore sign bit
    if (exp == 0) return;

    if (exp <= 3) {
        mant >>= 8 * (3 - exp);
        target_be[29] = (mant >> 16) & 0xff;
        target_be[30] = (mant >> 8) & 0xff;
        target_be[31] = mant & 0xff;
        return;
    }

    int idx = (int)(32 - exp);
    if (idx < 0) idx = 0;
    if (idx > 29) return;

    target_be[idx]     = (mant >> 16) & 0xff;
    target_be[idx + 1] = (mant >> 8) & 0xff;
    target_be[idx + 2] = mant & 0xff;
}

// [FIX] Ensure return is double and calculation handles large diffs
static double nbits_to_diff(uint32_t nbits) {
    int shift = (nbits >> 24) & 0xff;
    double diff = (double)0x0000ffff / (double)(nbits & 0x00ffffff);
    while (shift < 29) { diff *= 256.0; shift++; }
    while (shift > 29) { diff /= 256.0; shift--; }
    if (!isfinite(diff)) return 0.0;
    return diff;
}

static void diff1_target_be(uint8_t out[32]) {
    memset(out, 0, 32);
    out[4] = 0xff; out[5] = 0xff; out[6] = 0x00; out[7] = 0x00;
}

static void div256_u64_be(uint8_t x[32], uint64_t div) {
    if (div == 0) { memset(x, 0, 32); return; }
    __uint128_t rem = 0;
    for (int i = 0; i < 32; i++) {
        __uint128_t cur = (rem << 8) | x[i];
        x[i] = (uint8_t)(cur / div);
        rem = cur % div;
    }
}

static bool diff_to_target_be(double diff, uint8_t target_be[32]) {
    if (diff <= 0.0 || !isfinite(diff)) return false;
    uint8_t diff1[32];
    diff1_target_be(diff1);
    if (diff < 1.0) diff = 1.0;
    uint64_t diff_int = (uint64_t)diff;
    // Handle huge diffs (Testnet4/Regtest might have very low diff, causing high target)
    // But here we are converting SHARE diff to target.
    if (diff_int == 0) diff_int = 1;
    div256_u64_be(diff1, diff_int);
    memcpy(target_be, diff1, 32);
    return true;
}

static int encode_varint(uint8_t *buf, uint64_t n) {
    if (n < 0xfd) { buf[0] = (uint8_t)n; return 1; }
    if (n <= 0xffff) { buf[0] = 0xfd; put_le16(buf + 1, (uint16_t)n); return 3; }
    if (n <= 0xffffffffULL) { buf[0] = 0xfe; put_le32(buf + 1, (uint32_t)n); return 5; }
    buf[0] = 0xff; put_le64(buf + 1, (uint64_t)n); return 9;
}

static void ensure_dir_backup(void) {
#ifdef _WIN32
    _mkdir("backup");
#else
    mkdir("backup", 0777);
#endif
}

static void backup_block_to_disk(const char *block_hex) {
    ensure_dir_backup();
    char filename[128];
    snprintf(filename, sizeof(filename), "backup/block_%ld.hex", (long)time(NULL));
    FILE *f = fopen(filename, "w");
    if (!f) {
        log_error("Failed to write block backup to %s: %s", filename, strerror(errno));
        return;
    }
    fputs(block_hex, f);
    fclose(f);
    log_info("Block backup saved to %s", filename);
}

// ---------- CURL RPC ----------
struct MemoryStruct { char *memory; size_t size; };

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;
    mem->memory = ptr;
    memcpy(mem->memory + mem->size, contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

static json_t* rpc_call(const char *method, json_t *params) {
    CURL *curl = curl_easy_init();
    if (!curl) { log_error("Init CURL failed"); return NULL; }

    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;
    if (!chunk.memory) { curl_easy_cleanup(curl); return NULL; }

    json_t *req = json_object();
    json_object_set_new(req, "jsonrpc", json_string("1.0"));
    json_object_set_new(req, "id", json_string("sgw"));
    json_object_set_new(req, "method", json_string(method));
    json_object_set_new(req, "params", params ? params : json_array());

    char *post_data = json_dumps(req, JSON_COMPACT);
    if (!post_data) { json_decref(req); free(chunk.memory); curl_easy_cleanup(curl); return NULL; }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "content-type: text/plain;");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, g_config.rpc_url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
    curl_easy_setopt(curl, CURLOPT_USERNAME, g_config.rpc_user);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, g_config.rpc_pass);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    json_t *response = NULL;
    if (res == CURLE_OK && chunk.memory) {
        json_error_t err;
        response = json_loads(chunk.memory, 0, &err);
        if (!response) {
            log_error("RPC parse error or non-JSON response from %s", method);
        }
    } else {
        log_error("RPC %s connection failed: %s", method, curl_easy_strerror(res));
    }

    free(post_data);
    free(chunk.memory);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    json_decref(req);
    return response;
}

// ---------- job memory ----------
static void template_zero(Template *t) {
    memset(t, 0, sizeof(*t));
    t->valid = false;
}

int bitcoin_init(void) {
    for (int i = 0; i < MAX_JOB_HISTORY; i++) template_zero(&g_jobs[i]);
    return curl_global_init(CURL_GLOBAL_ALL);
}

void bitcoin_free_job(Template *t) {
    if (!t) return;
    if (t->merkle_branch) {
        for (size_t i = 0; i < t->merkle_count; i++) free(t->merkle_branch[i]);
        free(t->merkle_branch);
        t->merkle_branch = NULL;
    }
    t->merkle_count = 0;
    if (t->tx_hexs) {
        for (size_t i = 0; i < t->tx_count; i++) free(t->tx_hexs[i]);
        free(t->tx_hexs);
        t->tx_hexs = NULL;
    }
    if (t->txids_le) { free(t->txids_le); t->txids_le = NULL; }
    t->tx_count = 0;
    t->valid = false;
}

static bool template_deep_copy_notify(Template *dst, const Template *src) {
    if (!dst || !src) return false;
    template_zero(dst);
    *dst = *src;
    dst->merkle_branch = NULL;
    dst->tx_hexs = NULL;
    dst->txids_le = NULL;

    if (src->merkle_count > 0) {
        dst->merkle_branch = calloc(src->merkle_count, sizeof(char*));
        if (!dst->merkle_branch) return false;
        for (size_t i = 0; i < src->merkle_count; i++) {
            dst->merkle_branch[i] = strdup(src->merkle_branch[i]);
            if (!dst->merkle_branch[i]) return false;
        }
    }
    dst->tx_count = src->tx_count;
    return true;
}

bool bitcoin_get_latest_job(Template *out) {
    if (!out) return false;
    template_zero(out);
    pthread_mutex_lock(&g_tmpl_lock);
    const Template *curr = &g_jobs[g_job_head];
    if (!curr->valid) { pthread_mutex_unlock(&g_tmpl_lock); return false; }
    bool ok = template_deep_copy_notify(out, curr);
    pthread_mutex_unlock(&g_tmpl_lock);
    if (!ok) bitcoin_free_job(out);
    return ok;
}

// ---------- coinbase building ----------
static size_t write_pushdata(uint8_t *dst, size_t cap, const uint8_t *data, size_t len) {
    if (len <= 75) {
        if (cap < 1 + len) return 0;
        dst[0] = (uint8_t)len;
        memcpy(dst + 1, data, len);
        return 1 + len;
    }
    if (len <= 255) {
        if (cap < 2 + len) return 0;
        dst[0] = 0x4c; dst[1] = (uint8_t)len;
        memcpy(dst + 2, data, len);
        return 2 + len;
    }
    if (len <= 65535) {
        if (cap < 3 + len) return 0;
        dst[0] = 0x4d; put_le16(dst + 1, (uint16_t)len);
        memcpy(dst + 3, data, len);
        return 3 + len;
    }
    return 0;
}

static bool build_coinbase_variant(uint32_t height, int64_t value_sats,
                                   int variant,
                                   bool is_segwit,
                                   const char *default_witness_commitment_hex,
                                   int extranonce1_size,
                                   int extranonce2_size,
                                   char *coinb1_hex, size_t coinb1_cap,
                                   char *coinb2_hex, size_t coinb2_cap) {
    if (extranonce1_size <= 0 || extranonce2_size <= 0) return false;
    
    // --- ScriptSig Construction ---
    uint8_t scriptSig[4096];
    size_t sp = 0;

    // 1. BIP34 Height
    uint8_t h_enc[8];
    size_t h_len = 0;
    uint32_t th = height;
    do { h_enc[h_len++] = (uint8_t)(th & 0xff); th >>= 8; } while (th > 0);
    if (h_enc[h_len - 1] & 0x80) h_enc[h_len++] = 0x00;

    size_t w1 = write_pushdata(scriptSig + sp, sizeof(scriptSig) - sp, h_enc, h_len);
    if (w1 == 0) return false;
    sp += w1;

    // 2. ExtraNonce Opcode & Placeholders
    size_t en_tot = (size_t)(extranonce1_size + extranonce2_size);
    if (sizeof(scriptSig) < sp + 3 + en_tot) return false;

    if (en_tot <= 75) {
        scriptSig[sp++] = (uint8_t)en_tot;
    } else if (en_tot <= 255) {
        scriptSig[sp++] = 0x4c;
        scriptSig[sp++] = (uint8_t)en_tot;
    } else {
        scriptSig[sp++] = 0x4d;
        put_le16(scriptSig + sp, (uint16_t)en_tot);
        sp += 2;
    }

    size_t split_point_1 = sp; 
    memset(scriptSig + sp, 0, en_tot);
    sp += en_tot;
    size_t split_point_2 = sp;

    // 3. Variant Specific Padding / Tags
    // [FIX] Whatsminer 兼容性处理
    if (variant == CB_VARIANT_WHATSMINER) {
        const char *wm_pad = "SatoshiGateway/WhatsminerCompatMode/PaddingData...";
        // 增加 Padding，避免 Whatsminer 认为 Coinbase 太短
        for(int k=0; k<20; k++) {
            size_t w = write_pushdata(scriptSig + sp, sizeof(scriptSig) - sp, (uint8_t*)wm_pad, strlen(wm_pad));
            if (w) sp += w;
        }
    } 
    
    // Tag
    const char *tag = g_config.coinbase_tag;
    if (tag && tag[0]) {
        uint8_t tagbuf[64];
        size_t taglen = strlen(tag);
        if (taglen > 60) taglen = 60;
        memcpy(tagbuf, tag, taglen);
        size_t w3 = write_pushdata(scriptSig + sp, sizeof(scriptSig) - sp, tagbuf, taglen);
        if (w3 > 0) sp += w3;
    }

    // --- Coinb1 ---
    uint8_t tx_prefix[512];
    size_t tp = 0;
    put_le32(tx_prefix + tp, 1); tp += 4; // version
    tx_prefix[tp++] = 0x01; // vin count
    memset(tx_prefix + tp, 0, 32); tp += 32; // prevhash (0)
    put_le32(tx_prefix + tp, 0xffffffffU); tp += 4; // index
    tp += encode_varint(tx_prefix + tp, (uint64_t)sp); // Total ScriptSig Len

    uint8_t coinb1_bin[4096];
    if (sizeof(coinb1_bin) < tp + split_point_1) return false;

    size_t c1 = 0;
    memcpy(coinb1_bin + c1, tx_prefix, tp); c1 += tp;
    memcpy(coinb1_bin + c1, scriptSig, split_point_1); c1 += split_point_1;

    // --- Coinb2 ---
    uint8_t coinb2_bin[4096];
    size_t c2 = 0;
    memcpy(coinb2_bin + c2, scriptSig + split_point_2, sp - split_point_2); 
    c2 += (sp - split_point_2);
    put_le32(coinb2_bin + c2, 0xffffffffU); c2 += 4; // sequence

    // Outputs
    int outputs = 1;
    bool has_wit_commit = (is_segwit && default_witness_commitment_hex && default_witness_commitment_hex[0]);
    if (has_wit_commit) outputs = 2;

    coinb2_bin[c2++] = (uint8_t)outputs;

    // Output 1: Reward
    put_le64(coinb2_bin + c2, (uint64_t)value_sats); c2 += 8;
    char script_hex[256];
    if (!address_to_script_checked(g_config.payout_addr, script_hex, sizeof(script_hex))) return false;
    size_t script_len = strlen(script_hex) / 2;
    coinb2_bin[c2++] = (uint8_t)script_len;
    uint8_t script_bin[256];
    hex2bin_checked(script_hex, script_bin, script_len);
    memcpy(coinb2_bin + c2, script_bin, script_len); c2 += script_len;

    // Output 2: Witness Commitment
    if (has_wit_commit) {
        put_le64(coinb2_bin + c2, 0); c2 += 8; // value 0
        size_t wlen = strlen(default_witness_commitment_hex) / 2;
        coinb2_bin[c2++] = (uint8_t)wlen;
        uint8_t wbin[128];
        hex2bin_checked(default_witness_commitment_hex, wbin, wlen);
        memcpy(coinb2_bin + c2, wbin, wlen); c2 += wlen;
    }

    put_le32(coinb2_bin + c2, 0); c2 += 4; // locktime

    if (!bin2hex_safe(coinb1_bin, c1, coinb1_hex, coinb1_cap)) return false;
    if (!bin2hex_safe(coinb2_bin, c2, coinb2_hex, coinb2_cap)) return false;
    return true;
}

// [FIX] Correct Merkle Branch (idx^1) and use LE Hex (Bitaxe/Stratum Standard)
static bool calculate_merkle_branch_correct(const uint8_t (*txids_le)[32], size_t tx_count,
                                            char ***out_branch, size_t *out_count) {
    *out_branch = NULL; *out_count = 0;
    
    size_t level_len = 1 + tx_count; // placeholder for coinbase + txs
    if (level_len == 1) return true; // Only coinbase, no branch

    uint8_t *current_level = calloc(level_len, 32);
    if (!current_level) return false;

    // Fill level 0. Start at index 1 because index 0 (coinbase) is implicit/varying
    for (size_t i = 0; i < tx_count; i++) {
        memcpy(current_level + (i + 1) * 32, txids_le[i], 32);
    }

    char **branch = calloc(64, sizeof(char*));
    size_t b_idx = 0;

    while (level_len > 1) {
        // Since we are tracking the path for Index 0, the sibling is always at Index 1
        const uint8_t *sibling_le = (level_len > 1) ? (current_level + 32) : current_level;
        
        // [FIXED] Use LE Hex directly. Do NOT reverse to BE.
        char hex[65];
        bin2hex_safe(sibling_le, 32, hex, sizeof(hex));
        branch[b_idx++] = strdup(hex);

        // Calc next level
        size_t next_len = (level_len + 1) / 2;
        uint8_t *next_level = calloc(next_len, 32);
        
        for (size_t i = 0; i < next_len; i++) {
            const uint8_t *left = current_level + (2 * i) * 32;
            const uint8_t *right = ((2 * i + 1) < level_len) ? (current_level + (2 * i + 1) * 32) : left;
            
            uint8_t cat[64];
            memcpy(cat, left, 32);
            memcpy(cat + 32, right, 32);
            sha256d(cat, 64, next_level + i * 32);
        }
        
        free(current_level);
        current_level = next_level;
        level_len = next_len;
    }
    
    free(current_level);
    *out_branch = branch;
    *out_count = b_idx;
    return true;
}

static int bitcoin_submit_block(const char *hex_data) {
    json_t *params = json_array();
    json_array_append_new(params, json_string(hex_data));
    json_t *resp = rpc_call("submitblock", params);
    int success = 0;
    if (resp) {
        json_t *res = json_object_get(resp, "result");
        if (res && json_is_null(res)) success = 1;
        else log_error("submitblock rejected: %s", res ? json_string_value(res) : "(null)");
        json_decref(resp);
    }
    return success;
}

int bitcoin_validate_and_submit(const char *job_id,
                                const char *full_extranonce_hex,
                                const char *ntime_hex,
                                uint32_t nonce,
                                uint32_t version_bits,
                                double diff,
                                double *share_diff) {
    if (share_diff) *share_diff = 0.0;
    if (!job_id || !full_extranonce_hex || !ntime_hex) return 0;

    pthread_mutex_lock(&g_tmpl_lock);
    Template *job = NULL;
    for (int i = 0; i < MAX_JOB_HISTORY; i++) {
        if (g_jobs[i].valid && strcmp(g_jobs[i].job_id, job_id) == 0) { job = &g_jobs[i]; break; }
    }
    if (!job) { pthread_mutex_unlock(&g_tmpl_lock); return 0; }

    int valid_variant = -1;
    uint8_t root_le[32];
    uint8_t *coin_bin = NULL;
    size_t coin_bin_len = 0;
    char *coin_hex = NULL;

    for (int v = 0; v < MAX_COINBASE_VARIANTS; v++) {
        size_t hlen = strlen(job->coinb1[v]) + strlen(full_extranonce_hex) + strlen(job->coinb2[v]);
        if (hlen >= 32000) continue;
        
        char *tmp_hex = malloc(hlen + 1);
        strcpy(tmp_hex, job->coinb1[v]); 
        strcat(tmp_hex, full_extranonce_hex); 
        strcat(tmp_hex, job->coinb2[v]);
        
        size_t bin_len = hlen / 2;
        uint8_t *tmp_bin = malloc(bin_len);
        hex2bin_checked(tmp_hex, tmp_bin, bin_len);
        
        uint8_t cb_txid[32];
        sha256d(tmp_bin, bin_len, cb_txid);
        
        // Calculate Merkle Root
        uint8_t curr_root[32];
        memcpy(curr_root, cb_txid, 32);
        
        for (size_t k = 0; k < job->merkle_count; k++) {
            uint8_t sib_le[32];
            // [FIXED] Direct LE Hex -> LE Bin
            hex2bin_checked(job->merkle_branch[k], sib_le, 32);
            
            uint8_t cat[64];
            memcpy(cat, curr_root, 32);
            memcpy(cat + 32, sib_le, 32);
            sha256d(cat, 64, curr_root);
        }
        
        // Construct header
        uint8_t head[80];
        uint32_t ver = job->version_val;
        if (g_config.version_mask != 0) ver = (ver & ~g_config.version_mask) | (version_bits & g_config.version_mask);
        put_le32(head + 0, ver);
        memcpy(head + 4, job->prevhash_le, 32);
        memcpy(head + 36, curr_root, 32);
        uint32_t ntime = (uint32_t)strtoul(ntime_hex, NULL, 16);
        put_le32(head + 68, ntime);
        put_le32(head + 72, job->nbits_val);
        put_le32(head + 76, nonce);

        uint8_t hash_le[32]; sha256d(head, 80, hash_le);
        uint8_t hash_be[32]; for(int i=0;i<32;i++) hash_be[i] = hash_le[31-i];
        
        // Calculate diff
        double d = 0.0;
        for (int i = 0; i < 32; i++) d = d * 256.0 + hash_be[i];
        if (d < 1.0) d = 1.0;
        double t1 = 65535.0 * pow(2.0, 208.0);
        double s_diff = t1 / d;

        uint8_t share_target_be[32];
        diff_to_target_be(diff, share_target_be);
        
        if (cmp256_be(hash_be, share_target_be) <= 0) {
            valid_variant = v;
            memcpy(root_le, curr_root, 32);
            if (share_diff) *share_diff = s_diff;
            
            coin_hex = tmp_hex; // take ownership
            coin_bin = tmp_bin; // take ownership
            coin_bin_len = bin_len;
            break; 
        } else {
            free(tmp_hex);
            free(tmp_bin);
        }
    }

    if (valid_variant == -1) {
        pthread_mutex_unlock(&g_tmpl_lock);
        return 0; // Rejected
    }

    // Check if block
    uint8_t block_target_be[32];
    nbits_to_target_be(job->nbits_val, block_target_be);
    
    // Quick re-calc header hash for block check
    uint8_t head[80];
    uint32_t ver = job->version_val;
    if (g_config.version_mask != 0) ver = (ver & ~g_config.version_mask) | (version_bits & g_config.version_mask);
    put_le32(head + 0, ver);
    memcpy(head + 4, job->prevhash_le, 32);
    memcpy(head + 36, root_le, 32);
    put_le32(head + 68, (uint32_t)strtoul(ntime_hex, NULL, 16));
    put_le32(head + 72, job->nbits_val);
    put_le32(head + 76, nonce);
    uint8_t hash_le[32]; sha256d(head, 80, hash_le);
    uint8_t hash_be[32]; for(int i=0;i<32;i++) hash_be[i] = hash_le[31-i];

    int is_block = (cmp256_be(hash_be, block_target_be) <= 0);
    int result = 1; // Accepted share

    if (is_block) {
        log_info(">>> BLOCK FOUND! Hash via Variant %d", valid_variant);
        size_t cap = 10 * 1024 * 1024;
        char *block_hex = malloc(cap);
        if (block_hex) {
            size_t pos = 0;
            char head_hex[161]; bin2hex_safe(head, 80, head_hex, sizeof(head_hex));
            memcpy(block_hex + pos, head_hex, 160); pos += 160;

            uint8_t vi[9];
            int vl = encode_varint(vi, (uint64_t)(1 + job->tx_count));
            char vi_hex[19]; bin2hex_safe(vi, vl, vi_hex, sizeof(vi_hex));
            memcpy(block_hex + pos, vi_hex, strlen(vi_hex)); pos += strlen(vi_hex);

            if (job->has_segwit) {
                 char part[128];
                 bin2hex_safe(coin_bin, 4, part, sizeof(part));
                 memcpy(block_hex + pos, part, 8); pos += 8;
                 memcpy(block_hex + pos, "0001", 4); pos += 4;
                 
                 size_t body_len = coin_bin_len - 8;
                 char *body_hex = malloc(body_len * 2 + 1);
                 bin2hex_safe(coin_bin + 4, body_len, body_hex, body_len * 2 + 1);
                 memcpy(block_hex + pos, body_hex, strlen(body_hex)); pos += strlen(body_hex);
                 free(body_hex);

                 memcpy(block_hex + pos, "01200000000000000000000000000000000000000000000000000000000000000000", 68); pos += 68;
                 bin2hex_safe(coin_bin + coin_bin_len - 4, 4, part, sizeof(part));
                 memcpy(block_hex + pos, part, 8); pos += 8;
            } else {
                 memcpy(block_hex + pos, coin_hex, strlen(coin_hex)); pos += strlen(coin_hex);
            }

            for (size_t i = 0; i < job->tx_count; i++) {
                size_t tl = strlen(job->tx_hexs[i]);
                if (pos + tl + 1 < cap) { memcpy(block_hex + pos, job->tx_hexs[i], tl); pos += tl; }
            }
            block_hex[pos] = '\0';
            backup_block_to_disk(block_hex);
            if (bitcoin_submit_block(block_hex)) result = 2;
            free(block_hex);
        }
    }

    if (coin_hex) free(coin_hex);
    if (coin_bin) free(coin_bin);
    pthread_mutex_unlock(&g_tmpl_lock);
    return result;
}

void bitcoin_update_template(bool force_clean) {
    json_t *rules = json_array();
    json_array_append_new(rules, json_string("segwit"));
    json_array_append_new(rules, json_string("csv"));
    json_t *args = json_object();
    json_object_set_new(args, "rules", rules);
    json_t *params = json_array();
    json_array_append_new(params, args);

    json_t *resp = rpc_call("getblocktemplate", params);
    if (!resp) return;
    json_t *res = json_object_get(resp, "result");
    if (!res) { json_decref(resp); return; }

    const char *prev = json_string_value(json_object_get(res, "previousblockhash"));
    if (!prev || strlen(prev) != 64) { json_decref(resp); return; }

    uint8_t prev_be[32]; hex2bin_checked(prev, prev_be, 32);
    uint8_t prev_le[32]; memcpy(prev_le, prev_be, 32); reverse_bytes(prev_le, 32);

    Template tmp;
    template_zero(&tmp);
    tmp.valid = true;

    static int jid = 0;
    snprintf(tmp.job_id, sizeof(tmp.job_id), "%08x%08x", (uint32_t)time(NULL), (uint32_t)++jid);

    tmp.height = (uint32_t)json_integer_value(json_object_get(res, "height"));
    tmp.coinbase_value = (int64_t)json_integer_value(json_object_get(res, "coinbasevalue"));
    tmp.version_val = (uint32_t)json_integer_value(json_object_get(res, "version"));
    
    json_t *jv = json_object_get(res, "versionHex");
    if (jv && json_is_string(jv)) strncpy(tmp.version_hex, json_string_value(jv), 8);
    else snprintf(tmp.version_hex, sizeof(tmp.version_hex), "%08x", tmp.version_val);

    const char *bits = json_string_value(json_object_get(res, "bits"));
    if (bits) strncpy(tmp.nbits_hex, bits, 8);
    tmp.nbits_val = (uint32_t)strtoul(tmp.nbits_hex, NULL, 16);

    tmp.curtime_val = (uint32_t)json_integer_value(json_object_get(res, "curtime"));
    snprintf(tmp.ntime_hex, sizeof(tmp.ntime_hex), "%08x", tmp.curtime_val);
    memcpy(tmp.prevhash_le, prev_le, 32);

    uint8_t prev_stratum[32]; memcpy(prev_stratum, prev_le, 32); swap32_buffer(prev_stratum, 32);
    bin2hex_safe(prev_stratum, 32, tmp.prev_hash_stratum, sizeof(tmp.prev_hash_stratum));

    json_t *txs = json_object_get(res, "transactions");
    size_t tx_count = (txs && json_is_array(txs)) ? json_array_size(txs) : 0;
    tmp.tx_count = tx_count;

    if (tx_count > 0) {
        tmp.txids_le = calloc(tx_count, sizeof(*tmp.txids_le));
        tmp.tx_hexs = calloc(tx_count, sizeof(char*));

        for (size_t i = 0; i < tx_count; i++) {
            json_t *tx = json_array_get(txs, i);
            const char *txid = json_string_value(json_object_get(tx, "txid"));
            const char *data = json_string_value(json_object_get(tx, "data"));
            
            uint8_t bin[32];
            hex2bin_checked(txid, bin, 32);
            memcpy(tmp.txids_le[i], bin, 32); reverse_bytes(tmp.txids_le[i], 32);
            tmp.tx_hexs[i] = strdup(data);
        }
    }

    const char *dwc = NULL;
    json_t *dw = json_object_get(res, "default_witness_commitment");
    if (dw && json_is_string(dw)) dwc = json_string_value(dw);
    tmp.has_segwit = (dwc != NULL);

    for (int v = 0; v < MAX_COINBASE_VARIANTS; v++) {
        if (!build_coinbase_variant(tmp.height, tmp.coinbase_value, 
                                    v, // variant index
                                    tmp.has_segwit, dwc,
                                    4, g_config.extranonce2_size,
                                    tmp.coinb1[v], sizeof(tmp.coinb1[v]),
                                    tmp.coinb2[v], sizeof(tmp.coinb2[v]))) {
            log_error("Failed to build coinbase variant %d", v);
            bitcoin_free_job(&tmp); json_decref(resp); return;
        }
    }

    if (!calculate_merkle_branch_correct((const uint8_t (*)[32])tmp.txids_le, tmp.tx_count,
                                           &tmp.merkle_branch, &tmp.merkle_count)) {
        bitcoin_free_job(&tmp); json_decref(resp); return;
    }

    pthread_mutex_lock(&g_tmpl_lock);
    Template *last = &g_jobs[g_job_head];
    
    bool is_different = false;
    bool clean = force_clean;
    if (last->valid) {
        if (strncmp(last->prev_hash_stratum, tmp.prev_hash_stratum, 64) != 0) {
            clean = true; is_different = true;
        } else {
            if (last->curtime_val != tmp.curtime_val ||
                last->version_val != tmp.version_val ||
                last->nbits_val != tmp.nbits_val ||
                last->tx_count != tmp.tx_count) {
                is_different = true;
            } else {
                for(size_t k=0; k<tmp.merkle_count; k++) {
                    if (strcmp(last->merkle_branch[k], tmp.merkle_branch[k]) != 0) {
                        is_different = true; break;
                    }
                }
            }
        }
    } else {
        is_different = true;
    }

    if (!is_different) {
        pthread_mutex_unlock(&g_tmpl_lock);
        bitcoin_free_job(&tmp);
        json_decref(resp);
        return;
    }

    tmp.clean_jobs = clean;
    g_job_head = (g_job_head + 1) % MAX_JOB_HISTORY;
    Template *curr = &g_jobs[g_job_head];
    bitcoin_free_job(curr);
    *curr = tmp;
    template_zero(&tmp); 
    curr->valid = true;
    
    Template notify_snapshot;
    template_deep_copy_notify(&notify_snapshot, curr);
    pthread_mutex_unlock(&g_tmpl_lock);

    log_info("Job %s [H:%u Tx:%zu] Clean:%d", notify_snapshot.job_id, notify_snapshot.height,
             notify_snapshot.tx_count, notify_snapshot.clean_jobs ? 1 : 0);

    stratum_broadcast_job(&notify_snapshot);
    bitcoin_free_job(&notify_snapshot);
    json_decref(resp);
}

// [FIX] Use double for difficulty to prevent INT32_MIN overflow
void bitcoin_get_telemetry(uint32_t *height, int64_t *reward, double *difficulty) {
    pthread_mutex_lock(&g_tmpl_lock);
    const Template *curr = &g_jobs[g_job_head];
    if (curr->valid) {
        if (height) *height = curr->height;
        if (reward) *reward = curr->coinbase_value;
        if (difficulty) *difficulty = nbits_to_diff(curr->nbits_val);
    } else {
        if (height) *height = 0;
        if (reward) *reward = 0;
        if (difficulty) *difficulty = 0;
    }
    pthread_mutex_unlock(&g_tmpl_lock);
}
