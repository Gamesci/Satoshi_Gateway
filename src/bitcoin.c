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
    // Bitcoin "compact" format -> 256-bit target (big-endian)
    memset(target_be, 0, 32);
    uint32_t exp = nbits >> 24;
    uint32_t mant = nbits & 0x007fffffU; // ignore sign bit
    if (exp == 0) return;

    // target = mantissa * 2^(8*(exp-3))
    // mantissa is 3 bytes
    if (exp <= 3) {
        mant >>= 8 * (3 - exp);
        // place at end (big-endian)
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

// diff1 target (Bitcoin) = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
static void diff1_target_be(uint8_t out[32]) {
    memset(out, 0, 32);
    out[4] = 0x00;
    out[5] = 0x00;
    out[6] = 0x00;
    out[7] = 0x00;
    out[8] = 0xff;
    out[9] = 0xff;
    // Wait: correct diff1 target has 0x00000000FFFF0000 at bytes 4..7 and 8..?
    // Let's set exactly:
    // 00000000 ffff0000 00000000 ...
    memset(out, 0, 32);
    out[4] = 0x00;
    out[5] = 0x00;
    out[6] = 0x00;
    out[7] = 0x00;
    out[8] = 0xff;
    out[9] = 0xff;
    out[10] = 0x00;
    out[11] = 0x00;
    // remaining already 0
}

// Integer division of 256-bit big-endian by uint32 divisor (div>0)
static void div256_u32_be(uint8_t x[32], uint32_t div) {
    uint64_t rem = 0;
    for (int i = 0; i < 32; i++) {
        uint64_t cur = (rem << 8) | x[i];
        x[i] = (uint8_t)(cur / div);
        rem = cur % div;
    }
}

static bool diff_to_target_be(double diff, uint8_t target_be[32]) {
    if (!(diff > 0.0)) return false;
    // Avoid float heavy math: clamp to reasonable range and approximate divisor by uint32.
    // This is still deterministic for integer diffs (your vardiff uses powers of two).
    // For non-integer diff: use rounded divisor.
    double d = diff;
    if (d < 1.0) d = 1.0;

    // Convert to uint32 divisor (rounded). This keeps correct for typical pool diffs (integer).
    uint32_t div = (uint32_t)(d + 0.5);
    if (div == 0) div = 1;

    diff1_target_be(target_be);
    div256_u32_be(target_be, div);
    return true;
}

static bool is_hex_len(const char *s, size_t expect_len) {
    if (!s) return false;
    if (strlen(s) != expect_len) return false;
    for (size_t i = 0; i < expect_len; i++) {
        char c = s[i];
        if (!((c >= '0' && c <= '9') ||
              (c >= 'a' && c <= 'f') ||
              (c >= 'A' && c <= 'F'))) return false;
    }
    return true;
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
    if (!curl) {
        log_error("Init CURL failed");
        return NULL;
    }

    struct MemoryStruct chunk;
    chunk.memory = malloc(1);
    chunk.size = 0;
    if (!chunk.memory) {
        curl_easy_cleanup(curl);
        return NULL;
    }

    json_t *req = json_object();
    json_object_set_new(req, "jsonrpc", json_string("1.0"));
    json_object_set_new(req, "id", json_string("sgw"));
    json_object_set_new(req, "method", json_string(method));
    json_object_set_new(req, "params", params ? params : json_array());

    char *post_data = json_dumps(req, JSON_COMPACT);
    if (!post_data) {
        json_decref(req);
        free(chunk.memory);
        curl_easy_cleanup(curl);
        return NULL;
    }

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
    if (res == CURLE_OK && http_code == 200) {
        json_error_t err;
        response = json_loads(chunk.memory, 0, &err);
        if (!response) {
            log_error("RPC JSON parse error: %.200s", chunk.memory);
        } else {
            json_t *errf = json_object_get(response, "error");
            if (errf && !json_is_null(errf)) {
                char *es = json_dumps(errf, JSON_COMPACT);
                log_error("RPC error for %s: %s", method, es ? es : "(unprintable)");
                free(es);
                json_decref(response);
                response = NULL;
            }
        }
    } else {
        log_error("RPC %s failed: %s (HTTP %ld)", method, curl_easy_strerror(res), http_code);
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

    if (t->txids_le) {
        free(t->txids_le);
        t->txids_le = NULL;
    }
    t->tx_count = 0;
    t->valid = false;
}

static bool template_deep_copy_notify(Template *dst, const Template *src) {
    // copy only fields needed for notify + minimal metadata
    *dst = *src;

    // Deep copy merkle branch
    dst->merkle_branch = NULL;
    if (src->merkle_count > 0) {
        dst->merkle_branch = calloc(src->merkle_count, sizeof(char*));
        if (!dst->merkle_branch) return false;
        for (size_t i = 0; i < src->merkle_count; i++) {
            dst->merkle_branch[i] = strdup(src->merkle_branch[i]);
            if (!dst->merkle_branch[i]) return false;
        }
    }
    // For notify snapshot we do NOT copy tx_hexs/txids_le (not needed)
    dst->tx_hexs = NULL;
    dst->txids_le = NULL;
    dst->tx_count = 0;
    return true;
}

bool bitcoin_get_latest_job(Template *out) {
    if (!out) return false;
    template_zero(out);

    pthread_mutex_lock(&g_tmpl_lock);
    const Template *curr = &g_jobs[g_job_head];
    if (!curr->valid) {
        pthread_mutex_unlock(&g_tmpl_lock);
        return false;
    }
    bool ok = template_deep_copy_notify(out, curr);
    pthread_mutex_unlock(&g_tmpl_lock);
    if (!ok) bitcoin_free_job(out);
    return ok;
}

// ---------- coinbase building (binary -> hex coinb1/coinb2) ----------
static size_t write_pushdata(uint8_t *dst, size_t cap, const uint8_t *data, size_t len) {
    if (len <= 75) {
        if (cap < 1 + len) return 0;
        dst[0] = (uint8_t)len;
        memcpy(dst + 1, data, len);
        return 1 + len;
    }
    if (len <= 255) {
        if (cap < 2 + len) return 0;
        dst[0] = 0x4c; // OP_PUSHDATA1
        dst[1] = (uint8_t)len;
        memcpy(dst + 2, data, len);
        return 2 + len;
    }
    if (len <= 65535) {
        if (cap < 3 + len) return 0;
        dst[0] = 0x4d; // OP_PUSHDATA2
        put_le16(dst + 1, (uint16_t)len);
        memcpy(dst + 3, data, len);
        return 3 + len;
    }
    return 0;
}

static bool build_coinbase_hex(uint32_t height, int64_t value_sats,
                               const char *tag,
                               const char *default_witness_commitment_hex,
                               int extranonce1_size,
                               int extranonce2_size,
                               char *coinb1_hex, size_t coinb1_cap,
                               char *coinb2_hex, size_t coinb2_cap) {
    // Build coinbase tx:
    // version(4) + marker/flag(optional) not used here; we construct a legacy tx with optional witness commitment output
    // input count=1
    // prevout = 32*00 + 0xffffffff
    // scriptSig = push(BIP34 height) + push(extranonce placeholder) + push(tag)
    // sequence = 0xffffffff
    // outputs: (1 or 2) including witness commitment OP_RETURN if provided by GBT
    // locktime = 0

    if (extranonce1_size <= 0 || extranonce2_size <= 0) return false;
    if (extranonce1_size + extranonce2_size > 64) return false;

    uint8_t scriptSig[256];
    size_t sp = 0;

    // BIP34 height encoding: minimal little-endian with sign bit rule
    uint8_t h_enc[8];
    size_t h_len = 0;
    uint32_t th = height;
    do {
        h_enc[h_len++] = (uint8_t)(th & 0xff);
        th >>= 8;
    } while (th > 0);
    if (h_enc[h_len - 1] & 0x80) h_enc[h_len++] = 0x00;

    sp += write_pushdata(scriptSig + sp, sizeof(scriptSig) - sp, h_enc, h_len);
    if (sp == 0) return false;

    // Extranonce placeholder bytes (en1+en2) will be split between coinb1/coinb2:
    // We put a push of total extranonce bytes, but only place EN1 in coinb1 and EN2 will be inserted by miner after coinb1.
    uint8_t en_placeholder[64];
    memset(en_placeholder, 0, (size_t)(extranonce1_size + extranonce2_size));
    size_t en_tot = (size_t)(extranonce1_size + extranonce2_size);
    size_t w = write_pushdata(scriptSig + sp, sizeof(scriptSig) - sp, en_placeholder, en_tot);
    if (w == 0) return false;
    // We will split inside this push: first extranonce1_size bytes in coinb1,
    // remaining extranonce2_size bytes belong to miner insertion -> so we cut coinb1/coinb2 around it.
    // To do that, we need to know where the pushed data begins.
    size_t en_push_hdr = 0;
    if (en_tot <= 75) en_push_hdr = 1;
    else if (en_tot <= 255) en_push_hdr = 2;
    else en_push_hdr = 3;

    size_t en_data_offset_in_script = sp + en_push_hdr; // start of placeholder bytes
    sp += w;

    // Pool tag (optional, truncated)
    uint8_t tagbuf[64];
    size_t taglen = 0;
    if (tag && tag[0]) {
        taglen = strlen(tag);
        if (taglen > 60) taglen = 60;
        memcpy(tagbuf, tag, taglen);
        size_t w2 = write_pushdata(scriptSig + sp, sizeof(scriptSig) - sp, tagbuf, taglen);
        if (w2 == 0) return false;
        sp += w2;
    }

    // Now build tx bytes up to just before extranonce2 insertion point.
    // coinb1 = tx_prefix + scriptSig bytes up to EN2 start
    // coinb2 = remaining scriptSig bytes after EN2 + sequence + outputs + locktime

    // tx fixed parts
    uint8_t tx_prefix[512];
    size_t tp = 0;

    // version
    put_le32(tx_prefix + tp, 1); tp += 4;

    // input count (1)
    tx_prefix[tp++] = 0x01;

    // prevout hash (32*0) + index (0xffffffff)
    memset(tx_prefix + tp, 0, 32); tp += 32;
    put_le32(tx_prefix + tp, 0xffffffffU); tp += 4;

    // scriptSig length (varint, sp bytes)
    if (sp < 0xfd) {
        tx_prefix[tp++] = (uint8_t)sp;
    } else {
        return false; // scriptSig too big for our constraints
    }

    // Now we must split scriptSig into:
    // partA: scriptSig[0 .. en_data_offset_in_script + extranonce1_size)
    // miner inserts extranonce2_size bytes
    // partB: rest of scriptSig after (en_data_offset_in_script + extranonce1_size + extranonce2_size)

    size_t en1_end = en_data_offset_in_script + (size_t)extranonce1_size;
    size_t en2_end = en1_end + (size_t)extranonce2_size;
    if (en2_end > sp) return false;

    // Compose coinb1 bytes
    uint8_t coinb1_bin[2048];
    size_t c1 = 0;
    if (sizeof(coinb1_bin) < tp + en1_end) return false;
    memcpy(coinb1_bin + c1, tx_prefix, tp); c1 += tp;
    memcpy(coinb1_bin + c1, scriptSig, en1_end); c1 += en1_end;

    // coinb2 bytes begin with remaining scriptSig after EN2
    uint8_t coinb2_bin[4096];
    size_t c2 = 0;
    memcpy(coinb2_bin + c2, scriptSig + en2_end, sp - en2_end); c2 += (sp - en2_end);

    // sequence
    put_le32(coinb2_bin + c2, 0xffffffffU); c2 += 4;

    // outputs count
    int outputs = 1;
    bool has_wit_commit = (default_witness_commitment_hex && strlen(default_witness_commitment_hex) > 0);
    if (has_wit_commit) outputs = 2;

    coinb2_bin[c2++] = (uint8_t)outputs;

    // output 0: value + scriptPubKey(payout)
    put_le64(coinb2_bin + c2, (uint64_t)value_sats); c2 += 8;

    char script_hex[256];
    if (!address_to_script_checked(g_config.payout_addr, script_hex, sizeof(script_hex))) return false;
    size_t script_len = strlen(script_hex) / 2;
    if (script_len > 252) return false;

    coinb2_bin[c2++] = (uint8_t)script_len;

    uint8_t script_bin[256];
    if (!hex2bin_checked(script_hex, script_bin, script_len)) return false;
    memcpy(coinb2_bin + c2, script_bin, script_len); c2 += script_len;

    // optional witness commitment output (OP_RETURN with commitment script provided by GBT)
    if (has_wit_commit) {
        // value = 0
        put_le64(coinb2_bin + c2, 0); c2 += 8;

        size_t wlen = strlen(default_witness_commitment_hex) / 2;
        if (wlen < 1 || wlen > 80) return false;
        coinb2_bin[c2++] = (uint8_t)wlen;

        uint8_t wbin[128];
        if (!hex2bin_checked(default_witness_commitment_hex, wbin, wlen)) return false;
        memcpy(coinb2_bin + c2, wbin, wlen); c2 += wlen;
    }

    // locktime
    put_le32(coinb2_bin + c2, 0); c2 += 4;

    // Finally convert to hex
    if (!bin2hex_safe(coinb1_bin, c1, coinb1_hex, coinb1_cap)) return false;
    if (!bin2hex_safe(coinb2_bin, c2, coinb2_hex, coinb2_cap)) return false;
    return true;
}

// ---------- merkle branch generation ----------
// We store txids (non-coinbase) as LE bytes.
// For stratum, merkle_branch is list of siblings (LE hex) along coinbase path.
static bool calculate_merkle_branch_from_txids(const uint8_t (*txids_le)[32], size_t tx_count,
                                               char ***out_branch, size_t *out_count) {
    *out_branch = NULL;
    *out_count = 0;

    // Total leaves = 1 coinbase + tx_count
    size_t total = 1 + tx_count;
    if (total == 1) return true;

    // We'll build levels of hashes (LE bytes). coinbase leaf is unknown at template time,
    // but siblings for coinbase path depend only on other txids and tree structure:
    // At each level, sibling of position 0 is position 1 hash of that level.
    // However, when tx_count == 0, no siblings.

    // Level0 nodes: [COINBASE_PLACEHOLDER, txid1, txid2, ...]
    uint8_t *level = calloc(total, 32);
    if (!level) return false;

    // Set coinbase placeholder to 0x00..00 (doesn't affect sibling extraction)
    // Fill other txids
    for (size_t i = 0; i < tx_count; i++) {
        memcpy(level + (i + 1) * 32, txids_le[i], 32);
    }

    // Branch will have up to ceil(log2(total)) entries
    char **branch = calloc(64, sizeof(char*));
    if (!branch) { free(level); return false; }
    size_t bcount = 0;

    size_t level_count = total;
    uint8_t *next = NULL;

    while (level_count > 1) {
        // sibling for coinbase path at this level:
        // if level_count>1, sibling index for 0 is 1, but if missing, it's 0 itself.
        const uint8_t *sib = (level_count > 1) ? (level + 1 * 32) : (level + 0);
        // In case total==1 this loop doesn't run.
        char hex[65];
        if (!bin2hex_safe(sib, 32, hex, sizeof(hex))) { /* impossible */ }
        branch[bcount] = strdup(hex);
        if (!branch[bcount]) { free(level); for (size_t k=0;k<bcount;k++) free(branch[k]); free(branch); return false; }
        bcount++;

        // Build next level
        size_t pairs = (level_count + 1) / 2;
        next = calloc(pairs, 32);
        if (!next) { free(level); for (size_t k=0;k<bcount;k++) free(branch[k]); free(branch); return false; }

        for (size_t i = 0; i < pairs; i++) {
            const uint8_t *L = level + (2 * i) * 32;
            const uint8_t *R = (2 * i + 1 < level_count) ? (level + (2 * i + 1) * 32) : L;

            uint8_t buf[64];
            memcpy(buf, L, 32);
            memcpy(buf + 32, R, 32);
            sha256d(buf, 64, next + i * 32);
        }

        free(level);
        level = next;
        next = NULL;
        level_count = pairs;

        // safety bound
        if (bcount >= 64) break;
    }

    free(level);

    // shrink
    char **final = calloc(bcount, sizeof(char*));
    if (!final && bcount > 0) { for (size_t k=0;k<bcount;k++) free(branch[k]); free(branch); return false; }
    for (size_t i = 0; i < bcount; i++) final[i] = branch[i];
    free(branch);

    *out_branch = final;
    *out_count = bcount;
    return true;
}

// ---------- varint ----------
static int encode_varint(uint8_t *buf, uint64_t n) {
    if (n < 0xfd) { buf[0] = (uint8_t)n; return 1; }
    if (n <= 0xffff) { buf[0] = 0xfd; put_le16(buf + 1, (uint16_t)n); return 3; }
    if (n <= 0xffffffffULL) { buf[0] = 0xfe; put_le32(buf + 1, (uint32_t)n); return 5; }
    buf[0] = 0xff; put_le64(buf + 1, (uint64_t)n); return 9;
}

// ---------- submit block ----------
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

// ---------- validation ----------
int bitcoin_validate_and_submit(const char *job_id,
                                const char *full_extranonce_hex,
                                const char *ntime_hex,
                                uint32_t nonce,
                                uint32_t version_bits,
                                double diff) {
    if (!job_id || !full_extranonce_hex || !ntime_hex) return 0;
    if (!is_hex_len(ntime_hex, 8)) return 0;
    // extranonce length must match en1+en2 in hex
    size_t expect_en_hex = (size_t)(4 + g_config.extranonce2_size) * 2; // en1 fixed 4 bytes in this design
    if (strlen(full_extranonce_hex) != expect_en_hex) return 0;

    pthread_mutex_lock(&g_tmpl_lock);

    Template *job = NULL;
    for (int i = 0; i < MAX_JOB_HISTORY; i++) {
        if (g_jobs[i].valid && strcmp(g_jobs[i].job_id, job_id) == 0) {
            job = &g_jobs[i];
            break;
        }
    }
    if (!job) {
        pthread_mutex_unlock(&g_tmpl_lock);
        return 0;
    }

    // Build coinbase hex (coinb1 + extranonce + coinb2)
    size_t coin_hex_len = strlen(job->coinb1) + strlen(full_extranonce_hex) + strlen(job->coinb2);
    if (coin_hex_len >= 20000) { pthread_mutex_unlock(&g_tmpl_lock); return 0; }

    char *coin_hex = malloc(coin_hex_len + 1);
    if (!coin_hex) { pthread_mutex_unlock(&g_tmpl_lock); return 0; }
    strcpy(coin_hex, job->coinb1);
    strcat(coin_hex, full_extranonce_hex);
    strcat(coin_hex, job->coinb2);

    size_t coin_bin_len = strlen(coin_hex) / 2;
    uint8_t *coin_bin = malloc(coin_bin_len);
    if (!coin_bin) { free(coin_hex); pthread_mutex_unlock(&g_tmpl_lock); return 0; }
    if (!hex2bin_checked(coin_hex, coin_bin, coin_bin_len)) {
        free(coin_bin); free(coin_hex); pthread_mutex_unlock(&g_tmpl_lock);
        return 0;
    }

    // coinbase txid = sha256d(coinbase_tx_bytes) (little-endian bytes as produced)
    uint8_t coinbase_hash_le[32];
    sha256d(coin_bin, coin_bin_len, coinbase_hash_le);

    // Build merkle root: start from coinbase_hash_le, combine with siblings (LE)
    uint8_t root_le[32];
    memcpy(root_le, coinbase_hash_le, 32);

    for (size_t i = 0; i < job->merkle_count; i++) {
        uint8_t sib_le[32];
        if (!hex2bin_checked(job->merkle_branch[i], sib_le, 32)) {
            free(coin_bin); free(coin_hex); pthread_mutex_unlock(&g_tmpl_lock);
            return 0;
        }
        uint8_t cat[64];
        memcpy(cat, root_le, 32);
        memcpy(cat + 32, sib_le, 32);
        sha256d(cat, 64, root_le);
    }

    // Build header (80 bytes)
    uint8_t head[80];
    memset(head, 0, sizeof(head));

    uint32_t ver = job->version_val;
    if (g_config.version_mask != 0) {
        ver = (ver & ~g_config.version_mask) | (version_bits & g_config.version_mask);
    }
    put_le32(head + 0, ver);

    // prev_hash_bin stored as LE bytes (from getblocktemplate previousblockhash reversed)
    // header expects LE bytes in serialization, so memcpy directly
    // NOTE: job doesn't store prev_hash_bin in this revised Template, so we reconstruct from prev_hash_stratum?
    // We kept prev_hash_stratum only for notify. For validation we can derive header prevhash from notify's swapped format:
    // But easier: store prevhash LE bytes in internal job. We'll do that by embedding it in unused txids_le pointer area is wrong.
    // So: in this file we store prevhash LE in job->txids_le? No.
    // Solution: we maintain prevhash LE in coinbase_value field? No.
    // Instead: we add a static per-job prevhash_le in a private array aligned with g_jobs, but that changes header.
    // To keep interface minimal: store prevhash LE in coinb2? No.
    // Practical fix: we add a hidden field by reusing txids_le allocation? Not safe.
    // Therefore: we must store prevhash LE in Template; it existed in your original code but removed in new header.
    // We'll keep it by embedding in Template via a local static map keyed by job slot.
    // For simplicity in this patch: reconstruct prevhash LE from job->prev_hash_stratum by reversing swap32 + reverse_bytes.
    uint8_t prev_stratum_bin[32];
    if (!hex2bin_checked(job->prev_hash_stratum, prev_stratum_bin, 32)) {
        free(coin_bin); free(coin_hex); pthread_mutex_unlock(&g_tmpl_lock);
        return 0;
    }
    // prev_hash_stratum = swap32(prevhash_le)
    // so prevhash_le = swap32(prev_stratum_bin)
    swap32_buffer(prev_stratum_bin, 32);
    memcpy(head + 4, prev_stratum_bin, 32);

    // merkle root in header is LE serialization; our root_le is LE bytes
    memcpy(head + 36, root_le, 32);

    uint32_t ntime = (uint32_t)strtoul(ntime_hex, NULL, 16);
    put_le32(head + 68, ntime);
    put_le32(head + 72, job->nbits_val);
    put_le32(head + 76, nonce);

    // Hash header
    uint8_t hash_le[32];
    sha256d(head, 80, hash_le);

    // Convert to BE for comparisons/display
    uint8_t hash_be[32];
    for (int i = 0; i < 32; i++) hash_be[i] = hash_le[31 - i];

    char hash_hex[65];
    bin2hex_safe(hash_be, 32, hash_hex, sizeof(hash_hex));

    // Share target (from diff)
    uint8_t share_target_be[32];
    if (!diff_to_target_be(diff, share_target_be)) {
        free(coin_bin); free(coin_hex); pthread_mutex_unlock(&g_tmpl_lock);
        return 0;
    }

    int accepted = 0;
    if (cmp256_be(hash_be, share_target_be) <= 0) accepted = 1;

    // Block target from nbits
    uint8_t block_target_be[32];
    nbits_to_target_be(job->nbits_val, block_target_be);

    int is_block = (cmp256_be(hash_be, block_target_be) <= 0);

    int result = 0;
    if (!accepted && !is_block) {
        // low difficulty
        result = 0;
    } else if (is_block) {
        log_info(">>> BLOCK FOUND! Hash: %s", hash_hex);

        // Build full block hex: header + varint(tx_count) + coinbase + txs
        size_t tx_total = 1 + job->tx_count;

        // estimate
        size_t cap = 2000000;
        char *block_hex = malloc(cap);
        if (!block_hex) {
            free(coin_bin); free(coin_hex); pthread_mutex_unlock(&g_tmpl_lock);
            return 1; // share accepted but block serialization failed
        }

        size_t pos = 0;
        char head_hex[161];
        bin2hex_safe(head, 80, head_hex, sizeof(head_hex));
        size_t hl = strlen(head_hex);
        memcpy(block_hex + pos, head_hex, hl); pos += hl;

        uint8_t vi[9];
        int vl = encode_varint(vi, (uint64_t)tx_total);
        char vi_hex[19];
        bin2hex_safe(vi, (size_t)vl, vi_hex, sizeof(vi_hex));
        size_t vil = strlen(vi_hex);
        memcpy(block_hex + pos, vi_hex, vil); pos += vil;

        // coinbase
        size_t cl = strlen(coin_hex);
        memcpy(block_hex + pos, coin_hex, cl); pos += cl;

        // other txs (job->tx_hexs contain full tx hex)
        for (size_t i = 0; i < job->tx_count; i++) {
            size_t tl = strlen(job->tx_hexs[i]);
            if (pos + tl + 1 >= cap) { free(block_hex); block_hex = NULL; break; }
            memcpy(block_hex + pos, job->tx_hexs[i], tl); pos += tl;
        }
        if (block_hex) block_hex[pos] = '\0';

        if (block_hex) backup_block_to_disk(block_hex);

        if (block_hex && bitcoin_submit_block(block_hex)) {
            log_info("Block submitted successfully");
            result = 2;
        } else {
            log_error("Block submission rejected/failed");
            result = 1; // still count share
        }
        free(block_hex);
    } else {
        // accepted share only
        result = 1;
    }

    free(coin_bin);
    free(coin_hex);
    pthread_mutex_unlock(&g_tmpl_lock);
    return result;
}

// ---------- template update ----------
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

    uint8_t prev_be[32];
    if (!hex2bin_checked(prev, prev_be, 32)) { json_decref(resp); return; }
    // store as LE bytes for internal, and as stratum format = swap32(LE)
    uint8_t prev_le[32];
    memcpy(prev_le, prev_be, 32);
    reverse_bytes(prev_le, 32);

    bool clean = force_clean;

    // Prepare new Template in local (avoid holding lock during heavy JSON parsing)
    Template tmp;
    template_zero(&tmp);
    tmp.valid = true;

    static int jid = 0;
    snprintf(tmp.job_id, sizeof(tmp.job_id), "%08x%08x", (uint32_t)time(NULL), (uint32_t)++jid);

    tmp.height = (uint32_t)json_integer_value(json_object_get(res, "height"));
    tmp.coinbase_value = (int64_t)json_integer_value(json_object_get(res, "coinbasevalue"));

    tmp.version_val = (uint32_t)json_integer_value(json_object_get(res, "version"));
    json_t *jv = json_object_get(res, "versionHex");
    if (jv && json_is_string(jv)) {
        const char *vh = json_string_value(jv);
        strncpy(tmp.version_hex, vh, 8);
        tmp.version_hex[8] = '\0';
    } else {
        snprintf(tmp.version_hex, sizeof(tmp.version_hex), "%08x", tmp.version_val);
    }

    const char *bits = json_string_value(json_object_get(res, "bits"));
    if (bits && strlen(bits) == 8) {
        strncpy(tmp.nbits_hex, bits, 8);
        tmp.nbits_hex[8] = '\0';
    } else {
        strcpy(tmp.nbits_hex, "1d00ffff");
    }
    tmp.nbits_val = (uint32_t)strtoul(tmp.nbits_hex, NULL, 16);

    tmp.curtime_val = (uint32_t)json_integer_value(json_object_get(res, "curtime"));
    snprintf(tmp.ntime_hex, sizeof(tmp.ntime_hex), "%08x", tmp.curtime_val);

    // prev_hash_stratum = hex(swap32(prev_le))
    uint8_t prev_stratum[32];
    memcpy(prev_stratum, prev_le, 32);
    swap32_buffer(prev_stratum, 32);
    bin2hex_safe(prev_stratum, 32, tmp.prev_hash_stratum, sizeof(tmp.prev_hash_stratum));

    // transactions
    json_t *txs = json_object_get(res, "transactions");
    size_t tx_count = (txs && json_is_array(txs)) ? json_array_size(txs) : 0;
    tmp.tx_count = tx_count;

    tmp.txids_le = NULL;
    tmp.tx_hexs = NULL;
    if (tx_count > 0) {
        tmp.txids_le = malloc(tx_count * 32);
        tmp.tx_hexs = calloc(tx_count, sizeof(char*));
        if (!tmp.txids_le || !tmp.tx_hexs) {
            bitcoin_free_job(&tmp);
            json_decref(resp);
            return;
        }

        for (size_t i = 0; i < tx_count; i++) {
            json_t *tx = json_array_get(txs, i);
            const char *txid = json_string_value(json_object_get(tx, "txid"));
            const char *data = json_string_value(json_object_get(tx, "data"));
            if (!txid || strlen(txid) != 64 || !data) {
                // if malformed, fail hard (template must be consistent)
                bitcoin_free_job(&tmp);
                json_decref(resp);
                return;
            }

            uint8_t txid_be[32];
            if (!hex2bin_checked(txid, txid_be, 32)) {
                bitcoin_free_job(&tmp);
                json_decref(resp);
                return;
            }
            uint8_t txid_le[32];
            memcpy(txid_le, txid_be, 32);
            reverse_bytes(txid_le, 32);
            memcpy(tmp.txids_le[i], txid_le, 32);

            tmp.tx_hexs[i] = strdup(data);
            if (!tmp.tx_hexs[i]) {
                bitcoin_free_job(&tmp);
                json_decref(resp);
                return;
            }
        }
    }

    // build coinb1/coinb2 (en1 fixed 4 bytes, en2 from config)
    const char *dwc = NULL;
    json_t *dw = json_object_get(res, "default_witness_commitment");
    if (dw && json_is_string(dw)) dwc = json_string_value(dw);

    if (!build_coinbase_hex(tmp.height, tmp.coinbase_value, g_config.coinbase_tag, dwc,
                            4, g_config.extranonce2_size,
                            tmp.coinb1, sizeof(tmp.coinb1),
                            tmp.coinb2, sizeof(tmp.coinb2))) {
        bitcoin_free_job(&tmp);
        json_decref(resp);
        return;
    }

    // compute merkle branch siblings (LE hex)
    if (!calculate_merkle_branch_from_txids((const uint8_t (*)[32])tmp.txids_le, tmp.tx_count,
                                           &tmp.merkle_branch, &tmp.merkle_count)) {
        bitcoin_free_job(&tmp);
        json_decref(resp);
        return;
    }

    // Now commit to global history with lock, decide clean based on previous prevhash change
    Template notify_snapshot;
    template_zero(&notify_snapshot);

    pthread_mutex_lock(&g_tmpl_lock);
    Template *last = &g_jobs[g_job_head];
    if (last->valid) {
        // compare prevhash using prev_hash_stratum string (stable)
        if (strncmp(last->prev_hash_stratum, tmp.prev_hash_stratum, 64) != 0) clean = true;
    }
    tmp.clean_jobs = clean;

    g_job_head = (g_job_head + 1) % MAX_JOB_HISTORY;
    Template *curr = &g_jobs[g_job_head];
    bitcoin_free_job(curr);
    *curr = tmp; // shallow move of owned pointers into ring
    // tmp must not be freed now; null it to avoid double free
    template_zero(&tmp);
    curr->valid = true;

    // make notify snapshot to send outside lock
    (void)template_deep_copy_notify(&notify_snapshot, curr);
    pthread_mutex_unlock(&g_tmpl_lock);

    log_info("Job %s [H:%u Tx:%zu] Clean:%d", notify_snapshot.job_id, notify_snapshot.height,
             notify_snapshot.tx_count, notify_snapshot.clean_jobs ? 1 : 0);

    // Broadcast outside template lock
    stratum_broadcast_job(&notify_snapshot);
    bitcoin_free_job(&notify_snapshot);

    json_decref(resp);
}
