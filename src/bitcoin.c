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

    // target = mantissa * 2^(8*(exp-3))
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

// diff1 target (Bitcoin) = 0x00000000FFFF0000000000000000000000000000000000000000000000000000
static void diff1_target_be(uint8_t out[32]) {
    memset(out, 0, 32);
    // Big-endian placement:
    // 00 00 00 00 FF FF 00 00 00 ... 00
    out[4] = 0xff;
    out[5] = 0xff;
    out[6] = 0x00;
    out[7] = 0x00;
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

// Multiply 256-bit big-endian by uint32, keep low 256 bits. Returns carry (overflow) discarded.
static void mul256_u32_be(uint8_t x[32], uint32_t mul) {
    uint64_t carry = 0;
    for (int i = 31; i >= 0; i--) {
        uint64_t prod = (uint64_t)x[i] * (uint64_t)mul + carry;
        x[i] = (uint8_t)(prod & 0xff);
        carry = prod >> 8;
    }
}

// x = x * 2^k (k in [0,255]) for 256-bit BE, overflow discarded.
static void shl256_be(uint8_t x[32], unsigned k) {
    if (k == 0) return;
    unsigned bytes = k / 8;
    unsigned bits  = k % 8;

    if (bytes >= 32) {
        memset(x, 0, 32);
        return;
    }

    if (bytes > 0) {
        for (int i = 0; i < 32; i++) {
            int src = i + (int)bytes;
            x[i] = (src < 32) ? x[src] : 0;
        }
    }

    if (bits == 0) return;

    uint8_t prev = 0;
    for (int i = 31; i >= 0; i--) {
        uint8_t cur = x[i];
        x[i] = (uint8_t)((cur << bits) | (prev >> (8 - bits)));
        prev = cur;
    }
}

// Compare 256-bit BE to zero
static bool is_zero256_be(const uint8_t x[32]) {
    for (int i = 0; i < 32; i++) if (x[i] != 0) return false;
    return true;
}

// Divide 256-bit BE integer by 64-bit BE-ish? We'll implement long division by 64-bit divisor in base 256.
static void div256_u64_be(uint8_t x[32], uint64_t div) {
    if (div == 0) { memset(x, 0, 32); return; }
    __uint128_t rem = 0;
    for (int i = 0; i < 32; i++) {
        __uint128_t cur = (rem << 8) | x[i];
        x[i] = (uint8_t)(cur / div);
        rem = cur % div;
    }
}

// Convert diff -> target using high-precision approach:
// target = diff1_target / diff
// We implement: represent diff as mantissa * 2^exp (binary), then do integer division by mantissa and shift.
static bool diff_to_target_be(double diff, uint8_t target_be[32]) {
    if (!(diff > 0.0) || !isfinite(diff)) return false;

    // Clamp: Stratum diff should not be <1 in typical pools; allow but clamp to 1 to avoid target > diff1.
    if (diff < 1.0) diff = 1.0;

    // Decompose diff = m * 2^e, with m in [0.5,1)
    int e2 = 0;
    double m = frexp(diff, &e2); // diff = m * 2^e2

    // Scale mantissa to 64-bit integer for division
    // mant = round(m * 2^64). Since m<1, mant fits in 64 bits.
    long double md = (long double)m;
    long double scaled = md * (long double)18446744073709551616.0L; // 2^64
    uint64_t mant = (uint64_t)(scaled + 0.5L);
    if (mant == 0) mant = 1;

    // target = diff1 / (mant * 2^(e2-64))
    // = (diff1 * 2^(64 - e2)) / mant
    uint8_t t[32];
    diff1_target_be(t);

    // FIX: Perform division BEFORE shift to prevent overflow of the 256-bit buffer.
    // Diff1 is approx 2^224. If we shift left by e.g. 53 (for diff=1024), it exceeds 256 bits.
    // By dividing first, we reduce the number significantly, making the subsequent shift safe.
    div256_u64_be(t, mant);

    // Apply shift left by (64 - e2) if positive, else shift right by (e2 - 64) using division by 2^k.
    int shift = 64 - e2;
    if (shift > 0) {
        if (shift > 255) shift = 255;
        shl256_be(t, (unsigned)shift);
    } else if (shift < 0) {
        // right shift by -shift: repeated div by 2^k = div by 2^(-shift)
        int r = -shift;
        if (r > 255) { memset(t, 0, 32); }
        else {
            // divide by 2^r: do it byte-wise with carry
            unsigned bytes = (unsigned)(r / 8);
            unsigned bits  = (unsigned)(r % 8);
            if (bytes >= 32) memset(t, 0, 32);
            else {
                if (bytes > 0) {
                    for (int i = 31; i >= 0; i--) {
                        int src = i - (int)bytes;
                        t[i] = (src >= 0) ? t[src] : 0;
                    }
                }
                if (bits) {
                    uint8_t carry = 0;
                    for (int i = 0; i < 32; i++) {
                        uint8_t cur = t[i];
                        t[i] = (uint8_t)((cur >> bits) | (carry << (8 - bits)));
                        carry = (uint8_t)(cur & ((1u << bits) - 1u));
                    }
                }
            }
        }
    }

    if (is_zero256_be(t)) {
        // Avoid zero target
        t[31] = 1;
    }
    memcpy(target_be, t, 32);
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
    *dst = *src;

    dst->merkle_branch = NULL;
    if (src->merkle_count > 0) {
        dst->merkle_branch = calloc(src->merkle_count, sizeof(char*));
        if (!dst->merkle_branch) return false;
        for (size_t i = 0; i < src->merkle_count; i++) {
            dst->merkle_branch[i] = strdup(src->merkle_branch[i]);
            if (!dst->merkle_branch[i]) return false;
        }
    }
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
    if (extranonce1_size <= 0 || extranonce2_size <= 0) return false;
    if (extranonce1_size + extranonce2_size > 64) return false;

    uint8_t scriptSig[256];
    size_t sp = 0;

    // BIP34 height encoding
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

    uint8_t en_placeholder[64];
    memset(en_placeholder, 0, (size_t)(extranonce1_size + extranonce2_size));
    size_t en_tot = (size_t)(extranonce1_size + extranonce2_size);
    size_t w = write_pushdata(scriptSig + sp, sizeof(scriptSig) - sp, en_placeholder, en_tot);
    if (w == 0) return false;

    size_t en_push_hdr = 0;
    if (en_tot <= 75) en_push_hdr = 1;
    else if (en_tot <= 255) en_push_hdr = 2;
    else en_push_hdr = 3;

    size_t en_data_offset_in_script = sp + en_push_hdr;
    sp += w;

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

    uint8_t tx_prefix[512];
    size_t tp = 0;

    put_le32(tx_prefix + tp, 1); tp += 4;
    tx_prefix[tp++] = 0x01;
    memset(tx_prefix + tp, 0, 32); tp += 32;
    put_le32(tx_prefix + tp, 0xffffffffU); tp += 4;

    if (sp < 0xfd) tx_prefix[tp++] = (uint8_t)sp;
    else return false;

    size_t en1_end = en_data_offset_in_script + (size_t)extranonce1_size;
    size_t en2_end = en1_end + (size_t)extranonce2_size;
    if (en2_end > sp) return false;

    uint8_t coinb1_bin[2048];
    size_t c1 = 0;
    if (sizeof(coinb1_bin) < tp + en1_end) return false;
    memcpy(coinb1_bin + c1, tx_prefix, tp); c1 += tp;
    memcpy(coinb1_bin + c1, scriptSig, en1_end); c1 += en1_end;

    uint8_t coinb2_bin[4096];
    size_t c2 = 0;
    memcpy(coinb2_bin + c2, scriptSig + en2_end, sp - en2_end); c2 += (sp - en2_end);

    put_le32(coinb2_bin + c2, 0xffffffffU); c2 += 4;

    int outputs = 1;
    bool has_wit_commit = (default_witness_commitment_hex && strlen(default_witness_commitment_hex) > 0);
    if (has_wit_commit) outputs = 2;

    coinb2_bin[c2++] = (uint8_t)outputs;

    put_le64(coinb2_bin + c2, (uint64_t)value_sats); c2 += 8;

    char script_hex[256];
    if (!address_to_script_checked(g_config.payout_addr, script_hex, sizeof(script_hex))) return false;
    size_t script_len = strlen(script_hex) / 2;
    if (script_len > 252) return false;

    coinb2_bin[c2++] = (uint8_t)script_len;

    uint8_t script_bin[256];
    if (!hex2bin_checked(script_hex, script_bin, script_len)) return false;
    memcpy(coinb2_bin + c2, script_bin, script_len); c2 += script_len;

    if (has_wit_commit) {
        put_le64(coinb2_bin + c2, 0); c2 += 8;

        size_t wlen = strlen(default_witness_commitment_hex) / 2;
        if (wlen < 1 || wlen > 80) return false;
        coinb2_bin[c2++] = (uint8_t)wlen;

        uint8_t wbin[128];
        if (!hex2bin_checked(default_witness_commitment_hex, wbin, wlen)) return false;
        memcpy(coinb2_bin + c2, wbin, wlen); c2 += wlen;
    }

    put_le32(coinb2_bin + c2, 0); c2 += 4;

    if (!bin2hex_safe(coinb1_bin, c1, coinb1_hex, coinb1_cap)) return false;
    if (!bin2hex_safe(coinb2_bin, c2, coinb2_hex, coinb2_cap)) return false;
    return true;
}

// ---------- merkle branch generation ----------
static bool calculate_merkle_branch_from_txids(const uint8_t (*txids_le)[32], size_t tx_count,
                                               char ***out_branch, size_t *out_count) {
    *out_branch = NULL;
    *out_count = 0;

    size_t total = 1 + tx_count;
    if (total == 1) return true;

    uint8_t *level = calloc(total, 32);
    if (!level) return false;

    for (size_t i = 0; i < tx_count; i++) {
        memcpy(level + (i + 1) * 32, txids_le[i], 32);
    }

    char **branch = calloc(64, sizeof(char*));
    if (!branch) { free(level); return false; }
    size_t bcount = 0;

    size_t level_count = total;
    uint8_t *next = NULL;

    while (level_count > 1) {
        const uint8_t *sib = (level_count > 1) ? (level + 1 * 32) : (level + 0);
        char hex[65];
        (void)bin2hex_safe(sib, 32, hex, sizeof(hex));
        branch[bcount] = strdup(hex);
        if (!branch[bcount]) {
            free(level);
            for (size_t k = 0; k < bcount; k++) free(branch[k]);
            free(branch);
            return false;
        }
        bcount++;

        size_t pairs = (level_count + 1) / 2;
        next = calloc(pairs, 32);
        if (!next) {
            free(level);
            for (size_t k = 0; k < bcount; k++) free(branch[k]);
            free(branch);
            return false;
        }

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

        if (bcount >= 64) break;
    }

    free(level);

    char **final = calloc(bcount, sizeof(char*));
    if (!final && bcount > 0) {
        for (size_t k = 0; k < bcount; k++) free(branch[k]);
        free(branch);
        return false;
    }
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

    size_t expect_en_hex = (size_t)(4 + g_config.extranonce2_size) * 2;
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

    // Build coinbase hex
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

    // coinbase txid (LE bytes)
    uint8_t coinbase_hash_le[32];
    sha256d(coin_bin, coin_bin_len, coinbase_hash_le);

    // merkle root (LE bytes)
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

    // Build header (80 bytes, serialized little-endian fields)
    uint8_t head[80];
    memset(head, 0, sizeof(head));

    uint32_t ver = job->version_val;
    if (g_config.version_mask != 0) {
        ver = (ver & ~g_config.version_mask) | (version_bits & g_config.version_mask);
    }
    put_le32(head + 0, ver);

    // prevhash: use stored header-ready LE bytes (no reconstruction hacks)
    memcpy(head + 4, job->prevhash_le, 32);

    // merkle root: LE bytes
    memcpy(head + 36, root_le, 32);

    uint32_t ntime = (uint32_t)strtoul(ntime_hex, NULL, 16);
    put_le32(head + 68, ntime);
    put_le32(head + 72, job->nbits_val);
    put_le32(head + 76, nonce);

    // Hash header: sha256d -> LE bytes
    uint8_t hash_le[32];
    sha256d(head, 80, hash_le);

    // Convert to BE for numeric compare and display
    uint8_t hash_be[32];
    for (int i = 0; i < 32; i++) hash_be[i] = hash_le[31 - i];

    char hash_hex[65];
    (void)bin2hex_safe(hash_be, 32, hash_hex, sizeof(hash_hex));

    // Share target (from diff)
    uint8_t share_target_be[32];
    if (!diff_to_target_be(diff, share_target_be)) {
        free(coin_bin); free(coin_hex); pthread_mutex_unlock(&g_tmpl_lock);
        return 0;
    }

    int accepted = (cmp256_be(hash_be, share_target_be) <= 0);

    // Block target from nbits
    uint8_t block_target_be[32];
    nbits_to_target_be(job->nbits_val, block_target_be);
    int is_block = (cmp256_be(hash_be, block_target_be) <= 0);

    int result = 0;
    if (!accepted && !is_block) {
        result = 0; // low diff
    } else if (is_block) {
        log_info(">>> BLOCK FOUND! Hash: %s", hash_hex);

        size_t tx_total = 1 + job->tx_count;

        size_t cap = 2000000;
        char *block_hex = malloc(cap);
        if (!block_hex) {
            free(coin_bin); free(coin_hex); pthread_mutex_unlock(&g_tmpl_lock);
            return 1;
        }

        size_t pos = 0;
        char head_hex[161];
        (void)bin2hex_safe(head, 80, head_hex, sizeof(head_hex));
        size_t hl = strlen(head_hex);
        memcpy(block_hex + pos, head_hex, hl); pos += hl;

        uint8_t vi[9];
        int vl = encode_varint(vi, (uint64_t)tx_total);
        char vi_hex[19];
        (void)bin2hex_safe(vi, (size_t)vl, vi_hex, sizeof(vi_hex));
        size_t vil = strlen(vi_hex);
        memcpy(block_hex + pos, vi_hex, vil); pos += vil;

        size_t cl = strlen(coin_hex);
        memcpy(block_hex + pos, coin_hex, cl); pos += cl;

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
            result = 1;
        }
        free(block_hex);
    } else {
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

    // Header needs prevhash as LE bytes
    uint8_t prev_le[32];
    memcpy(prev_le, prev_be, 32);
    reverse_bytes(prev_le, 32);

    bool clean = force_clean;

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

    // Store prevhash for header
    memcpy(tmp.prevhash_le, prev_le, 32);

    // prev_hash_stratum = hex(swap32(prev_le)) as your original design
    uint8_t prev_stratum[32];
    memcpy(prev_stratum, prev_le, 32);
    swap32_buffer(prev_stratum, 32);
    (void)bin2hex_safe(prev_stratum, 32, tmp.prev_hash_stratum, sizeof(tmp.prev_hash_stratum));

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

    if (!calculate_merkle_branch_from_txids((const uint8_t (*)[32])tmp.txids_le, tmp.tx_count,
                                           &tmp.merkle_branch, &tmp.merkle_count)) {
        bitcoin_free_job(&tmp);
        json_decref(resp);
        return;
    }

    Template notify_snapshot;
    template_zero(&notify_snapshot);

    pthread_mutex_lock(&g_tmpl_lock);
    Template *last = &g_jobs[g_job_head];
    if (last->valid) {
        if (strncmp(last->prev_hash_stratum, tmp.prev_hash_stratum, 64) != 0) clean = true;
    }
    tmp.clean_jobs = clean;

    g_job_head = (g_job_head + 1) % MAX_JOB_HISTORY;
    Template *curr = &g_jobs[g_job_head];
    bitcoin_free_job(curr);
    *curr = tmp;
    template_zero(&tmp);
    curr->valid = true;

    (void)template_deep_copy_notify(&notify_snapshot, curr);
    pthread_mutex_unlock(&g_tmpl_lock);

    log_info("Job %s [H:%u Tx:%zu] Clean:%d", notify_snapshot.job_id, notify_snapshot.height,
             notify_snapshot.tx_count, notify_snapshot.clean_jobs ? 1 : 0);

    stratum_broadcast_job(&notify_snapshot);
    bitcoin_free_job(&notify_snapshot);

    json_decref(resp);
}
