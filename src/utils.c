#include "utils.h"
#include "sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>

// --- 日志实现 (线程安全版) ---
static void log_print(const char* level, const char* format, va_list args) {
    time_t now;
    time(&now);
    struct tm timeinfo;
    localtime_r(&now, &timeinfo); // 使用线程安全的 localtime_r
    
    char buf[20];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &timeinfo);
    
    // 使用原子写入或锁更好，但 stdout 通常是线程安全的行缓冲
    fprintf(stdout, "[%s] [%s] ", buf, level);
    vfprintf(stdout, format, args);
    fprintf(stdout, "\n");
    fflush(stdout); 
}

void log_info(const char *format, ...) {
    va_list args;
    va_start(args, format);
    log_print("INFO", format, args);
    va_end(args);
}

void log_error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    log_print("ERROR", format, args);
    va_end(args);
}

void log_debug(const char *format, ...) {
    va_list args;
    va_start(args, format);
    log_print("DEBUG", format, args);
    va_end(args);
}

// --- Hex 工具 ---
void hex2bin(const char *hex, uint8_t *bin, size_t bin_len) {
    for (size_t i = 0; i < bin_len; i++) {
        sscanf(hex + 2*i, "%2hhx", &bin[i]);
    }
}

void bin2hex(const uint8_t *bin, size_t bin_len, char *hex) {
    for (size_t i = 0; i < bin_len; i++) {
        sprintf(hex + 2*i, "%02x", bin[i]);
    }
}

void reverse_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len / 2; i++) {
        uint8_t temp = buf[i];
        buf[i] = buf[len - 1 - i];
        buf[len - 1 - i] = temp;
    }
}

// Stratum PrevHash Swap (4-byte swap)
void swap32_buffer(uint8_t *buf, size_t len) {
    if (len % 4 != 0) return;
    for (size_t i = 0; i < len; i += 4) {
        uint8_t temp = buf[i];
        buf[i] = buf[i+3];
        buf[i+3] = temp;
        temp = buf[i+1];
        buf[i+1] = buf[i+2];
        buf[i+2] = temp;
    }
}

uint32_t swap_uint32(uint32_t val) {
    return ((val >> 24) & 0xff) | ((val << 8) & 0xff0000) |
           ((val >> 8) & 0xff00) | ((val << 24) & 0xff000000);
}

// --- Base58 ---
static const char *b58digits_map = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
int base58_decode_check(const char *str, uint8_t *payload, size_t *payload_len) {
    uint8_t bin[128]; 
    size_t bin_len = 0;
    size_t len = strlen(str);
    int zeros = 0;
    while (zeros < (int)len && str[zeros] == '1') zeros++;
    memset(bin, 0, sizeof(bin));
    for (const char *p = str; *p; p++) {
        const char *digit = strchr(b58digits_map, *p);
        if (!digit) return -1;
        int carrier = (int)(digit - b58digits_map);
        for (int i = sizeof(bin) - 1; i >= 0; i--) {
            int val = bin[i] * 58 + carrier;
            bin[i] = val & 0xFF;
            carrier = val >> 8;
        }
    }
    int i = 0;
    while (i < (int)sizeof(bin) && bin[i] == 0) i++;
    bin_len = zeros + (sizeof(bin) - i);
    if (bin_len < 4) return -1;
    if (payload) {
        memset(payload, 0, zeros);
        memcpy(payload + zeros, bin + i, bin_len - zeros);
    }
    uint8_t hash[32];
    sha256_double(payload, bin_len - 4, hash);
    if (memcmp(hash, payload + bin_len - 4, 4) != 0) return -1;
    *payload_len = bin_len - 4;
    return payload[0];
}

// --- Bech32 ---
static uint32_t bech32_polymod_step(uint32_t pre) {
    uint32_t b = pre >> 25;
    return ((pre & 0x1FFFFFF) << 5) ^
           (-((b >> 0) & 1) & 0x3b6a57b2UL) ^ (-((b >> 1) & 1) & 0x26508e6dUL) ^
           (-((b >> 2) & 1) & 0x1ea119faUL) ^ (-((b >> 3) & 1) & 0x3d4233ddUL) ^
           (-((b >> 4) & 1) & 0x2a1462b3UL);
}
static int bech32_decode(const char* hrp, const char* addr, uint8_t *data, size_t *data_len, int *encoding) {
    uint32_t chk = 1; size_t i; const char *p; size_t len = strlen(addr);
    if (len < 8 || len > 90) return 0;
    p = strrchr(addr, '1');
    if (!p || p == addr || p + 7 > addr + len) return 0;
    if ((size_t)(p - addr) != strlen(hrp)) return 0;
    if (strncasecmp(addr, hrp, (p - addr)) != 0) return 0;
    for (i = 0; i < (size_t)(p - addr); ++i) chk = bech32_polymod_step(chk) ^ ((addr[i] & 0x1F) ? (addr[i] | 0x20) >> 5 : 0);
    chk = bech32_polymod_step(chk);
    for (i = 0; i < (size_t)(p - addr); ++i) chk = bech32_polymod_step(chk) ^ (addr[i] & 0x1f);
    const char *charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    size_t dlen = 0;
    for (p++; *p; ++p) {
        const char *d = strchr(charset, tolower(*p));
        if (!d) return 0;
        uint8_t val = (d - charset);
        chk = bech32_polymod_step(chk) ^ val;
        if (dlen < 82) data[dlen++] = val;
    }
    if (encoding) { if (chk == 1) *encoding = 1; else if (chk == 0x2bc830a3) *encoding = 2; else return 0; }
    else if (chk != 1 && chk != 0x2bc830a3) return 0;
    *data_len = dlen - 6; return 1;
}
static int convert_bits(uint8_t* out, size_t* outlen, int outbits, const uint8_t* in, size_t inlen, int inbits, int pad) {
    uint32_t val = 0; int bits = 0; uint32_t maxv = (((uint32_t)1) << outbits) - 1; size_t op = 0;
    for (size_t i = 0; i < inlen; ++i) {
        val = (val << inbits) | in[i]; bits += inbits;
        while (bits >= outbits) { bits -= outbits; out[op++] = (val >> bits) & maxv; }
    }
    if (pad) { if (bits) out[op++] = (val << (outbits - bits)) & maxv; }
    else if (bits >= inbits || ((val << (outbits - bits)) & maxv)) return 0;
    *outlen = op; return 1;
}
int segwit_addr_decode(int* witver, uint8_t* witprog, size_t* witprog_len, const char* hrp, const char* addr) {
    uint8_t data[84]; size_t data_len; int encoding = 0;
    if (!bech32_decode(hrp, addr, data, &data_len, &encoding)) return 0;
    if (data_len < 1 || data_len > 65) return 0;
    if (data[0] > 16) return 0;
    if (data[0] == 0 && encoding != 1) return 0; if (data[0] > 0 && encoding != 2) return 0;
    *witver = data[0];
    if (!convert_bits(witprog, witprog_len, 8, data + 1, data_len - 1, 5, 0)) return 0;
    if (*witprog_len < 2 || *witprog_len > 40) return 0;
    if (*witver == 0 && *witprog_len != 20 && *witprog_len != 32) return 0;
    return 1;
}

void address_to_script(const char *addr, char *script_hex) {
    uint8_t buf[64]; size_t len = 0; int witver;
    if (segwit_addr_decode(&witver, buf, &len, "bc", addr) || segwit_addr_decode(&witver, buf, &len, "tb", addr) || segwit_addr_decode(&witver, buf, &len, "bcrt", addr)) {
        uint8_t op_ver = (witver == 0) ? 0x00 : (0x50 + witver);
        sprintf(script_hex, "%02x%02x", op_ver, (int)len);
        char prog_hex[128]; bin2hex(buf, len, prog_hex); strcat(script_hex, prog_hex); return;
    }
    int ver = base58_decode_check(addr, buf, &len);
    if (ver >= 0) {
        if (ver == 0 || ver == 111) { strcpy(script_hex, "76a914"); char hash_hex[41]; bin2hex(buf, len, hash_hex); strcat(script_hex, hash_hex); strcat(script_hex, "88ac"); return; } 
        else if (ver == 5 || ver == 196) { strcpy(script_hex, "a914"); char hash_hex[41]; bin2hex(buf, len, hash_hex); strcat(script_hex, hash_hex); strcat(script_hex, "87"); return; }
    }
    log_error("Invalid Address: %s. Using OP_RETURN.", addr);
    strcpy(script_hex, "6a04deadbeef"); 
}
