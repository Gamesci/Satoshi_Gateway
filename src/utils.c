#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>

#include "utils.h"
#include "sha256.h"

// ---------- logging ----------
static void log_v(FILE *f, const char *lvl, const char *fmt, va_list ap) {
    char msg[2048];
    time_t now = time(NULL);
    char tbuf[64];
    strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    vsnprintf(msg, sizeof(msg), fmt, ap);
    fprintf(f, "[%s] [%s] %s\n", tbuf, lvl, msg);
}

void log_info(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    log_v(stdout, "INFO", fmt, ap);
    va_end(ap);
}

void log_error(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    log_v(stderr, "ERROR", fmt, ap);
    va_end(ap);
}

// ---------- hex ----------
static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

bool hex2bin_checked(const char *hex, uint8_t *bin, size_t bin_len) {
    if (!hex || !bin) return false;
    size_t hex_len = strlen(hex);
    if (hex_len != bin_len * 2) return false;

    for (size_t i = 0; i < bin_len; i++) {
        int hi = hexval((unsigned char)hex[i * 2]);
        int lo = hexval((unsigned char)hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        bin[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

bool bin2hex_safe(const uint8_t *bin, size_t bin_len, char *hex, size_t hex_cap) {
    static const char *d = "0123456789abcdef";
    if (!bin || !hex) return false;
    if (hex_cap < bin_len * 2 + 1) return false;
    for (size_t i = 0; i < bin_len; i++) {
        hex[i * 2]     = d[(bin[i] >> 4) & 0xF];
        hex[i * 2 + 1] = d[bin[i] & 0xF];
    }
    hex[bin_len * 2] = '\0';
    return true;
}

// ---------- byte order ----------
void reverse_bytes(uint8_t *buf, size_t len) {
    if (!buf) return;
    for (size_t i = 0; i < len / 2; i++) {
        uint8_t t = buf[i];
        buf[i] = buf[len - 1 - i];
        buf[len - 1 - i] = t;
    }
}

void swap32_buffer(uint8_t *buf, size_t len) {
    if (!buf) return;
    if (len % 4 != 0) return;
    for (size_t i = 0; i < len; i += 4) {
        uint8_t t;
        t = buf[i]; buf[i] = buf[i + 3]; buf[i + 3] = t;
        t = buf[i + 1]; buf[i + 1] = buf[i + 2]; buf[i + 2] = t;
    }
}

void put_le16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
}
void put_le32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xff);
    p[1] = (uint8_t)((v >> 8) & 0xff);
    p[2] = (uint8_t)((v >> 16) & 0xff);
    p[3] = (uint8_t)((v >> 24) & 0xff);
}
void put_le64(uint8_t *p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xff);
}

void sha256d(const uint8_t *data, size_t len, uint8_t out32[32]) {
    sha256_double(data, len, out32);
}

// ---------- address decoding (Base58Check + Bech32/Bech32m) ----------
// Minimal Base58Check verify for legacy addresses (P2PKH/P2SH).
static const int8_t b58values[128] = {
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1, -1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6,  7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15, 16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29, 30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39, 40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54, 55,56,57,-1,-1,-1,-1,-1
};

static bool base58_decode_25(const char *str, uint8_t out25[25]) {
    uint8_t buf[25] = {0};
    size_t len = strlen(str);
    for (size_t i = 0; i < len; ++i) {
        unsigned char ch = (unsigned char)str[i];
        if (ch & 0x80) return false;
        if (ch >= 128) return false;
        int carry = b58values[ch];
        if (carry < 0) return false;
        for (int j = 24; j >= 0; --j) {
            int val = buf[j] * 58 + carry;
            buf[j] = (uint8_t)(val & 0xff);
            carry = val >> 8;
        }
    }
    memcpy(out25, buf, 25);
    return true;
}

static bool base58check_payload20(const char *addr, uint8_t *ver, uint8_t payload20[20]) {
    uint8_t bin[25];
    if (!base58_decode_25(addr, bin)) return false;

    // checksum is last 4 bytes of sha256d(version+payload)
    uint8_t chk[32];
    sha256d(bin, 21, chk);
    if (memcmp(chk, bin + 21, 4) != 0) return false;

    *ver = bin[0];
    memcpy(payload20, bin + 1, 20);
    return true;
}

// Bech32 decode based on your previous code (kept) with small safety fixes.
static uint32_t bech32_polymod_step(uint32_t pre) {
    uint32_t b = pre >> 25;
    return ((pre & 0x1FFFFFF) << 5) ^
           (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
           (-((b >> 1) & 1) & 0x26508e6dUL) ^
           (-((b >> 2) & 1) & 0x1ea119faUL) ^
           (-((b >> 3) & 1) & 0x3d4233ddUL) ^
           (-((b >> 4) & 1) & 0x2a1462b3UL);
}

static const int8_t bech32_values[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1
};

static bool convert_bits(uint8_t* out, size_t* outlen, int outbits,
                         const uint8_t* in, size_t inlen, int inbits, int pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    size_t out_pos = 0;

    for (size_t i = 0; i < inlen; ++i) {
        val = (val << inbits) | in[i];
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[out_pos++] = (uint8_t)((val >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits) out[out_pos++] = (uint8_t)((val << (outbits - bits)) & maxv);
    } else {
        if (bits >= inbits) return false;
        if (((val << (outbits - bits)) & maxv) != 0) return false;
    }
    *outlen = out_pos;
    return true;
}

static bool segwit_addr_decode(int* witver, uint8_t* witprog, size_t* witprog_len,
                               const char* hrp, const char* addr) {
    size_t hrp_len = strlen(hrp);
    if (strncmp(addr, hrp, hrp_len) != 0) return false;
    if (addr[hrp_len] != '1') return false;

    const char *data_part = addr + hrp_len + 1;
    size_t data_len = strlen(data_part);
    if (data_len < 6 || data_len > 127) return false;

    uint8_t values[128];

    uint32_t chk = 1;
    for (size_t i = 0; i < hrp_len; ++i) chk = bech32_polymod_step(chk) ^ (hrp[i] >> 5);
    chk = bech32_polymod_step(chk);
    for (size_t i = 0; i < hrp_len; ++i) chk = bech32_polymod_step(chk) ^ (hrp[i] & 0x1f);

    for (size_t i = 0; i < data_len; ++i) {
        unsigned char c = (unsigned char)data_part[i];
        if (c > 127) return false;
        int8_t v = bech32_values[c];
        if (v < 0) return false;
        values[i] = (uint8_t)v;
        chk = bech32_polymod_step(chk) ^ values[i];
    }

    int spec = -1;
    if (chk == 1) spec = 1;                 // bech32
    else if (chk == 0x2bc830a3) spec = 2;   // bech32m
    else return false;

    *witver = values[0];

    size_t prog_len_5 = data_len - 1 - 6;
    if (!convert_bits(witprog, witprog_len, 8, values + 1, prog_len_5, 5, 0)) return false;

    if (*witprog_len < 2 || *witprog_len > 40) return false;
    if (*witver == 0 && spec != 1) return false;
    if (*witver != 0 && spec != 2) return false;

    return true;
}

bool address_to_script_checked(const char *addr, char *script_hex, size_t script_hex_cap) {
    if (!addr || !script_hex || script_hex_cap < 3) return false;
    script_hex[0] = '\0';

    // Base58 P2PKH/P2SH mainnet/testnet/regtest (by version byte)
    if (addr[0] == '1' || addr[0] == '3' || addr[0] == 'm' || addr[0] == 'n' || addr[0] == '2') {
        uint8_t ver = 0;
        uint8_t h20[20];
        if (!base58check_payload20(addr, &ver, h20)) return false;

        // 0x00/0x6f => P2PKH, 0x05/0xc4 => P2SH
        if (ver == 0x00 || ver == 0x6f) {
            // 76 a9 14 <20> 88 ac
            if (script_hex_cap < 2 + 2 + 2 + 40 + 2 + 2 + 1) return false;
            strcpy(script_hex, "76a914");
            char h[41];
            if (!bin2hex_safe(h20, 20, h, sizeof(h))) return false;
            strcat(script_hex, h);
            strcat(script_hex, "88ac");
            return true;
        }
        if (ver == 0x05 || ver == 0xc4) {
            // a9 14 <20> 87
            if (script_hex_cap < 2 + 2 + 40 + 2 + 1) return false;
            strcpy(script_hex, "a914");
            char h[41];
            if (!bin2hex_safe(h20, 20, h, sizeof(h))) return false;
            strcat(script_hex, h);
            strcat(script_hex, "87");
            return true;
        }
        return false;
    }

    // Bech32 segwit v0/v1+ (including taproot v1)
    if (strncmp(addr, "bc1", 3) == 0 || strncmp(addr, "tb1", 3) == 0 || strncmp(addr, "bcrt1", 5) == 0) {
        const char *hrp = "bc";
        if (strncmp(addr, "tb1", 3) == 0) hrp = "tb";
        else if (strncmp(addr, "bcrt1", 5) == 0) hrp = "bcrt";

        int witver = 0;
        uint8_t witprog[40];
        size_t witprog_len = sizeof(witprog);
        if (!segwit_addr_decode(&witver, witprog, &witprog_len, hrp, addr)) return false;

        // script: <version opcode> <pushlen> <program>
        // v0 => 0x00, v1..16 => 0x50+v
        uint8_t verop = (witver == 0) ? 0x00 : (uint8_t)(0x50 + witver);
        if (witver < 0 || witver > 16) return false;
        if (witprog_len < 2 || witprog_len > 40) return false;

        // hex capacity: 1+1+witprog_len bytes => (2*(2+witprog_len)+1)
        if (script_hex_cap < (size_t)(2 * (2 + witprog_len) + 1)) return false;

        char tmp[128];
        snprintf(tmp, sizeof(tmp), "%02x%02x", verop, (unsigned)witprog_len);
        strcpy(script_hex, tmp);

        char prog_hex[81];
        if (!bin2hex_safe(witprog, witprog_len, prog_hex, sizeof(prog_hex))) return false;
        strcat(script_hex, prog_hex);
        return true;
    }

    return false;
}
