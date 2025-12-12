#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include "utils.h"
#include "sha256.h"

// --- Log & Hex Tools ---

void log_info(const char *fmt, ...) {
    char buf[1024]; va_list args;
    time_t now; time(&now); char tbuf[64]; strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    va_start(args, fmt); vsnprintf(buf, sizeof(buf), fmt, args); va_end(args);
    printf("[%s] [INFO] %s\n", tbuf, buf);
}

void log_error(const char *fmt, ...) {
    char buf[1024]; va_list args;
    time_t now; time(&now); char tbuf[64]; strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    va_start(args, fmt); vsnprintf(buf, sizeof(buf), fmt, args); va_end(args);
    fprintf(stderr, "[%s] [ERROR] %s\n", tbuf, buf);
}

void hex2bin(const char *hex, uint8_t *bin, size_t len) {
    for(size_t i=0; i<len; i++) sscanf(hex+i*2, "%2hhx", &bin[i]);
}

void bin2hex(const uint8_t *bin, size_t len, char *hex) {
    for(size_t i=0; i<len; i++) sprintf(hex+i*2, "%02x", bin[i]);
}

void reverse_bytes(uint8_t *buf, size_t len) {
    for(size_t i=0; i<len/2; i++) {
        uint8_t t=buf[i]; buf[i]=buf[len-1-i]; buf[len-1-i]=t;
    }
}

void swap32_buffer(uint8_t *buf, size_t len) {
    for(size_t i=0; i<len; i+=4) {
        uint8_t t;
        t=buf[i]; buf[i]=buf[i+3]; buf[i+3]=t;
        t=buf[i+1]; buf[i+1]=buf[i+2]; buf[i+2]=t;
    }
}

uint32_t swap_uint32(uint32_t val) {
    return ((val>>24)&0xff) | ((val<<8)&0xff0000) | ((val>>8)&0xff00) | ((val<<24)&0xff000000);
}

// --- Base58 ---

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

int base58_decode(const char *str, uint8_t *out) {
    uint8_t buf[25] = {0};
    size_t len = strlen(str);
    for (size_t i = 0; i < len; ++i) {
        if (str[i] & 0x80) return 0;
        int carry = b58values[(int)str[i]];
        if (carry < 0) return 0;
        for (int j = 24; j >= 0; --j) {
            int val = buf[j] * 58 + carry;
            buf[j] = val & 0xff;
            carry = val >> 8;
        }
    }
    memcpy(out, buf, 25);
    return 1;
}

// --- Bech32 (Segwit) ---

uint32_t bech32_polymod_step(uint32_t pre) {
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

int convert_bits(uint8_t* out, size_t* outlen, int outbits, const uint8_t* in, size_t inlen, int inbits, int pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    size_t out_pos = 0;
    for (size_t i = 0; i < inlen; ++i) {
        val = (val << inbits) | in[i];
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[out_pos++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) {
            out[out_pos++] = (val << (outbits - bits)) & maxv;
        }
    } else if (((val << (outbits - bits)) & maxv) || bits >= inbits) {
        return 0;
    }
    *outlen = out_pos;
    return 1;
}

int segwit_addr_decode(int* witver, uint8_t* witprog, size_t* witprog_len, const char* hrp, const char* addr) {
    uint32_t chk = 1;
    size_t i;
    const char *data_part = NULL;
    
    size_t hrp_len = strlen(hrp);
    if (strncmp(addr, hrp, hrp_len) != 0) return 0;
    if (addr[hrp_len] != '1') return 0;
    data_part = addr + hrp_len + 1;
    
    for (i = 0; i < hrp_len; ++i) chk = bech32_polymod_step(chk) ^ (hrp[i] & 0x1f);
    
    size_t data_len = strlen(data_part);
    if (data_len < 6) return 0;
    
    uint8_t values[128]; 
    if (data_len > 127) return 0;

    chk = 1;
    for (i = 0; i < hrp_len; ++i) chk = bech32_polymod_step(chk) ^ (hrp[i] >> 5);
    chk = bech32_polymod_step(chk);
    for (i = 0; i < hrp_len; ++i) chk = bech32_polymod_step(chk) ^ (hrp[i] & 0x1f);

    for (i = 0; i < data_len; ++i) {
        int v = (int)data_part[i];
        if (v < 0 || v > 127) return 0;
        int8_t val = bech32_values[v];
        if (val == -1) return 0;
        values[i] = val;
        chk = bech32_polymod_step(chk) ^ val;
    }
    
    int spec = -1;
    if (chk == 1) spec = 1;
    else if (chk == 0x2bc830a3) spec = 2;
    else return 0;

    *witver = values[0];
    
    size_t prog_len_5bit = data_len - 1 - 6;
    if (!convert_bits(witprog, witprog_len, 8, values + 1, prog_len_5bit, 5, 0)) return 0;
    
    if (*witver == 0 && spec != 1) return 0;
    if (*witver != 0 && spec != 2) return 0;
    if (*witprog_len < 2 || *witprog_len > 40) return 0;
    
    return 1;
}

void address_to_script(const char *addr, char *script_hex) {
    // 1. Base58 (P2PKH / P2SH)
    if (addr[0] == '1' || addr[0] == '3' || addr[0] == 'm' || addr[0] == 'n' || addr[0] == '2') {
        uint8_t bin[25];
        if (base58_decode(addr, bin)) {
            uint8_t hash[20];
            memcpy(hash, bin + 1, 20); 
            
            if (addr[0] == '1' || addr[0] == 'm' || addr[0] == 'n') { // P2PKH
                sprintf(script_hex, "76a914");
                char h[41]; bin2hex(hash, 20, h);
                strcat(script_hex, h);
                strcat(script_hex, "88ac");
                log_info("Decoded Base58 P2PKH: %s", addr);
                return;
            } else if (addr[0] == '3' || addr[0] == '2') { // P2SH
                sprintf(script_hex, "a914");
                char h[41]; bin2hex(hash, 20, h);
                strcat(script_hex, h);
                strcat(script_hex, "87");
                log_info("Decoded Base58 P2SH: %s", addr);
                return;
            }
        }
    }
    
    // 2. Segwit (Bech32)
    if (strncmp(addr, "bc1", 3) == 0 || strncmp(addr, "tb1", 3) == 0 || strncmp(addr, "bcrt1", 5) == 0) {
        int witver;
        uint8_t witprog[40];
        size_t witprog_len = 40;
        
        const char *hrp = "bc"; 
        if (strncmp(addr, "tb1", 3) == 0) hrp = "tb";
        else if (strncmp(addr, "bcrt1", 5) == 0) hrp = "bcrt";
        
        if (segwit_addr_decode(&witver, witprog, &witprog_len, hrp, addr)) {
            if (witver == 0) sprintf(script_hex, "00");
            else sprintf(script_hex, "%02x", 0x50 + witver);
            
            char len_hex[4]; sprintf(len_hex, "%02x", (int)witprog_len);
            strcat(script_hex, len_hex);
            
            char prog_hex[81]; bin2hex(witprog, witprog_len, prog_hex);
            strcat(script_hex, prog_hex);
            
            log_info("Decoded Bech32 Segwit (v%d): %s", witver, addr);
            return;
        }
    }

    log_error("Failed to decode address: %s. Using BURN script (OP_RETURN).", addr);
    strcpy(script_hex, "6a");
}
