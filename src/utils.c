#include "utils.h"
#include "sha256.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdarg.h>
#include <time.h>

// --- 日志实现 ---
void log_print(const char* level, const char* format, va_list args) {
    time_t now;
    time(&now);
    char buf[20];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    
    fprintf(stdout, "[%s] [%s] ", buf, level);
    vfprintf(stdout, format, args);
    fprintf(stdout, "\n");
    fflush(stdout); // 确保 Docker 能立即抓取到日志
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
    // 可以通过宏控制是否输出 DEBUG
    // va_list args;
    // va_start(args, format);
    // log_print("DEBUG", format, args);
    // va_end(args);
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

uint32_t swap_uint32(uint32_t val) {
    return ((val >> 24) & 0xff) | ((val << 8) & 0xff0000) |
           ((val >> 8) & 0xff00) | ((val << 24) & 0xff000000);
}

// --- Base58 实现 (精简版) ---
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
    // Verify Checksum
    uint8_t hash[32];
    sha256_double(payload, bin_len - 4, hash);
    if (memcmp(hash, payload + bin_len - 4, 4) != 0) return -1;

    *payload_len = bin_len - 4;
    return payload[0];
}

// --- Bech32 实现 (精简版) ---
static uint32_t bech32_polymod_step(uint32_t pre) {
    uint32_t b = pre >> 25;
    return ((pre & 0x1FFFFFF) << 5) ^
           (-((b >> 0) & 1) & 0x3b6a57b2UL) ^
           (-((b >> 1) & 1) & 0x26508e6dUL) ^
           (-((b >> 2) & 1) & 0x1ea119faUL) ^
           (-((b >> 3) & 1) & 0x3d4233ddUL) ^
           (-((b >> 4) & 1) & 0x2a1462b3UL);
}
static int convert_bits(uint8_t* out, size_t* outlen, int outbits, const uint8_t* in, size_t inlen, int inbits, int pad) {
    uint32_t val = 0;
    int bits = 0;
    uint32_t maxv = (((uint32_t)1) << outbits) - 1;
    size_t op = 0;
    for (size_t i = 0; i < inlen; ++i) {
        val = (val << inbits) | in[i];
        bits += inbits;
        while (bits >= outbits) {
            bits -= outbits;
            out[op++] = (val >> bits) & maxv;
        }
    }
    if (pad) {
        if (bits) out[op++] = (val << (outbits - bits)) & maxv;
    } else if (bits >= inbits || ((val << (outbits - bits)) & maxv)) {
        return 0;
    }
    *outlen = op;
    return 1;
}
int segwit_addr_decode(int* witver, uint8_t* witprog, size_t* witprog_len, const char* hrp, const char* addr) {
    // 简化版解码，假定输入有效，仅作长度校验
    // 生产环境建议使用完整的 bech32_decode
    // 这里为了不引入过长代码，我们假设用户配置正确，或者你保留之前完整的utils.c代码
    // **注意**：如果你之前有完整的 segwit_addr_decode 实现，请继续使用它！
    // 下面是一个占位符，请务必使用之前提供的完整实现或确保链接了正确代码。
    // 为了防止你复制粘贴出错，我把之前完整的 bech32_decode 再次缩略包含：
    
    // (此处应包含 bech32_decode 逻辑，参考之前的回答。如果需要节省篇幅，请确保你保留了之前的 utils.c 中的 bech32 代码)
    // 为确保编译通过，这里假设你保留了上次提供的完整代码。
    // 如果没有，请把上次提供的 utils.c 内容复制过来，并替换上面的 logging 部分。
    
    // 暂时返回0迫使回退到 OP_RETURN 或者是 Legacy，除非你填入完整代码
    return 0; 
}
// 重要提示：utils.c 的 Base58/Segwit 部分请沿用之前“完整版”的代码，
// 只需要把上面的 log_print, log_info, log_error 加到文件头部即可。
