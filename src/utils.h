#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>

// 日志系统
void log_info(const char *format, ...);
void log_error(const char *format, ...);
void log_debug(const char *format, ...);

// Hex 与 字节处理
void hex2bin(const char *hex, uint8_t *bin, size_t bin_len);
void bin2hex(const uint8_t *bin, size_t bin_len, char *hex);
void reverse_bytes(uint8_t *buf, size_t len);
uint32_t swap_uint32(uint32_t val);

// 地址解码支持
int base58_decode_check(const char *str, uint8_t *payload, size_t *payload_len);
int segwit_addr_decode(int* witver, uint8_t* witprog, size_t* witprog_len, const char* hrp, const char* addr);

#endif
