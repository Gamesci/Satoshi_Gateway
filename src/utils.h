#ifndef UTILS_H
#define UTILS_H
#include <stdint.h>
#include <stddef.h>

void hex2bin(const char *hex, uint8_t *bin, size_t bin_len);
void bin2hex(const uint8_t *bin, size_t bin_len, char *hex);
void reverse_bytes(uint8_t *buf, size_t len); // 大小端转换
uint32_t swap_uint32(uint32_t val);
#endif
