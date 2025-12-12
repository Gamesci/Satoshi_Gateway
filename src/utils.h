#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>

void log_info(const char *format, ...);
void log_error(const char *format, ...);
void log_debug(const char *format, ...);

void hex2bin(const char *hex, uint8_t *bin, size_t bin_len);
void bin2hex(const uint8_t *bin, size_t bin_len, char *hex);

// 字节序处理
void reverse_bytes(uint8_t *buf, size_t len); // 全反转
void swap32_buffer(uint8_t *buf, size_t len); // 新增：按4字节一组反转 (Stratum PrevHash)
uint32_t swap_uint32(uint32_t val);

int base58_decode_check(const char *str, uint8_t *payload, size_t *payload_len);
int segwit_addr_decode(int* witver, uint8_t* witprog, size_t* witprog_len, const char* hrp, const char* addr);
void address_to_script(const char *addr, char *script_hex);

#endif
