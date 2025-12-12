#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>

// 现有的工具函数
void hex2bin(const char *hex, uint8_t *bin, size_t bin_len);
void bin2hex(const uint8_t *bin, size_t bin_len, char *hex);
void reverse_bytes(uint8_t *buf, size_t len);
uint32_t swap_uint32(uint32_t val);

// --- 新增：地址解码支持 ---

// Base58Check 解码 (用于 Legacy P2PKH/P2SH)
// 返回: >0 成功 (版本字节), -1 失败
int base58_decode_check(const char *str, uint8_t *payload, size_t *payload_len);

// SegWit Bech32/Bech32m 解码 (用于 P2WPKH/P2WSH/P2TR)
// 返回: 1 成功, 0 失败
int segwit_addr_decode(int* witver, uint8_t* witprog, size_t* witprog_len, const char* hrp, const char* addr);

#endif
