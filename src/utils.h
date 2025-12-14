#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

void log_info(const char *fmt, ...);
void log_error(const char *fmt, ...);

// Strict hex helpers
bool hex2bin_checked(const char *hex, uint8_t *bin, size_t bin_len);
bool bin2hex_safe(const uint8_t *bin, size_t bin_len, char *hex, size_t hex_cap);

// Byte order helpers
void reverse_bytes(uint8_t *buf, size_t len);
void swap32_buffer(uint8_t *buf, size_t len);

void put_le16(uint8_t *p, uint16_t v);
void put_le32(uint8_t *p, uint32_t v);
void put_le64(uint8_t *p, uint64_t v);

// Hash helpers
void sha256d(const uint8_t *data, size_t len, uint8_t out32[32]);

// Address -> scriptPubKey (hex string). Returns false on failure.
bool address_to_script_checked(const char *addr, char *script_hex, size_t script_hex_cap);

#endif
