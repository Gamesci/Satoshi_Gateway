#ifndef UTILS_H
#define UTILS_H

#include <stdint.h>
#include <stddef.h>

void log_info(const char *fmt, ...);
void log_error(const char *fmt, ...);
void hex2bin(const char *hex, uint8_t *bin, size_t len);
void bin2hex(const uint8_t *bin, size_t len, char *hex);
void reverse_bytes(uint8_t *buf, size_t len);
void swap32_buffer(uint8_t *buf, size_t len);
uint32_t swap_uint32(uint32_t val);

void address_to_script(const char *addr, char *script_hex);

#endif
