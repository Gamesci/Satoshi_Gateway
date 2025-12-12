#ifndef SHA256_WRAPPER_H
#define SHA256_WRAPPER_H

#include <stddef.h>
#include <stdint.h>

// 双重 SHA256: output = SHA256(SHA256(data))
void sha256_double(const void *data, size_t len, uint8_t *output);

// 单次 SHA256
void sha256_single(const void *data, size_t len, uint8_t *output);

#endif
