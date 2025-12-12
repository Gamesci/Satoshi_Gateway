#ifndef SHA256_H
#define SHA256_H
#include <stdint.h>
#include <stddef.h>
void sha256_double(const void *data, size_t len, uint8_t *output);
void sha256_single(const void *data, size_t len, uint8_t *output);
#endif
