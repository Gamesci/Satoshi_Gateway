#ifndef SHA256_WRAPPER_H
#define SHA256_WRAPPER_H
#include <stddef.h>
#include <stdint.h>

void sha256_double(const void *data, size_t len, uint8_t *output);
void sha256_single(const void *data, size_t len, uint8_t *output);
#endif
