#include "sha256.h"
#include <openssl/sha.h>
void sha256_double(const void *data, size_t len, uint8_t *output) {
    uint8_t hash1[SHA256_DIGEST_LENGTH]; SHA256(data, len, hash1); SHA256(hash1, SHA256_DIGEST_LENGTH, output);
}
void sha256_single(const void *data, size_t len, uint8_t *output) { SHA256(data, len, output); }
