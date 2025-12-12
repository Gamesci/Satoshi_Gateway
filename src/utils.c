#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void hex2bin(const char *hex, uint8_t *bin, size_t bin_len) {
    for (size_t i = 0; i < bin_len; i++) {
        sscanf(hex + 2*i, "%2hhx", &bin[i]);
    }
}

void bin2hex(const uint8_t *bin, size_t bin_len, char *hex) {
    for (size_t i = 0; i < bin_len; i++) {
        sprintf(hex + 2*i, "%02x", bin[i]);
    }
}

void reverse_bytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len / 2; i++) {
        uint8_t temp = buf[i];
        buf[i] = buf[len - 1 - i];
        buf[len - 1 - i] = temp;
    }
}

uint32_t swap_uint32(uint32_t val) {
    return ((val >> 24) & 0xff) | ((val << 8) & 0xff0000) |
           ((val >> 8) & 0xff00) | ((val << 24) & 0xff000000);
}
