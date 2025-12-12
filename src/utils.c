#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include "utils.h"

void log_info(const char *fmt, ...) {
    char buf[1024]; va_list args;
    time_t now; time(&now); char tbuf[64]; strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    va_start(args, fmt); vsnprintf(buf, sizeof(buf), fmt, args); va_end(args);
    printf("[%s] [INFO] %s\n", tbuf, buf);
}

void log_error(const char *fmt, ...) {
    char buf[1024]; va_list args;
    time_t now; time(&now); char tbuf[64]; strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    va_start(args, fmt); vsnprintf(buf, sizeof(buf), fmt, args); va_end(args);
    fprintf(stderr, "[%s] [ERROR] %s\n", tbuf, buf);
}

void hex2bin(const char *hex, uint8_t *bin, size_t len) {
    for(size_t i=0; i<len; i++) {
        sscanf(hex+i*2, "%2hhx", &bin[i]);
    }
}

void bin2hex(const uint8_t *bin, size_t len, char *hex) {
    for(size_t i=0; i<len; i++) sprintf(hex+i*2, "%02x", bin[i]);
}

void reverse_bytes(uint8_t *buf, size_t len) {
    for(size_t i=0; i<len/2; i++) {
        uint8_t t=buf[i]; buf[i]=buf[len-1-i]; buf[len-1-i]=t;
    }
}

void swap32_buffer(uint8_t *buf, size_t len) {
    for(size_t i=0; i<len; i+=4) {
        uint8_t t;
        t=buf[i]; buf[i]=buf[i+3]; buf[i+3]=t;
        t=buf[i+1]; buf[i+1]=buf[i+2]; buf[i+2]=t;
    }
}

uint32_t swap_uint32(uint32_t val) {
    return ((val>>24)&0xff) | ((val<<8)&0xff0000) | ((val>>8)&0xff00) | ((val<<24)&0xff000000);
}
