#ifndef BITCOIN_H
#define BITCOIN_H
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    char job_id[32];
    char prev_hash[65];     // Hex string (Little Endian for Stratum)
    char coinb1[1024];      // Hex string
    char coinb2[1024];      // Hex string
    char merkle_branch[20][65]; // Merkle path (Hex)
    int merkle_count;
    char version[9];        // Hex string
    char nbits[9];          // Hex string
    char ntime[9];          // Hex string
    uint32_t height;
    bool clean_jobs;
    uint32_t target_bits;   // int representation of nbits
} Template;

int bitcoin_init();
void bitcoin_update_template(bool clean_jobs);
int bitcoin_submit_block(const char *hex_data);
#endif
