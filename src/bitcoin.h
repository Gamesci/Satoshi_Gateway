#ifndef BITCOIN_H
#define BITCOIN_H

#include <stdbool.h>
#include <stdint.h>

#define MAX_JOB_HISTORY 3

typedef struct {
    char job_id[32];
    char prev_hash_stratum[65]; // for stratum (swapped)
    uint8_t prev_hash_bin[32];  // for block (LE)
    char coinb1[8192];
    char coinb2[8192];
    char merkle_branch[16][65];
    int merkle_count;
    char version_hex[9];
    uint32_t version_val;
    char nbits_hex[9];
    uint32_t nbits_val;
    char ntime_hex[9];
    uint32_t curtime_val;
    bool clean_jobs;
    bool valid;
    
    // Internal
    uint32_t height;
    int64_t coinbase_value;
    char **tx_hexs;
    size_t tx_count;
} Template;

int bitcoin_init();
void bitcoin_update_template(bool force_clean);
bool bitcoin_get_latest_job(Template *out);
int bitcoin_validate_and_submit(const char *job_id, const char *full_extranonce, const char *ntime, uint32_t nonce, uint32_t version_bits);

#endif
