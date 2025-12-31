#ifndef BITCOIN_H
#define BITCOIN_H

#include <stdint.h>
#include <stdbool.h>
#include <jansson.h>

#define MAX_JOB_HISTORY 16

#define MAX_COINBASE_VARIANTS 3
#define CB_VARIANT_DEFAULT 0
#define CB_VARIANT_WHATSMINER 1
#define CB_VARIANT_NICEHASH 2

typedef struct {
    bool valid;
    bool clean_jobs;
    
    char job_id[32];
    uint32_t height;
    
    uint32_t version_val;
    char version_hex[9];
    uint32_t nbits_val;
    char nbits_hex[9];
    uint32_t curtime_val;
    char ntime_hex[9];
    
    uint8_t prevhash_le[32];
    char prev_hash_stratum[65];
    
    size_t tx_count;
    uint8_t (*txids_le)[32];
    char **tx_hexs;
    
    size_t merkle_count;
    char **merkle_branch;
    
    int64_t coinbase_value;
    bool has_segwit;
    
    char coinb1[MAX_COINBASE_VARIANTS][4096];
    char coinb2[MAX_COINBASE_VARIANTS][4096];
    
} Template;

int bitcoin_init(void);
void bitcoin_free_job(Template *t);
bool bitcoin_get_latest_job(Template *out);
void bitcoin_update_template(bool force_clean);

// [NEW] Fast Block Switch Trigger
void bitcoin_fast_new_block(const uint8_t *header_80_bytes);

int bitcoin_validate_and_submit(const char *job_id,
                                const char *full_extranonce_hex,
                                const char *ntime_hex,
                                uint32_t nonce,
                                uint32_t version_bits,
                                double diff,
                                double *share_diff);

void bitcoin_get_telemetry(uint32_t *height, int64_t *reward, double *difficulty);

#endif
