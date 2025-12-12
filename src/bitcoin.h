#ifndef BITCOIN_H
#define BITCOIN_H
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

#define MAX_JOB_HISTORY 3

typedef struct {
    char job_id[32];
    bool valid;
    uint8_t prev_hash_bin[32]; // Internal LE
    uint32_t version_val;
    uint32_t nbits_val;
    uint32_t curtime_val;
    uint32_t height;
    
    char prev_hash_stratum[65]; // Stratum Swap32 Hex
    char version_hex[9];        // Stratum Hex
    char nbits_hex[9];
    char ntime_hex[9];
    
    char coinb1[4096];
    char coinb2[4096];
    char merkle_branch[20][65]; 
    int merkle_count;
    char **tx_hexs;
    int tx_count;
    bool clean_jobs;
} Template;

int bitcoin_init();
void bitcoin_update_template(bool force_clean);
int bitcoin_validate_and_submit(const char *job_id, const char *full_extranonce, const char *ntime, uint32_t nonce, uint32_t version_mask);
bool bitcoin_get_latest_job(Template *out);
#endif
