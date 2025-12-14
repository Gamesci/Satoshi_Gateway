#ifndef BITCOIN_H
#define BITCOIN_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_JOB_HISTORY 8

typedef struct {
    char job_id[32];

    // Stratum notify fields
    char prev_hash_stratum[65]; // 32 bytes, "stratum format" (swap32 over LE prevhash)
    char coinb1[8192];
    char coinb2[8192];

    // merkle_branch: siblings for coinbase path
    // stored as hex of 32-byte LITTLE-ENDIAN hash (standard for Stratum)
    char **merkle_branch;     // array of hex strings, each 64 chars + '\0'
    size_t merkle_count;

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

    // Non-coinbase txids in LITTLE-ENDIAN bytes
    uint8_t (*txids_le)[32];
    size_t tx_count;

    // For building block when found
    char **tx_hexs;           // raw tx hex (as given by GBT "data")
} Template;

int bitcoin_init(void);
void bitcoin_update_template(bool force_clean);

/**
 * Returns a deep-copied snapshot suitable for mining.notify sending.
 * Caller must free with bitcoin_job_free().
 */
bool bitcoin_get_latest_job(Template *out);

/**
 * Free a Template snapshot produced by bitcoin_get_latest_job or internal job storage.
 * Safe to call on partially-filled templates.
 */
void bitcoin_free_job(Template *t);

/**
 * Validate share against per-connection difficulty and submit block if found.
 * Returns:
 * 0 = rejected (stale/invalid/low diff)
 * 1 = share accepted
 * 2 = block found and submitted (submitblock accepted)
 */
int bitcoin_validate_and_submit(const char *job_id,
                                const char *full_extranonce_hex,
                                const char *ntime_hex,
                                uint32_t nonce,
                                uint32_t version_bits,
                                double diff);

#endif
