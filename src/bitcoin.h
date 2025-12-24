#ifndef BITCOIN_H
#define BITCOIN_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <jansson.h> // 新增

#define MAX_JOB_HISTORY 16

typedef struct {
    char job_id[32];
    char prev_hash_stratum[65]; 
    char coinb1[8192];
    char coinb2[8192];
    char **merkle_branch;
    size_t merkle_count;
    char version_hex[9];
    uint32_t version_val;
    char nbits_hex[9];
    uint32_t nbits_val;
    char ntime_hex[9];
    uint32_t curtime_val;
    bool clean_jobs;
    bool valid;
    uint32_t height;
    int64_t coinbase_value;
    bool has_segwit;
    uint8_t prevhash_le[32];
    uint8_t (*txids_le)[32];
    size_t tx_count;
    char **tx_hexs;
} Template;

int bitcoin_init(void);
void bitcoin_update_template(bool force_clean);
bool bitcoin_get_latest_job(Template *out);
void bitcoin_free_job(Template *t);

int bitcoin_validate_and_submit(const char *job_id,
                                const char *full_extranonce_hex,
                                const char *ntime_hex,
                                uint32_t nonce,
                                uint32_t version_bits,
                                double diff);

// 新增：获取当前的区块元数据供 API 使用
void bitcoin_get_telemetry(uint32_t *height, int64_t *reward, uint32_t *difficulty);

#endif
