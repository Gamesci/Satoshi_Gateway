#ifndef BITCOIN_H
#define BITCOIN_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

typedef struct {
    char job_id[32];
    char prev_hash[65];
    char coinb1[2048];
    char coinb2[2048];
    char merkle_branch[20][65]; 
    int merkle_count;
    char version[9];
    char nbits[9];
    char ntime[9];
    uint32_t height;
    
    uint32_t version_int;
    uint32_t nbits_int;
    uint32_t ntime_int;
    
    char **tx_hexs;
    int tx_count;
    bool clean_jobs;
} Template;

int bitcoin_init();
void bitcoin_update_template(bool clean_jobs);
int bitcoin_reconstruct_and_submit(const char *job_id, const char *full_extranonce, const char *ntime, uint32_t nonce, uint32_t version_mask);

// 线程安全地获取当前任务副本 (用于新连接矿机)
bool bitcoin_get_current_job_copy(Template *out);

#endif
