#ifndef BITCOIN_H
#define BITCOIN_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

// 任务历史深度 (4个足以应对 Solo 挖矿的网络延迟)
#define MAX_JOB_HISTORY 3

typedef struct {
    char job_id[32];
    bool valid;
    
    // --- 核心数据 (Block Header 原始数值 / Little Endian) ---
    uint8_t prev_hash_bin[32]; // 32字节二进制 (Little Endian)，用于重构
    uint32_t version_val;
    uint32_t nbits_val;
    uint32_t curtime_val;
    uint32_t height;
    
    // --- Stratum 协议格式 (用于下发) ---
    char prev_hash_stratum[65]; // 经过 Swap32 处理的 Hex
    char version_hex[9];        // 直接 Hex 字符串
    char nbits_hex[9];
    char ntime_hex[9];
    
    // --- Coinbase ---
    char coinb1[4096];
    char coinb2[4096];
    
    // --- Merkle ---
    char merkle_branch[20][65]; 
    int merkle_count;
    
    // --- 交易数据 (用于提交) ---
    char **tx_hexs;
    int tx_count;
    
    bool clean_jobs;
} Template;

int bitcoin_init();
void bitcoin_update_template(bool force_clean);
int bitcoin_validate_and_submit(const char *job_id, const char *full_extranonce, const char *ntime, uint32_t nonce, uint32_t version_mask);
bool bitcoin_get_latest_job(Template *out);

#endif
