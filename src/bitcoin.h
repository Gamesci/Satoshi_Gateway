#ifndef BITCOIN_H
#define BITCOIN_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

// 任务历史深度：设置为 3
#define MAX_JOB_HISTORY 3

typedef struct {
    char job_id[32];
    bool valid;             // 该槽位是否有效
    
    // --- 核心数据 (Internal / Block Header Format - Little Endian) ---
    // 用于区块重构和哈希计算
    uint8_t prev_hash_bin[32]; 
    uint32_t version_val;
    uint32_t nbits_val;
    uint32_t curtime_val;
    uint32_t height;
    
    // --- Stratum 协议格式 (用于 mining.notify 发送) ---
    // 已经处理好字节序的字符串
    char prev_hash_stratum[65]; // Swap32 Hex
    char version_hex[9];        // BE Hex
    char nbits_hex[9];
    char ntime_hex[9];
    
    // --- Coinbase & Merkle ---
    char coinb1[4096];
    char coinb2[4096];
    char merkle_branch[20][65]; 
    int merkle_count;
    
    // --- 交易数据 (用于提交) ---
    char **tx_hexs;
    int tx_count;
    
    bool clean_jobs;
} Template;

// 初始化
int bitcoin_init();

// 轮询更新 GBT
void bitcoin_update_template(bool force_clean);

// 验证 Share 并提交 (返回: 0=无效, 1=有效低难度, 2=发现新块)
int bitcoin_validate_and_submit(const char *job_id, const char *full_extranonce, const char *ntime, uint32_t nonce, uint32_t version_mask);

// 获取最新任务副本 (用于矿机刚连接时)
bool bitcoin_get_latest_job(Template *out);

#endif
