#ifndef BITCOIN_H
#define BITCOIN_H

#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>

// 模板结构：缓存构建区块所需的所有原材料
typedef struct {
    char job_id[32];
    char prev_hash[65];     // Hex (为 Stratum 协议调整过的字节序)
    char coinb1[2048];      // Coinbase 交易前半部分
    char coinb2[2048];      // Coinbase 交易后半部分
    
    // Merkle Branch (Stratum V1 格式)
    char merkle_branch[20][65]; 
    int merkle_count;
    
    // 区块头基础信息
    char version[9];
    char nbits[9];
    char ntime[9];
    uint32_t height;
    
    // 原始整数值 (用于计算)
    uint32_t version_int;
    uint32_t nbits_int;
    uint32_t ntime_int;
    
    // 原始交易数据缓存 (用于重构区块提交)
    char **tx_hexs;         // 交易原始 Hex 列表 (不含 Coinbase)
    int tx_count;           // 交易数量
    
    bool clean_jobs;
} Template;

// 初始化 CURL
int bitcoin_init();

// 从节点获取新模板并广播
void bitcoin_update_template(bool clean_jobs);

/**
 * 重构并提交区块
 * @param job_id 任务ID
 * @param full_extranonce 完整的 ExtraNonce (Extranonce1 + Extranonce2)
 * @param ntime 矿机提交的时间戳
 * @param nonce 矿机提交的 Nonce
 * @param version_mask 矿机提交的版本位 (用于 ASICBoost/VersionRolling)，若无则为0
 */
int bitcoin_reconstruct_and_submit(const char *job_id, const char *full_extranonce, const char *ntime, uint32_t nonce, uint32_t version_mask);

#endif
