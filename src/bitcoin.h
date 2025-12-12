#ifndef BITCOIN_H
#define BITCOIN_H
#include <stdbool.h>
#include <stdint.h>
#include <jansson.h>

typedef struct {
    char job_id[32];
    char prev_hash[65];     // Hex (Little Endian for Stratum)
    char coinb1[1024];      // Coinbase Part 1
    char coinb2[1024];      // Coinbase Part 2
    
    // Merkle Branch for Stratum (最多 20 层足以支持 >1MB 的交易列表)
    char merkle_branch[20][65]; 
    int merkle_count;
    
    // Block Header info
    char version[9];
    char nbits[9];
    char ntime[9];
    uint32_t height;
    uint32_t version_int;   // 原始整数版本，便于位运算
    uint32_t nbits_int;
    uint32_t ntime_int;
    
    // 原始交易数据缓存 (用于提交区块)
    char **tx_hexs;         // 交易原始 Hex 列表
    int tx_count;           // 交易数量 (不含 Coinbase)
    
    bool clean_jobs;
} Template;

int bitcoin_init();
void bitcoin_cleanup(); // 新增清理函数
void bitcoin_update_template(bool clean_jobs);

// 修改：需要传入构建区块所需的参数
int bitcoin_reconstruct_and_submit(const char *job_id, const char *extranonce2, const char *ntime, uint32_t nonce, uint32_t version_mask);

#endif
