#ifndef BITCOIN_H
#define BITCOIN_H
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    char job_id;
    char prev_hash;
    char bits;
    uint32_t version;
    uint32_t curtime;
    uint32_t height;
    int64_t coinbase_value;
    bool clean_jobs;
    // 实际实现需要存储 coinbase 交易部分和 merkle branches
} Template;

int bitcoin_init();
void bitcoin_update_template(bool clean_jobs);
int bitcoin_submit_block(const char *hex_data);

#endif
