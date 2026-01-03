#ifndef STRATUM_H
#define STRATUM_H

#include <netinet/in.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>
#include <jansson.h>
#include "bitcoin.h"

#define MAX_CLIENTS 1024
#define STRATUM_JOBID_MAX 64

// ShareLog 结构 (用于 Last Shares 列表)
typedef struct {
    char worker_ex1[9];
    double difficulty;
    char share_hash[65];
    time_t timestamp;
    bool is_block; 
} ShareLog;

typedef struct {
    int id;
    int sock;
    struct sockaddr_in addr;
    bool active;
    bool is_authorized;
    pthread_t thread_id;

    char extranonce1_hex[17];
    char last_job_id[STRATUM_JOBID_MAX];

    double current_diff;
    double previous_diff; 
    time_t last_retarget_time;
    int shares_in_window;
    
    // Stats
    double hashrate_est;
    time_t last_submit_time;
    uint64_t total_shares;
    double best_diff; 
    
    char user_agent[128];
    int coinbase_variant; 
} Client;

void stratum_broadcast_job(Template *tmpl);
int stratum_start_thread(void);
void stratum_send_mining_notify(int sock, Template *tmpl);

// [NEW] API for Eco Mode
int stratum_get_client_count(void);

#endif
