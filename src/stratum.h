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

// ShareLog Structure (for Last Shares)
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

    char extranonce1_hex[9];
    char last_job_id[STRATUM_JOBID_MAX];

    double current_diff;
    time_t last_retarget_time;
    int shares_in_window;
    
    // Stats
    double hashrate_est;
    time_t last_submit_time;
    uint64_t total_shares;
    
    // Track Best Share Difficulty per Worker
    double best_diff; 
} Client;

void stratum_send_mining_notify(int sock, Template *tmpl);
void stratum_broadcast_job(Template *tmpl);
int stratum_start_thread(void);

json_t* stratum_get_stats(void);

#endif
