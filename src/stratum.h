#ifndef STRATUM_H
#define STRATUM_H

#include <netinet/in.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>
#include "bitcoin.h"

#define MAX_CLIENTS 1024

typedef struct {
    int id;
    int sock;
    struct sockaddr_in addr;
    bool active;
    bool is_authorized;
    pthread_t thread_id;
    char extranonce1_hex[10];
    
    // VarDiff Stats
    double current_diff;
    time_t last_retarget_time;
    int shares_in_window;
} Client;

void stratum_send_mining_notify(int sock, Template *tmpl);
int stratum_start_thread();

#endif
