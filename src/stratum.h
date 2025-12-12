#ifndef STRATUM_H
#define STRATUM_H
#include "bitcoin.h"
#include <netinet/in.h>
#define MAX_CLIENTS 64
typedef struct {
    int sock; struct sockaddr_in addr; int id;
    char extranonce1_hex[16]; bool is_authorized; bool active; pthread_t thread_id;
} Client;
int stratum_start_thread();
void stratum_broadcast_job(Template *tmpl);
#endif
