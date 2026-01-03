#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <zmq.h>

#include "zmq_listener.h"
#include "config.h"
#include "bitcoin.h"
#include "utils.h"
#include "stratum.h" // [NEW] Need for Eco check

static int drain_backlog(void *subscriber) {
    int drained_count = 0;
    while (1) {
        zmq_msg_t topic;
        zmq_msg_init(&topic);
        if (zmq_msg_recv(&topic, subscriber, ZMQ_DONTWAIT) == -1) {
            zmq_msg_close(&topic);
            break;
        }
        int more = 0;
        size_t more_size = sizeof(more);
        zmq_getsockopt(subscriber, ZMQ_RCVMORE, &more, &more_size);
        while (more) {
            zmq_msg_t part;
            zmq_msg_init(&part);
            zmq_msg_recv(&part, subscriber, 0); 
            zmq_getsockopt(subscriber, ZMQ_RCVMORE, &more, &more_size);
            zmq_msg_close(&part);
        }
        zmq_msg_close(&topic);
        drained_count++;
    }
    return drained_count;
}

static void *zmq_thread(void *arg) {
    (void)arg;

    if (strlen(g_config.zmq_addr) == 0) {
        log_info("ZMQ disabled (no address configured). Using polling only.");
        return NULL;
    }

    void *context = zmq_ctx_new();
    if (!context) {
        log_error("ZMQ ctx init failed");
        return NULL;
    }

    void *subscriber = zmq_socket(context, ZMQ_SUB);
    if (!subscriber) {
        log_error("ZMQ socket create failed");
        zmq_ctx_destroy(context);
        return NULL;
    }

    int hwm = 1000;
    zmq_setsockopt(subscriber, ZMQ_RCVHWM, &hwm, sizeof(hwm));

    if (zmq_connect(subscriber, g_config.zmq_addr) != 0) {
        log_error("ZMQ connect failed: %s", g_config.zmq_addr);
        zmq_close(subscriber);
        zmq_ctx_destroy(context);
        return NULL;
    }

    zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, "hashblock", 9);
    log_info("ZMQ listening on %s", g_config.zmq_addr);

    while (1) {
        zmq_msg_t topic;
        zmq_msg_init(&topic);
        
        int len = zmq_msg_recv(&topic, subscriber, 0);
        if (len == -1) {
            zmq_msg_close(&topic);
            continue;
        }

        bool is_hashblock = (len >= 9 && strncmp((char*)zmq_msg_data(&topic), "hashblock", 9) == 0);

        int more = 0;
        size_t more_size = sizeof(more);
        zmq_getsockopt(subscriber, ZMQ_RCVMORE, &more, &more_size);
        while (more) {
            zmq_msg_t part;
            zmq_msg_init(&part);
            zmq_msg_recv(&part, subscriber, 0);
            zmq_getsockopt(subscriber, ZMQ_RCVMORE, &more, &more_size);
            zmq_msg_close(&part);
        }
        zmq_msg_close(&topic);

        if (is_hashblock) {
            // [ECO MODE] Check
            if (stratum_get_client_count() == 0) {
                log_info("ZMQ: Block detected but ignored (Eco Mode)");
                drain_backlog(subscriber);
                continue;
            }

            log_info("ZMQ: New block detected, triggering update...");
            
            // Anti-Avalanche
            int burst_count = 0;
            do {
                if (burst_count > 0) {
                    log_info("ZMQ: Coalesced %d buffered events", burst_count);
                }
                
                bitcoin_update_template(true);
                
                burst_count = drain_backlog(subscriber);
                
            } while (burst_count > 0);
        }
    }

    zmq_close(subscriber);
    zmq_ctx_destroy(context);
    return NULL;
}

int zmq_listener_start(void) {
    pthread_t t;
    return pthread_create(&t, NULL, zmq_thread, NULL);
}
