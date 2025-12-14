#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <zmq.h>

#include "zmq_listener.h"
#include "config.h"
#include "bitcoin.h"
#include "utils.h"

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

        if (len >= 9 && strncmp((char*)zmq_msg_data(&topic), "hashblock", 9) == 0) {
            zmq_msg_t payload;
            zmq_msg_init(&payload);
            int len2 = zmq_msg_recv(&payload, subscriber, 0);
            if (len2 != -1) {
                log_info("ZMQ: new block detected, updating template");
                bitcoin_update_template(true);
            }
            zmq_msg_close(&payload);
        }

        zmq_msg_close(&topic);
    }

    // unreachable
    zmq_close(subscriber);
    zmq_ctx_destroy(context);
    return NULL;
}

int zmq_listener_start(void) {
    pthread_t t;
    return pthread_create(&t, NULL, zmq_thread, NULL);
}
