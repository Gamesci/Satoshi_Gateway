#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <zmq.h>
#include "zmq_listener.h"
#include "config.h"
#include "bitcoin.h"
#include "utils.h"

void *zmq_thread(void *arg) {
    (void)arg;
    if (strlen(g_config.zmq_addr) == 0) {
        log_info("ZMQ disabled (no address configured). Using polling only.");
        return NULL;
    }

    void *context = zmq_ctx_new();
    void *subscriber = zmq_socket(context, ZMQ_SUB);
    
    int rc = zmq_connect(subscriber, g_config.zmq_addr);
    if (rc != 0) {
        log_error("ZMQ Connect Failed: %s", g_config.zmq_addr);
        return NULL;
    }

    zmq_setsockopt(subscriber, ZMQ_SUBSCRIBE, "hashblock", 9);
    
    log_info("ZMQ Listening on %s ...", g_config.zmq_addr);

    while (1) {
        zmq_msg_t topic;
        zmq_msg_init(&topic);
        int len = zmq_msg_recv(&topic, subscriber, 0);
        
        if (len != -1) {
            if (strncmp((char*)zmq_msg_data(&topic), "hashblock", 9) == 0) {
                zmq_msg_t payload;
                zmq_msg_init(&payload);
                zmq_msg_recv(&payload, subscriber, 0);
                
                log_info(">>> ZMQ: New Block Detected! Updating immediately. <<<");
                bitcoin_update_template(true);
                
                zmq_msg_close(&payload);
            }
        }
        zmq_msg_close(&topic);
    }
    
    zmq_close(subscriber);
    zmq_ctx_destroy(context);
    return NULL;
}

int zmq_listener_start() {
    pthread_t t;
    return pthread_create(&t, NULL, zmq_thread, NULL);
}
