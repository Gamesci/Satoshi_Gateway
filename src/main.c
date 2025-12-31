#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "config.h"
#include "bitcoin.h"
#include "stratum.h"
#include "utils.h"
#include "zmq_listener.h"
#include "web.h"
#include "p2p.h"

volatile sig_atomic_t g_block_notify = 0;
static void handle_signal(int sig) { if (sig == SIGUSR1) g_block_notify = 1; }

int main(int argc, char *argv[]) {
    setbuf(stdout, NULL);

    const char *conf_file = "config.json";
    if (argc > 2 && strcmp(argv[1], "-c") == 0) conf_file = argv[2];

    log_info("Starting Satoshi Gateway (Production)...");
    if (load_config(conf_file) != 0) {
        log_error("Config load failed.");
        return 1;
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGUSR1, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    if (bitcoin_init() != 0) return 1;
    if (stratum_start_thread() != 0) return 1;

    // 1. Start ZMQ (Updates template reliably but with latency)
    zmq_listener_start();
    
    // 2. Start Web
    web_server_start(8080); 

    log_info("Gateway ready on port %d.", g_config.stratum_port);

    // 3. First RPC Sync (Get initial block template & Height)
    log_info("Performing initial RPC sync...");
    bitcoin_update_template(true);
    time_t last_check = time(NULL);

    // 4. Get Current Height for P2P Handshake
    uint32_t current_height = 0;
    bitcoin_get_telemetry(&current_height, NULL, NULL);
    if (current_height == 0) {
        log_error("Warning: Initial RPC failed, P2P will start with height 0 (Slow push)");
    }

    // 5. Start P2P Listener (Now that we know the height)
    log_info("Starting P2P with initial height: %d", current_height);
    p2p_start_thread(g_config.p2p_host, g_config.p2p_port, g_config.p2p_magic, (int32_t)current_height);

    while (1) {
        if (g_block_notify) {
            log_info("Signal: new block (ZMQ/RPC)");
            g_block_notify = 0;
            bitcoin_update_template(true);
            last_check = time(NULL);
        }

        time_t now = time(NULL);
        if (now - last_check > g_config.poll_interval_sec) {
            bitcoin_update_template(false);
            last_check = now;
        }
        usleep(100000);
    }
    return 0;
}
