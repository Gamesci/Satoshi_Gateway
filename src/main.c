#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "config.h"
#include "bitcoin.h"
#include "stratum.h"

volatile sig_atomic_t g_block_notify = 0;
void handle_signal(int sig) { if(sig == SIGUSR1) g_block_notify = 1; }

int main(int argc, char *argv[]) {
    const char *conf_file = "config.json";
    if(argc > 2 && strcmp(argv[1], "-c") == 0) conf_file = argv[2];
    
    if(load_config(conf_file) != 0) return 1;
    
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigaction(SIGUSR1, &sa, NULL);
    
    if(bitcoin_init() != 0) return 1;
    if(stratum_start_thread() != 0) return 1;
    
    printf("Gateway running on %d. RPC: %s\n", g_config.stratum_port, g_config.rpc_url);
    
    bitcoin_update_template(true);
    time_t last_check = time(NULL);
    
    while(1) {
        if(g_block_notify) {
            printf("New Block! Refreshing...\n");
            g_block_notify = 0;
            bitcoin_update_template(true);
            last_check = time(NULL);
        }
        
        time_t now = time(NULL);
        if(now - last_check > g_config.poll_interval_sec) {
            bitcoin_update_template(false);
            last_check = now;
        }
        usleep(100000);
    }
    return 0;
}
