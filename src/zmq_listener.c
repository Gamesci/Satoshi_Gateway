#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <zmq.h>

#include "zmq_listener.h"
#include "config.h"
#include "bitcoin.h"
#include "utils.h"

// [优化] 辅助函数：排空积压的 ZMQ 消息
// 返回值：排空（丢弃）的消息数量
static int drain_backlog(void *subscriber) {
    int drained_count = 0;
    while (1) {
        zmq_msg_t topic;
        zmq_msg_init(&topic);
        
        // 非阻塞接收：如果没有消息立即返回 -1
        if (zmq_msg_recv(&topic, subscriber, ZMQ_DONTWAIT) == -1) {
            zmq_msg_close(&topic);
            break; // 队列已空
        }
        
        // 发现积压消息，读取并丢弃它的剩余部分（Payload + Seq）
        // 必须读完 multipart 消息的每一帧，否则 ZMQ 状态机错乱
        int more = 0;
        size_t more_size = sizeof(more);
        zmq_getsockopt(subscriber, ZMQ_RCVMORE, &more, &more_size);
        
        while (more) {
            zmq_msg_t part;
            zmq_msg_init(&part);
            zmq_msg_recv(&part, subscriber, 0); // 这里必须用阻塞读取确保读完完整帧
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

    // 设置高水位线，防止处理不过来时内存溢出
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
        
        // 1. 阻塞等待：这里是主循环的停车点，没有新块时 CPU 占用为 0
        int len = zmq_msg_recv(&topic, subscriber, 0);
        if (len == -1) {
            zmq_msg_close(&topic);
            continue;
        }

        // 检查是否为 hashblock 消息
        bool is_hashblock = (len >= 9 && strncmp((char*)zmq_msg_data(&topic), "hashblock", 9) == 0);

        // 2. 消费当前消息的剩余部分（确保 multipart 完整读取）
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

        // 3. 业务处理逻辑
        if (is_hashblock) {
            log_info("ZMQ: New block detected, triggering update...");
            
            // 循环处理机制：
            // 如果在 bitcoin_update_template 执行期间又来了新块（积压），
            // 我们会排空它们，然后再更新一次，确保拿到最新的。
            int burst_count = 0;
            do {
                if (burst_count > 0) {
                    log_info("ZMQ: Coalesced %d buffered events (Anti-Storm active)", burst_count);
                }
                
                // 执行重型 RPC 操作
                bitcoin_update_template(true);
                
                // 检查并排空在 RPC 期间堆积的消息
                burst_count = drain_backlog(subscriber);
                
            } while (burst_count > 0); // 如果有积压，说明我们可能不是最新的，再循环一次
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
