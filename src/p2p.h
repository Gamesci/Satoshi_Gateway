#ifndef P2P_H
#define P2P_H

#include <stdint.h>
#include <stdbool.h>

/**
 * 启动 P2P 监听线程
 * @param host 比特币节点 IP 或域名
 * @param port P2P 端口
 * @param magic 网络魔数
 * @param start_height 当前区块高度 (用于告知节点我们也已同步，请求实时推送)
 */
int p2p_start_thread(const char *host, int port, uint32_t magic, int32_t start_height);

#endif
