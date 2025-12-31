#ifndef P2P_H
#define P2P_H

#include <stdint.h>
#include <stdbool.h>

/**
 * 启动 P2P 监听线程
 * @param ip 比特币节点 IP (如 "127.0.0.1")
 * @param port P2P 端口 (主网 8333, Testnet 18333)
 * @param magic 网络魔数 (主网 0xD9B4BEF9)
 */
int p2p_start_thread(const char *ip, int port, uint32_t magic);

#endif
