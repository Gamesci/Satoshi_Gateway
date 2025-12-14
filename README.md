基于我们之前的深入代码分析和讨论，为您起草了一份适用于 GitHub 仓库的 `README.md`。

这份文档突出了 **Satoshi\_Gateway** 针对“家庭矿工”和“独立挖矿（Solo Mining）”的定位，同时也客观地指出了其架构特点和配置建议（特别是针对 Bitaxe 和 NerdMiner 的区别设置）。

-----

# Satoshi Gateway

**Satoshi Gateway** 是一个轻量级、开源的比特币 Stratum 挖矿网关，专为**家庭矿工**（Home Miners）和**独立挖矿**（Solo Mining）设计。

它充当比特币全节点（Bitcoin Core）与矿机之间的桥梁，通过 Stratum V1 协议将矿机连接到主网，支持从微型矿机（如 ESP32/NerdMiner）到高性能家用 ASIC（如 Bitaxe）的多种设备。

> **注意**：本项目定位为 MVP（最小可行性产品），旨在提供清晰、易读且功能完备的代码库，适合学习比特币协议或搭建私人矿池。如果您需要承载数万台矿机的大型矿池方案，建议参考 [Datum Gateway](https://github.com/OCEAN-xyz/datum_gateway)。

## 核心特性

  * **完全兼容主网**：正确实现 GBT (GetBlockTemplate) 协议，支持 SegWit (隔离见证) 和 BIP34 高度编码。
  * **Stratum V1 协议**：支持标准的挖矿协议，兼容市面上绝大多数矿机。
  * **ASICBoost 支持**：实现 Version Rolling 扩展，完美支持 Bitaxe 等现代 ASIC 设备的高效挖矿。
  * **VarDiff (动态难度)**：自动根据算力调整难度，确保从 50KH/s 到 100TH/s 的设备均可稳定连接。
  * **ZMQ 极速响应**：通过监听 Bitcoin Core 的 ZMQ 接口，毫秒级感知新区块诞生。
  * **轻量级架构**：代码精简（C语言），依赖少，适合部署在树莓派、闲置 PC 或云服务器上。

## 支持的硬件

Satoshi Gateway 经过测试，特别适合以下开源硬件：

  * **Bitaxe** (推荐): 基于 BM1366 等芯片的开源 ASIC 矿机。支持 Overt ASICBoost，运行极其稳定。
  * **NerdMiner / ESP32**: 基于微控制器的教学级矿机（需调整难度配置，见下文）。
  * **传统 ASIC**: 如 Antminer S9/S19 等（仅限小规模部署）。

## 安装与编译

### 依赖项

你需要安装 `cmake`, `libcurl`, `jansson` 和 `libzmq`。

**Ubuntu/Debian:**

```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake libcurl4-openssl-dev libjansson-dev libzmq3-dev git
```

### 编译步骤

```bash
git clone https://github.com/your-repo/satoshi_gateway.git
cd satoshi_gateway
mkdir build && cd build
cmake ..
make
```

## 配置说明

在运行之前，请复制 `config.json` 并根据你的环境进行修改。

```json
{
  "rpc_url": "http://127.0.0.1:8332",    // 比特币节点的 RPC 地址
  "rpc_user": "your_rpc_user",           // RPC 用户名
  "rpc_pass": "your_rpc_password",       // RPC 密码
  "zmq_pub_hashblock": "tcp://127.0.0.1:28332", // ZMQ 监听地址 (必须与比特币节点配置一致)
  
  "reward_address": "bc1q...",           // 【重要】你的比特币钱包地址，用于接收挖矿奖励
  "pool_tag": "/SatoshiGateway/",        // Coinbase 中的个性化标签
  
  "listen_port": 3333,                   // Stratum 服务监听端口
  
  "diff_asic": 1024,                     // 起始难度 (重要，见下文硬件适配)
  "vardiff_target_shares_min": 20        // VarDiff 目标每分钟提交的 Share 数量
}
```

### 针对不同硬件的配置建议

  * **Bitaxe (ASIC)**:

      * 保持默认配置 `diff_asic`: **1024** 或更高。
      * ASIC 算力较强，高难度可减少网络流量。

  * **NerdMiner (ESP32)**:

      * **必须修改** `diff_asic`: 设置为 **1**。
      * 原因：ESP32 算力极低（\~50KH/s），如果使用默认 1024 难度，可能几天都算不出一个 Share，导致连接超时断开。

## 运行

确保你的 Bitcoin Core 节点已完全同步，并且 `bitcoin.conf` 中开启了 server 模式和 zmq：

```ini
# bitcoin.conf
server=1
rpcuser=...
rpcpassword=...
zmqpubhashblock=tcp://127.0.0.1:28332
```

启动网关：

```bash
./satoshi_gateway -c config.json
```

## 架构说明

  * **线程模型**：采用 Thread-per-Client 模型。每个连接的矿机都会分配一个独立的系统线程。这对于家庭网络（几十台设备）完全没有问题，且代码逻辑简单易读，方便二次开发。
  * **空块策略**：当前版本在新区块发现时，会立即触发模板更新，但需等待 RPC 返回完整交易列表。相比工业级矿池（Empty Block Fast Send）可能有 1-2 秒的算力空转，但这对于 Solo 挖矿的影响微乎其微。

## 开发计划 (Roadmap)

  - [ ] 实现“空块速发”机制，进一步降低新块传播延迟。
  - [ ] 增加针对不同 UserAgent 的自动难度匹配（无需手动改配置）。
  - [ ] 增加 Web 监控面板。

## 许可证

本项目采用 MIT 许可证。详见 [LICENSE](https://www.google.com/search?q=LICENSE) 文件。

-----

**免责声明**：Solo 挖矿是一项靠运气的活动。使用 Satoshi Gateway 并不保证你能挖到区块。请确保你理解比特币挖矿的基本原理及风险。
