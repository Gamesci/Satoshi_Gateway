# 第一阶段：编译环境
FROM debian:bookworm-slim AS builder

# 安装编译依赖 (新增 libzmq3-dev)
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libcurl4-openssl-dev \
    libjansson-dev \
    libssl-dev \
    libzmq3-dev \
    pkg-config

# 复制源代码
WORKDIR /app
COPY . .

# 编译
RUN mkdir build && cd build && \
    cmake .. && \
    make -j$(nproc)

# 第二阶段：运行环境 (极简)
FROM debian:bookworm-slim

# 安装运行时依赖 (新增 libzmq5)
# libcurl4, libjansson4, libssl3, libzmq5 是必须的动态库
RUN apt-get update && apt-get install -y \
    libcurl4 \
    libjansson4 \
    libssl3 \
    libzmq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root/

# 从第一阶段复制编译好的二进制文件
COPY --from=builder /app/build/satoshi_gateway .

# 容器启动命令
ENTRYPOINT ["./satoshi_gateway", "-c", "/root/config.json"]
