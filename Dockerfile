# 第一阶段：编译环境
FROM debian:bookworm-slim AS builder

# 安装编译依赖
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libcurl4-openssl-dev \
    libjansson-dev \
    libssl-dev \
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

# 安装运行时依赖 (必须包含 libcurl, jansson, openssl)
RUN apt-get update && apt-get install -y \
    libcurl4 \
    libjansson4 \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root/

# 从第一阶段复制编译好的二进制文件
COPY --from=builder /app/build/satoshi_gateway .

# 容器启动命令
# 默认读取 /root/config.json，这与 docker-compose 的挂载路径一致
ENTRYPOINT ["./satoshi_gateway", "-c", "/root/config.json"]
