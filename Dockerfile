# 第一阶段：编译环境
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libcurl4-openssl-dev \
    libjansson-dev \
    libssl-dev \
    libzmq3-dev \
    pkg-config

WORKDIR /app
COPY . .

RUN mkdir build && cd build && \
    cmake .. && \
    make -j$(nproc)

# 第二阶段：运行环境
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    libcurl4 \
    libjansson4 \
    libssl3 \
    libzmq5 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 复制二进制文件
COPY --from=builder /app/build/satoshi_gateway .
# 复制 Web 文件
COPY --from=builder /app/web ./web

# 暴露端口：3333(Stratum) 8080(Web)
EXPOSE 3333 8080

ENTRYPOINT ["./satoshi_gateway", "-c", "/app/config.json"]
