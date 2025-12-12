cmake_minimum_required(VERSION 3.10)
project(satoshi_gateway C)

set(CMAKE_C_STANDARD 99)
# 增加 -g 以便调试 crash，-O2 优化性能
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2 -g -pthread -D_GNU_SOURCE")

# 1. 查找依赖
find_package(PkgConfig REQUIRED)
pkg_check_modules(JANSSON REQUIRED jansson)
pkg_check_modules(CURL REQUIRED libcurl)
find_package(OpenSSL REQUIRED)

# 2. 包含头文件路径
include_directories(
    ${JANSSON_INCLUDE_DIRS} 
    ${CURL_INCLUDE_DIRS} 
    ${OPENSSL_INCLUDE_DIR} 
    src
)

# 3. 指定源文件
set(SOURCES
    src/main.c
    src/config.c
    src/utils.c
    src/sha256.c
    src/stratum.c
    src/bitcoin.c
)

# 4. 生成可执行文件
add_executable(satoshi_gateway ${SOURCES})

# 5. 链接库
# 注意：OpenSSL::Crypto 是 OpenSSL 的 crypto 库目标
target_link_libraries(satoshi_gateway 
    ${JANSSON_LIBRARIES} 
    ${CURL_LIBRARIES} 
    OpenSSL::Crypto 
    pthread
    m
)
