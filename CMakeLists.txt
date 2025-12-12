cmake_minimum_required(VERSION 3.10)
project(satoshi_gateway C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2 -g -pthread -D_GNU_SOURCE")

find_package(PkgConfig REQUIRED)
pkg_check_modules(JANSSON REQUIRED jansson)
pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(ZMQ REQUIRED libzmq)  # 新增 ZMQ
find_package(OpenSSL REQUIRED)

include_directories(
    ${JANSSON_INCLUDE_DIRS} 
    ${CURL_INCLUDE_DIRS} 
    ${ZMQ_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR} 
    src
)

set(SOURCES
    src/main.c
    src/config.c
    src/utils.c
    src/sha256.c
    src/stratum.c
    src/bitcoin.c
    src/zmq_listener.c  # 新增
)

add_executable(satoshi_gateway ${SOURCES})
target_link_libraries(satoshi_gateway 
    ${JANSSON_LIBRARIES} 
    ${CURL_LIBRARIES} 
    ${ZMQ_LIBRARIES} 
    OpenSSL::Crypto 
    pthread 
    m
)
