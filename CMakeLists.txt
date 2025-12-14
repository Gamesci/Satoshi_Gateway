cmake_minimum_required(VERSION 3.10)
project(satoshi_gateway C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(satoshi_gateway
    src/main.c
    src/config.c
    src/utils.c
    src/sha256.c
    src/stratum.c
    src/bitcoin.c
    src/zmq_listener.c
)

# Warnings / flags
target_compile_options(satoshi_gateway PRIVATE -Wall -Wextra -O2 -g -D_GNU_SOURCE -pthread)

find_package(PkgConfig REQUIRED)
pkg_check_modules(JANSSON REQUIRED jansson)
pkg_check_modules(CURL REQUIRED libcurl)
pkg_check_modules(ZMQ REQUIRED libzmq)
find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

target_include_directories(satoshi_gateway PRIVATE
    src
    ${JANSSON_INCLUDE_DIRS}
    ${CURL_INCLUDE_DIRS}
    ${ZMQ_INCLUDE_DIRS}
)

# Carry pkg-config extra flags (more portable)
target_compile_options(satoshi_gateway PRIVATE
    ${JANSSON_CFLAGS_OTHER}
    ${CURL_CFLAGS_OTHER}
    ${ZMQ_CFLAGS_OTHER}
)

target_link_libraries(satoshi_gateway PRIVATE
    ${JANSSON_LIBRARIES}
    ${CURL_LIBRARIES}
    ${ZMQ_LIBRARIES}
    OpenSSL::Crypto
    Threads::Threads
    m
)

target_link_options(satoshi_gateway PRIVATE
    ${JANSSON_LDFLAGS_OTHER}
    ${CURL_LDFLAGS_OTHER}
    ${ZMQ_LDFLAGS_OTHER}
)
