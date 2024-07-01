/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2024 Jean Gressmann <jean@0x42.de>
 *
 */

#pragma once

#include <errno.h>
#include <time.h>
#include <stdbool.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/tcp.h>
#include <string.h> // strerror


#include "teeth.h"


#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

#define stringify_(x) #x
#define stringify(x) stringify_(x)

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

enum {
    LOG_LEVEL_ERROR,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG1,
    LOG_LEVEL_DEBUG2,
    LOG_LEVEL_DEBUG3,
};

extern int g_log_level;

#define sys_error(...) \
    do { \
        fprintf(stderr, "ERROR: "); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, ": %s (%d)\n", strerror(errno), errno); \
    } while (0)

#define log_error(...) \
    do { \
        if (g_log_level >= LOG_LEVEL_ERROR) { \
            fprintf(stderr, "ERROR: "); \
            fprintf(stderr, __VA_ARGS__); \
        } \
    } while (0)


#define log_warn(...) \
    do { \
        if (g_log_level >= LOG_LEVEL_WARNING) { \
            fprintf(stderr, "WARN: "); \
            fprintf(stderr, __VA_ARGS__); \
        } \
    } while (0)

#define log_info(...) \
    do { \
        if (g_log_level >= LOG_LEVEL_INFO) { \
            fprintf(stderr, "INFO: "); \
            fprintf(stderr, __VA_ARGS__); \
        } \
    } while (0)

#define log_debug1(...) \
    do { \
        if (g_log_level >= LOG_LEVEL_DEBUG1) { \
            fprintf(stderr, "DEBUG1: "); \
            fprintf(stderr, __VA_ARGS__); \
        } \
    } while (0)


#define log_debug2(...) \
    do { \
        if (g_log_level >= LOG_LEVEL_DEBUG2) { \
            fprintf(stderr, "DEBUG2: "); \
            fprintf(stderr, __VA_ARGS__); \
        } \
    } while (0)

#define log_debug3(...) \
    do { \
        if (g_log_level >= LOG_LEVEL_DEBUG3) { \
            fprintf(stderr, "DEBUG3: "); \
            fprintf(stderr, __VA_ARGS__); \
        } \
    } while (0)



static inline uint64_t now_mono()
{
    struct timespec ts;

    if (0 == clock_gettime(CLOCK_MONOTONIC, &ts)) {
        return ts.tv_nsec + UINT64_C(1000000000) * ts.tv_sec;
    }

    return 0;
}

static inline uint64_t now_utc()
{
    struct timespec ts;

    if (0 == clock_gettime(CLOCK_REALTIME, &ts)) {
        return ts.tv_nsec + UINT64_C(1000000000) * ts.tv_sec;
    }

    return 0;
}

static inline bool sock_set_nonblock(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

static inline bool sock_disable_linger(int fd) {
    struct linger arg;
    arg.l_linger = 0; // don't linger
    arg.l_onoff = 1;

    return 0 == setsockopt(fd, SOL_SOCKET, SO_LINGER, &arg, sizeof(arg));
}

static inline bool sock_keep_alive(int fd) {
    int option = 1;

    return 0 == setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &option, sizeof(option));
}

static inline bool tcp_disable_nagle(int fd) {
    int flag = 1;

    return 0 == setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
}

static inline bool tcp_cork(int fd) {
    int flag = 1;

    return 0 == setsockopt(fd, IPPROTO_TCP, TCP_CORK, &flag, sizeof(flag));
}

static inline bool tcp_uncork(int fd) {
    int flag = 0;

    return 0 == setsockopt(fd, IPPROTO_TCP, TCP_CORK, &flag, sizeof(flag));
}


static inline bool tcp_out_queued(int fd, size_t* out_queued) {
    int out_bytes_pending = 0;

    if (-1 == ioctl(fd, TIOCOUTQ, &out_bytes_pending)) {
        return false;
    }

    *out_queued = out_bytes_pending;

    return true;
}

bool safe_close_ref(int* fd);

static inline bool safe_close(int fd)
{
    return safe_close_ref(&fd);
}

bool teeth_signal_handler_init();
bool teeth_signal_handler_arm();
void teeth_signal_handler_uninit();
extern int teeth_signal_handler_fd;

#define TEETH_SIGNAL_HANDLER_EPOLL_FLAGS (EPOLLIN | EPOLLET)


static inline void teeth_net_to_host_base(struct teeth_base_hdr* hdr)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    hdr->len = __builtin_bswap16(hdr->len);
#endif
}

static inline void teeth_net_to_host_eth_rx(struct teeth_eth_rx_hdr* hdr)
{
//    teeth_net_to_host_base(&hdr->base)
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    hdr->flags = __builtin_bswap32(hdr->flags);
    hdr->ts_utc_nano = __builtin_bswap64(hdr->ts_utc_nano);
#endif
}

static inline void teeth_net_to_host_echo(struct teeth_echo_hdr* hdr)
{
//    teeth_net_to_host_base(&hdr->base)unlikely(
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__s
    hdr->ts_utc_nano = __builtin_bswap64(hdr->ts_utc_nano);
    hdr->ts_mono_nano = __builtin_bswap64(hdr->ts_mono_nano);
#endif
}

static inline void teeth_net_to_host_stats(struct teeth_eth_stats_hdr* hdr)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    hdr->speed_mbps = __builtin_bswap32(hdr->speed_mbps);
    hdr->mtu = __builtin_bswap16(hdr->mtu);
    hdr->flags = __builtin_bswap16(hdr->flags);
    hdr->tx_packets = __builtin_bswap32(hdr->tx_packets);
    hdr->rx_packets = __builtin_bswap32(hdr->rx_packets);
    hdr->tx_errors = __builtin_bswap32(hdr->tx_errors);
    hdr->rx_errors = __builtin_bswap32(hdr->rx_errors);
    hdr->rx_missed = __builtin_bswap32(hdr->rx_missed);
#endif
}

static inline void teeth_net_to_host_eth_tx_req(struct teeth_eth_tx_req_hdr* hdr)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    hdr->track_id = __builtin_bswap16(hdr->track_id);
    hdr->flags = __builtin_bswap16(hdr->flags);
#endif
}

static inline void teeth_net_to_host_eth_tx_res(struct teeth_eth_tx_res_hdr* hdr)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    hdr->track_id = __builtin_bswap16(hdr->track_id);
    hdr->error = __builtin_bswap16(hdr->error);
    hdr->ts_utc_nano = __builtin_bswap64(hdr->ts_utc_nano);
#endif
}

static inline void teeth_net_to_host_eth_mtu(struct teeth_eth_mtu_hdr* hdr)
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    hdr->mtu = __builtin_bswap16(hdr->mtu);
    hdr->error = __builtin_bswap16(hdr->error);
#endif
}




bool timerfd_drain(int fd);
