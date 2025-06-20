/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2024 Jean Gressmann <jean@0x42.de>
 *
 */

#define _GNU_SOURCE


#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <string.h>
#include <fcntl.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <linux/sockios.h> // ethtool
#include <linux/if_packet.h> // packet ring
#include <linux/mman.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <sys/uio.h> // readv
#include <linux/tcp.h>
#include <linux/ethtool.h>
#include <linux/net_tstamp.h>
#include <stdbool.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>
#include <linux/if.h> // IFF_*
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "lib.h"


#define DEFAULT_PORT 12345
#define DEFAULT_MTU 1500
#define ETH_MIN_FRAME_LEN 64



static void usage(FILE* stream)
{
    fprintf(stream, "teethd [OPTIONS] LISTEN-IF TARGET-IF\n\n");
    fprintf(stream, "  -h, --help              print this help\n");
    fprintf(stream, "  -p, --port PORT         port to listen on (default %d)\n", DEFAULT_PORT);
    fprintf(stream, "      --port-file FILE    write listen port to file\n");
    fprintf(stream, "  -v, --verbose           increase verbosity\n");
    fprintf(stream, "\n");
}


enum {
    STATE_READ_HEADER,
    STATE_READ_DATA,
    STATE_OP,
};


enum {
    FD_SLOT_TYPE_FREE,
    FD_SLOT_TYPE_TCP,
};

struct teeth_nic_stats {
    uint64_t tx_packets;
    uint64_t rx_packets;
    uint64_t tx_errors;
    uint64_t rx_errors;
    uint64_t rx_missed;
};

struct tcp_slot {
    int type;
    int state;
    int tcp_send_buffer_size;
    int w_pipe_open;
    int r_pipe_open;
    int tx_error_code;
    struct teeth_nic_stats stats;
    size_t rx_offset;
    struct iovec iov_buffer[2];
    size_t iov_count;
    _Alignas(8) uint8_t rx_buffer[TEETH_BUFFER_SIZE];
};


struct slot_entry {
    int type;
    unsigned generation;
    union {
        struct tcp_slot* tcp;
    } data;
};

typedef struct app {
    char const* nic_name;
    int nic_index;
    int packet_socket_rx_fd;
    int packet_socket_tx_fd;
    int netlink_socket_fd;
    uint32_t netlink_seq_no;
    int fd_slot_capacity;
    struct slot_entry* fd_slot_ptr;
    int epoll_fd;
    int event_capacity;
    int event_count;
    struct epoll_event* event_ptr;
    uint8_t* packet_ring_rx_ptr;
    uint8_t* packet_ring_tx_ptr;
    size_t packet_ring_rx_block_current; // not an index
    size_t packet_ring_tx_frame_put_no;  // not an index
    size_t packet_ring_tx_frame_get_no;  // not an index
    size_t frames_per_block;
    size_t packet_ring_tx_frames_queued;
    struct tpacket_req3 packet_ring_setup;
    uint32_t rx_flags;
    struct ifreq ifr;
    struct ethtool_link_settings* glink_settings;
    unsigned glink_settings_link_mode_mask_words;
    struct teeth_eth_stats_hdr stats_hdr;
    struct rtnl_link_stats rtnetlink_stats;
} app;

static inline void fd_slot_uninit(app* app, int fd)
{
    assert(app);
    assert(app->fd_slot_ptr);
    assert(fd >= 0);
    assert(fd < app->fd_slot_capacity);

    struct slot_entry *slot = &app->fd_slot_ptr[fd];

    switch (slot->type) {
    case FD_SLOT_TYPE_TCP:
        assert(slot->data.tcp);
        shutdown(fd, SHUT_RDWR);
        safe_close(fd);
        free(slot->data.tcp);
        slot->data.tcp = NULL;
        app->event_count -= 1;
        slot->type = FD_SLOT_TYPE_FREE;
        break;
    }
}

static inline void app_uninit(struct app* app)
{
    safe_close_ref(&app->epoll_fd);

    if (app->event_ptr) {
        free(app->event_ptr);
        app->event_ptr = NULL;
    }

    app->event_capacity = 0;
    app->event_count = 0;

    if (app->glink_settings) {
        free(app->glink_settings);
        app->glink_settings = NULL;
    }

    if (app->packet_ring_rx_ptr) {
        munmap(app->packet_ring_rx_ptr, app->packet_ring_setup.tp_block_nr * app->packet_ring_setup.tp_block_size);
        app->packet_ring_rx_ptr = NULL;
    }

    safe_close_ref(&app->packet_socket_rx_fd);
    safe_close_ref(&app->packet_socket_tx_fd);
    safe_close_ref(&app->netlink_socket_fd);

    if (app->fd_slot_ptr) {
        for (int fd = 0; fd < app->fd_slot_capacity; ++fd) {
            fd_slot_uninit(app, fd);
        }

        free(app->fd_slot_ptr);
        app->fd_slot_ptr = NULL;
    }

    app->fd_slot_capacity = 0;
}

static inline void app_init(struct app* app)
{
    memset(app, 0, sizeof(*app));

    app->epoll_fd = -1;
    app->packet_socket_rx_fd = -1;
    app->packet_socket_tx_fd = -1;
    app->netlink_socket_fd = -1;

    app->stats_hdr.base.len = sizeof(app->stats_hdr);
    app->stats_hdr.base.msg_type = TEETH_MT_ETH_STATS;
    app->stats_hdr.base.version = TEETH_PROTOCOL_VERSION;
}

static inline void app_assign_rtnetlink_stats(app const* app, struct teeth_nic_stats* stats)
{
    stats->tx_packets = app->rtnetlink_stats.tx_packets;
    stats->rx_packets = app->rtnetlink_stats.rx_packets;
    stats->tx_errors = app->rtnetlink_stats.tx_errors;
    stats->rx_errors = app->rtnetlink_stats.rx_errors;
    stats->rx_missed = app->rtnetlink_stats.rx_dropped + app->rtnetlink_stats.rx_missed_errors;
}


#define TX_PRIVATE_DATA_SIZE 16

struct tx_ring_frame_data_priv {
    uint8_t frame[TEETH_MAX_ETHER_PACKET_SIZE];
    union {
        struct {
            unsigned generation;
            int fd;
            uint16_t echo;
            uint16_t track_id;
            uint16_t error;
        } tx_res;
        uint8_t padding[TX_PRIVATE_DATA_SIZE];
    };
};

static inline void fd_slot_init(struct slot_entry* e)
{
    memset(e, 0, sizeof(*e));
}



static inline void tcp_gone(app* app, int fd) {
    log_debug1("client disconnected (%d)\n", fd);
    fd_slot_uninit(app, fd);
}

static inline void tcp_on_change(app* app, int fd) {
    assert(app);
    assert(app->fd_slot_ptr);
    assert(fd >= 0);
    assert(fd < app->fd_slot_capacity);
    assert(app->fd_slot_ptr[fd].type == FD_SLOT_TYPE_TCP);


    struct tcp_slot *tcp = app->fd_slot_ptr[fd].data.tcp;

    if (!tcp->w_pipe_open && !tcp->r_pipe_open) {
        tcp_gone(app, fd);
    }
}

static inline void tcp_on_r_pipe_closed(app* app, int fd) {
    assert(app);
    assert(app->fd_slot_ptr);
    assert(fd >= 0);
    assert(fd < app->fd_slot_capacity);
    assert(app->fd_slot_ptr[fd].type == FD_SLOT_TYPE_TCP);


    struct tcp_slot *tcp = app->fd_slot_ptr[fd].data.tcp;

    tcp->r_pipe_open = 0;
}

static inline void tcp_on_w_pipe_closed(app* app, int fd) {
    assert(app);
    assert(app->fd_slot_ptr);
    assert(fd >= 0);
    assert(fd < app->fd_slot_capacity);
    assert(app->fd_slot_ptr[fd].type == FD_SLOT_TYPE_TCP);


    struct tcp_slot *tcp = app->fd_slot_ptr[fd].data.tcp;

    tcp->w_pipe_open = 0;
}

static inline void on_tcp_send_failed(app* app, int fd)
{
    assert(app);
    assert(app->fd_slot_ptr);
    assert(fd >= 0);
    assert(fd < app->fd_slot_capacity);

    log_error("failed to send to TCP client (%d), disconnecting\n", fd);

    fd_slot_uninit(app, fd);
}


static bool tcp_send(app* app, int fd, void const* ptr, size_t bytes);
static bool fd_slot_reserve(app* app, int fd);
static bool epoll_reserve(app* app, size_t count);
static bool on_tcp_event(app* app, struct epoll_event const* ev);
static bool fetch_stats(app* app);
static void send_stats(app* app, int fd);
static bool init_client(app* app, int fd);
static struct tcp_slot* tcp_new();
static bool on_packet_socket_event(app* app);
static bool setup_packet_socket(app* app, char const* name);

#define on_packet_socket_error() \
    do { \
        /* has the device gone? */ \
        if (0 == if_nametoindex(target_arg) && errno == ENODEV) { \
            log_info("%s gone, exiting\n", target_arg); \
        } else { \
            log_error("packet socket failed\n"); \
            error = 2; \
        } \
        goto Exit; \
    } while (0)


int main(int argc, char** argv)
{
    app app;
    long port = DEFAULT_PORT;
    char* listen_arg = NULL;
    char* target_arg = NULL;
    int listen_socket = -1;
    int stats_timer_fd = -1;
    int error = 0;
    struct sockaddr_in6 listen_socket_address;
    char* port_file_path = NULL;
    const unsigned STATIC_EPOLL_EVENT_SIZE = 4;
    _Alignas(8) uint8_t packet_rx_frame_buffer[TEETH_MAX_ETHER_PACKET_SIZE];


    memset(&listen_socket_address, 0, sizeof(listen_socket_address));
    app_init(&app);

    for (int option_index = 0;;) {
        static const struct option long_options[] = {
            {"help",        no_argument,        0, 'h' },
            {"port",        required_argument,  0, 'p' },
            {"port-file",   required_argument,  0, 0x100 },
            {"verbose",     no_argument,        0, 'v' },
            {0,             0,                  0, 0 }
        };

        int c = getopt_long(argc, argv, "vhp:", long_options, &option_index);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage(stdout);
            goto Exit;
        case 'p': {
            port = strtol(optarg, NULL, 10);

            if (port < 0 || port > 65535) {
                log_error("port %ld out of range.\n", port);
                error = 1;
                goto Exit;
            }
        } break;
        case 'v':
            ++g_log_level;
            break;
//        case '?':
//            // bad option
//            error = 1;
//            goto Exit;
//        case ':':
//            error = 1;
//            goto Exit;
        case 0x100:
            port_file_path = optarg;
            break;
        default:
            log_error("getopt returned character code %d\n", c);
            error = 1;
            goto Exit;
        }
    }

    if (optind + 2 != argc) {
        log_error("required non-option arguments LISTEN-IF and TARGET-IF missing!\n");
        error = 1;
        goto Exit;
    }

    listen_arg = argv[optind];
    target_arg = argv[optind+1];

    if (!setup_packet_socket(&app, target_arg)) {
        error = 2;
        goto Exit;
    }

    unsigned listen_index = if_nametoindex(listen_arg);

    if (0 == listen_index) {
        sys_error("failed to get index for interface name %s", listen_arg);
        error = 2;
        goto Exit;
    }


    listen_socket = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if (-1 == listen_socket) {
        sys_error("failed to create IPv6 listen socket");
        error = 2;
        goto Exit;
    }

    {
        int flag = 1;

        if (-1 == setsockopt(listen_socket, SOL_SOCKET, SO_REUSEPORT, &flag, sizeof(flag))) {
            sys_error("failed to reuse port");
            error = 2;
            goto Exit;
        }
    }
    // bind to device
    {
        struct ifreq ifr;

        memset(&ifr, 0, sizeof(ifr));

        strncpy(ifr.ifr_name, listen_arg, IFNAMSIZ-1);

        if (-1 == setsockopt(listen_socket, SOL_SOCKET, SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0) {
            sys_error("failed to bind listen socket to %s", listen_arg);
            error = 2;
            goto Exit;
        }
    }


    listen_socket_address.sin6_family = AF_INET6;
    listen_socket_address.sin6_port = htons((unsigned short)port);
    listen_socket_address.sin6_addr = in6addr_any;
//    listen_socket_address.sin6_scope_id = listen_index; // doesn't work

    if (-1 == bind(listen_socket, (struct sockaddr*)&listen_socket_address, sizeof(listen_socket_address))) {
        sys_error("failed to bind IPv6 listen socket to %s", listen_arg);
        error = 2;
        goto Exit;
    }

    if (-1 == listen(listen_socket, SOMAXCONN)) {
        sys_error("failed to listen on TCP socket");
        error = 2;
        goto Exit;
    }

    if (!sock_set_nonblock(listen_socket)) {
        sys_error("failed to make socket non-blocking");
        error = 2;
        goto Exit;
    }


    if (!port) {
        socklen_t len = sizeof(listen_socket_address);

        if (-1 == getsockname(listen_socket, (struct sockaddr *)&listen_socket_address, &len)) {
            sys_error("failed get socket name");
            error = 2;
            goto Exit;
        }

        port = ntohs(listen_socket_address.sin6_port);
    }

    log_info("listen on port %hu\n", (unsigned short)port);

    if (port_file_path) {
        FILE* f = fopen(port_file_path, "w");

        if (f) {
            fprintf(f, "%hu\n", (unsigned short)port);
            fclose(f);
        } else {
            sys_error("failed open '%s' for writing", port_file_path);
            error = 2;
            goto Exit;
        }
    }
    {
        struct itimerspec timer_setup;

        stats_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);

        if (-1 == stats_timer_fd) {
            sys_error("timerfd_settime");
            error = 2;
            goto Exit;
        }

        timer_setup.it_interval.tv_sec = TEETH_STATS_INTERVAL_S;
        timer_setup.it_interval.tv_nsec = 0;
        timer_setup.it_value = timer_setup.it_interval;

        if (-1 == timerfd_settime(stats_timer_fd, 0, &timer_setup, NULL)) {
            sys_error("timerfd_settime");
            error = 2;
            goto Exit;
        }
    }


    if (!teeth_signal_handler_init()) {
        sys_error("failed to initialize signal handler");
        error = 2;
        goto Exit;
    }

    app.epoll_fd = epoll_create1(0);
    if (-1 == app.epoll_fd) {
        sys_error("failed to create epoll instance");
        error = 2;
        goto Exit;
    }

    {
        app.event_capacity = STATIC_EPOLL_EVENT_SIZE;
        app.event_count = STATIC_EPOLL_EVENT_SIZE;
        app.event_ptr = calloc(sizeof(*app.event_ptr), app.event_capacity);

        app.event_ptr[0].data.fd = app.packet_socket_rx_fd;
        app.event_ptr[0].events = EPOLLOUT | EPOLLIN | EPOLLET;
        app.event_ptr[1].data.fd = listen_socket;
        app.event_ptr[1].events = EPOLLIN | EPOLLET;
        app.event_ptr[2].data.fd = teeth_signal_handler_fd;
        app.event_ptr[2].events = TEETH_SIGNAL_HANDLER_EPOLL_FLAGS;
        app.event_ptr[3].data.fd = stats_timer_fd;
        app.event_ptr[3].events = EPOLLIN | EPOLLET;

        for (int i = 0; i < app.event_count; ++i) {
            if (-1 == epoll_ctl(app.epoll_fd, EPOLL_CTL_ADD, app.event_ptr[i].data.fd, &app.event_ptr[i])) {
                sys_error("failed to register fd with epoll");
                error = 2;
                goto Exit;
            }
        }
    }


    teeth_signal_handler_arm();

    for (;;) {
        assert(app.event_count >= STATIC_EPOLL_EVENT_SIZE);

        int count = epoll_wait(app.epoll_fd, app.event_ptr, app.event_count, -1);

        if (-1 == count) {
            switch (errno) {
            case EINTR:
                break;
            default:
                sys_error("epoll_wait failed");
                error = 2;
                goto Exit;
            }
        } else {
            for (int i = 0; i < count; ++i) {
                if (app.packet_socket_rx_fd == app.event_ptr[i].data.fd) {
                    if (unlikely(app.event_ptr[i].events & EPOLLERR)) {
                        int ec = 0;
                        socklen_t len = sizeof(ec);

                        if (-1 == getsockopt(app.packet_socket_rx_fd, SOL_SOCKET, SO_ERROR, &ec, &len)) {
                            sys_error("getsocketopt SO_ERROR");
                            error = 2;
                            goto Exit;
                        }

                        switch (ec) {
                        case 0:
                        case EINTR:
                            break;
                        default:
                            log_error("packet socket failure: %s (%d)\n", strerror(ec), ec);
                            error = 2;
                            goto Exit;
                            break;
                        }
                    }

                    if (unlikely(!on_packet_socket_event(&app))) {
                        error = 2;
                        goto Exit;
                    }
                } else if (listen_socket == app.event_ptr[i].data.fd) {
                    struct sockaddr_in6 peer_adress;
                    socklen_t peer_adress_len = sizeof(peer_adress);

                    // listen socket
                    if (unlikely(app.event_ptr[i].events & EPOLLERR)) {
                        log_error("listen socket failed");
                        error = 2;
                        goto Exit;
                    }

                    for (bool done = false; !done; ) {
                        int fd = accept4(listen_socket, &peer_adress, &peer_adress_len, O_NONBLOCK | O_CLOEXEC);

                        if (-1 == fd) {
                            switch (errno) {
                            case EINTR:
                                break;
                            case EAGAIN:
                                done = true;
                                break;
                            default:
                                sys_error("accept");
                                error = 2;
                                goto Exit;
                            }
                        } else {
                            if (!init_client(&app, fd)) {
                                error = 2;
                                goto Exit;
                            }

                            send_stats(&app, fd);
                        }
                    }
                } else if (stats_timer_fd == app.event_ptr[i].data.fd) {
                    if (unlikely(!timerfd_drain(stats_timer_fd))) {
                        error = 2;
                        goto Exit;
                    }

                    if (unlikely(!fetch_stats(&app))) {
                        error = 2;
                        goto Exit;
                    }

                    for (int fd = 0; fd < app.fd_slot_capacity; ++fd) {
                        struct slot_entry *slot = &app.fd_slot_ptr[fd];
                        struct tcp_slot *tcp = slot->data.tcp;

                        if (slot->type != FD_SLOT_TYPE_TCP) {
                            continue;
                        }

                        send_stats(&app, fd);
                    }
                } else if (teeth_signal_handler_fd == app.event_ptr[i].data.fd) {
                    log_info("shutting down\n");
                    goto Exit;
                } else {
                    int const fd = app.event_ptr[i].data.fd;

                    if (fd >= app.fd_slot_capacity) {
                        continue;
                    }

                    switch (app.fd_slot_ptr[fd].type) {
                    case FD_SLOT_TYPE_FREE:
                        break;
                    case FD_SLOT_TYPE_TCP:
                        if (!on_tcp_event(&app, &app.event_ptr[i])) {
                            on_packet_socket_error();
                        }
                        break;
                    }
                }
            }

            if (app.packet_ring_tx_frames_queued) {
                log_debug2("txq %zu frames\n", app.packet_ring_tx_frames_queued);
                app.packet_ring_tx_frames_queued = 0;

                for (;;) {
                    ssize_t w = sendto(app.packet_socket_tx_fd, NULL, 0, 0, NULL, 0);

                    if (-1 == w) {
                        if (errno != EINTR) {
                            sys_error("packet socket send");
                            error = 2;
                            goto Exit;
                        }
                    } else {
                        break;
                    }
                }
            }
        }
    }


Exit:
    teeth_signal_handler_uninit();

    safe_close(listen_socket);

    app_uninit(&app);

    if (port_file_path) {
        unlink(port_file_path);
    }

    return error;
}

static bool tcp_send(app* app, int fd, void const* ptr, size_t bytes)
{
    for (;;) {
        ssize_t w = sendto(fd, ptr, bytes, MSG_NOSIGNAL, NULL, 0);

        if (-1 == w) {
            switch (errno) {
            case EINTR:
                break;
            case EAGAIN:
                return false;
            default:
                tcp_on_w_pipe_closed(app, fd);
                return false;
            }
        } else if (0 == w) {
            // peer closed receive end
            tcp_on_w_pipe_closed(app, fd);
            return false;
        } else if ((size_t)w != bytes) {
            return false;
        } else {
            break;
        }
    }

    return true;
}


static bool on_tcp_event(app* app, struct epoll_event const* ev)
{
    assert(ev);
    assert(app);
    assert(app->fd_slot_ptr);
    assert(app->fd_slot_capacity > ev->data.fd);
    assert(app->fd_slot_ptr[ev->data.fd].type == FD_SLOT_TYPE_TCP);

    bool bad_client = false;
    bool connection_error = false;
    int const fd = ev->data.fd;
    struct tcp_slot *tcp = app->fd_slot_ptr[fd].data.tcp;


    // Even with read pipe closed, there may be data left to read.

    for (;;) {
        struct teeth_base_hdr* const base = (struct teeth_base_hdr*)tcp->rx_buffer;

        switch (tcp->state) {
        case STATE_READ_HEADER: {
            for (;;) {
                ssize_t r = read(fd, &tcp->rx_buffer[tcp->rx_offset], sizeof(*base) - tcp->rx_offset);

                if (-1 == r) {
                    switch (errno) {
                    case EINTR:
                        break;
                    case EAGAIN:
                        goto client_done;
                    default:
                        connection_error = true;
                        goto client_done;
                    }
                } else if (0 == r) {
                    tcp->rx_offset = 0;
                    tcp->state = STATE_READ_HEADER;
                    tcp_on_r_pipe_closed(app, fd);
                    goto client_done;
                } else {
                    tcp->rx_offset += r;

                    if (tcp->rx_offset == sizeof(*base)) {
                        tcp->rx_offset = 0;

                        teeth_net_to_host_base(base);

                        switch (base->version) {
                        case TEETH_PROTOCOL_VERSION:
                            if (base->len < sizeof(*base)) {
                                log_debug1("bad header of %u bytes (%d)\n", base->len, fd);
                                bad_client = true;
                                goto client_done;
                            } else {
                                switch (base->msg_type) {
                                case TEETH_MT_ETH_TX_REQ: {
                                    unsigned frame_len = base->len - sizeof(struct teeth_eth_tx_req_hdr);

                                    if (frame_len > TEETH_MAX_ETHER_PACKET_SIZE) {
                                        log_error("client (%d) sent TX request beyond TEETH_MAX_ETHER_PACKET_SIZE\n", fd);
                                        bad_client = true;
                                        goto client_done;
                                    }

                                    // is frame entry free?
                                    uint8_t* frame_base = app->packet_ring_tx_ptr + (app->packet_ring_tx_frame_put_no % app->packet_ring_setup.tp_frame_nr) * app->packet_ring_setup.tp_frame_size;
                                    struct tpacket3_hdr* phdr = (struct tpacket3_hdr*)frame_base;

                                     if (likely(__atomic_load_n(&phdr->tp_status,__ATOMIC_ACQUIRE)  == TP_STATUS_AVAILABLE)) {
                                        tcp->iov_buffer[0].iov_base = tcp->rx_buffer + sizeof(*base);
                                        tcp->iov_buffer[0].iov_len = sizeof(struct teeth_eth_tx_req_hdr) - sizeof(*base);
                                        tcp->iov_buffer[1].iov_base = frame_base + TPACKET_ALIGN(sizeof(*phdr));
                                        tcp->iov_buffer[1].iov_len = frame_len;
                                        tcp->iov_count = 2;
                                        if (unlikely(frame_len < 64)) {
                                            tcp->tx_error_code = TEETH_TX_ERROR_TOO_SMALL;
                                        } else {
                                            tcp->tx_error_code = TEETH_TX_ERROR_NONE;
                                        }
                                     } else {
                                         // fail, need to read out data
                                         tcp->iov_buffer[0].iov_base = tcp->rx_buffer + sizeof(*base);
                                         tcp->iov_buffer[0].iov_len = base->len - sizeof(*base);
                                         tcp->iov_count = 1;
                                         tcp->tx_error_code = TEETH_TX_ERROR_QUEUE_FULL;
                                     }

                                    tcp->state = STATE_READ_DATA;
                                } break;
                                default:
                                    if (base->len == sizeof(*base)) {
                                        tcp->state = STATE_OP;
                                    } else {
                                        tcp->iov_buffer[0].iov_base = tcp->rx_buffer + sizeof(*base);
                                        tcp->iov_buffer[0].iov_len = base->len - sizeof(*base);
                                        tcp->iov_count = 1;
                                        tcp->state = STATE_READ_DATA;
                                    }
                                    break;
                                }
                                break;
                            default:
                                log_debug1("unhandled protocol version %u (%d)\n", base->version, fd);
                                bad_client = true;
                                goto client_done;
                            }
                        }
                        break;
                    }
                }
            }
        } break;
        case STATE_READ_DATA: {
            for (;;) {
                ssize_t r = readv(fd, tcp->iov_buffer, tcp->iov_count);

                if (-1 == r) {
                    switch (errno) {
                    case EINTR:
                        break;
                    case EAGAIN:
                        goto client_done;
                    default:
                        connection_error = true;
                        goto client_done;
                    }
                } else if (0 == r) {
                    tcp->rx_offset = 0;
                    tcp->state = STATE_READ_HEADER;
                    tcp_on_r_pipe_closed(app, fd);
                    goto client_done;
                } else {
                    size_t active_index = 0;

                    for (; r >= tcp->iov_buffer[active_index].iov_len; ) {
                        r -= tcp->iov_buffer[active_index].iov_len;
                        ++active_index;
                    }

                    if (r) {
                        tcp->iov_buffer[active_index].iov_len -= r;
                        tcp->iov_buffer[active_index].iov_base = ((uint8_t*)tcp->iov_buffer[active_index].iov_base) + r;

                        if (active_index) {
                            tcp->iov_buffer[0] = tcp->iov_buffer[1];
                            tcp->iov_count = 1;
                        }
                    } else {
                        tcp->state = STATE_OP;
                        break;
                    }
                }
            }
        } break;
        case STATE_OP: {
            tcp->state = STATE_READ_HEADER;
            tcp->rx_offset = 0;

            switch (base->msg_type) {
            case TEETH_MT_ETH_TX_REQ: {
                struct teeth_eth_tx_req_hdr* tx_hdr = (struct teeth_eth_tx_req_hdr*)tcp->rx_buffer;
                uint8_t* frame_base = app->packet_ring_tx_ptr + (app->packet_ring_tx_frame_put_no % app->packet_ring_setup.tp_frame_nr) * app->packet_ring_setup.tp_frame_size;
                struct tpacket3_hdr* phdr = (struct tpacket3_hdr*)frame_base;
                struct tx_ring_frame_data_priv* priv = (struct tx_ring_frame_data_priv*)(frame_base + app->packet_ring_setup.tp_frame_size - TX_PRIVATE_DATA_SIZE);

                teeth_net_to_host_eth_tx_req(tx_hdr);

                if (likely(tcp->tx_error_code == TEETH_TX_ERROR_NONE)) {
                    assert(phdr->tp_status == TP_STATUS_AVAILABLE);

                    if (unlikely(!app->stats_hdr.link_detected)) {
                        tcp->tx_error_code = TEETH_TX_ERROR_LINK_DOWN;
                    }
                }

                if (likely(tcp->tx_error_code == TEETH_TX_ERROR_NONE)) {
                    // store track ID
                    priv->tx_res.track_id = tx_hdr->track_id;
                    priv->tx_res.fd = fd;
                    priv->tx_res.generation =  app->fd_slot_ptr[fd].generation;
                    priv->tx_res.echo = (tx_hdr->flags & TEETH_TX_FLAG_SUPPRESS_RESPONSE) == 0;
                    priv->tx_res.error = tcp->tx_error_code;


                    phdr->tp_next_offset = 0;
                    phdr->tp_len = tx_hdr->base.len - sizeof(*tx_hdr);

                    __atomic_store_n(&phdr->tp_status, TP_STATUS_SEND_REQUEST, __ATOMIC_RELEASE);
                    log_debug3("tx put i=%lu fd=%d\n", app->packet_ring_tx_frame_put_no % app->packet_ring_setup.tp_frame_nr, fd);

                    ++app->packet_ring_tx_frame_put_no;
                    ++app->packet_ring_tx_frames_queued;
                } else {
                    log_debug1("tx error=%d fd=%d\n", tcp->tx_error_code, fd);

                    if (!(tx_hdr->flags & TEETH_TX_FLAG_SUPPRESS_RESPONSE)) {
                        struct teeth_eth_tx_res_hdr tx_res_hdr;

                        tx_res_hdr.base.len = sizeof(tx_hdr);
                        tx_res_hdr.base.msg_type = TEETH_MT_ETH_TX_RES;
                        tx_res_hdr.base.version = TEETH_PROTOCOL_VERSION;
                        tx_res_hdr.track_id = tx_hdr->track_id;
                        tx_res_hdr.error = tcp->tx_error_code;
                        tx_res_hdr.ts_utc_nano = now_utc();

                        teeth_net_to_host_base(&tx_res_hdr.base);
                        teeth_net_to_host_eth_tx_res(&tx_res_hdr);

                        if (!tcp_send(app, fd, &tx_res_hdr, sizeof(tx_res_hdr))) {
                            goto client_done;
                        }
                    }
                }
            } break;
            case TEETH_MT_ECHO: {
                struct teeth_echo_hdr hdr;

                hdr.base.version = TEETH_PROTOCOL_VERSION;
                hdr.base.msg_type = TEETH_MT_ECHO;
                hdr.base.len = sizeof(hdr);
                hdr.ts_utc_nano = now_utc();
                hdr.ts_mono_nano = now_mono();

                teeth_net_to_host_base(&hdr.base);
                teeth_net_to_host_echo(&hdr);

                tcp_cork(fd);

                if (!tcp_send(app, fd, &hdr, sizeof(hdr))) {
                    goto client_done;
                }

                tcp_uncork(fd);
            } break;
            case TEETH_MT_ETH_MTU: {
                struct teeth_eth_mtu_hdr hdr;

                teeth_net_to_host_eth_mtu(&hdr);

                if (hdr.mtu)  {
                    if (hdr.mtu < DEFAULT_MTU) {
                        hdr.mtu = app->stats_hdr.mtu;
                        hdr.error = TEETH_MTU_ERROR_OUT_OF_RANGE;
                    } else {
                        if (-1 == ioctl(app->packet_socket_rx_fd, SIOCSIFMTU, &app->ifr)) {
                            switch (errno) {
                            default:
                                hdr.mtu = app->stats_hdr.mtu;
                                hdr.error = TEETH_MTU_ERROR_OUT_OF_RANGE;
                                break;
                            }
                        } else {
                            app->stats_hdr.mtu = hdr.mtu;
                            hdr.error = TEETH_MTU_ERROR_NONE;
                        }
                    }
                } else {
                    hdr.mtu = app->stats_hdr.mtu;
                    hdr.error = TEETH_MTU_ERROR_NONE;
                }

                teeth_net_to_host_base(&hdr.base);
                teeth_net_to_host_eth_mtu(&hdr);

                if (!tcp_send(app, fd, &hdr, sizeof(hdr))) {
                    goto client_done;
                }
            } break;
            default:
                log_warn("unhandle@d message type %02x\n", base->msg_type);
                break;
            }
        } break;
        }
    }
client_done:
    if (unlikely(bad_client)) {
        fd_slot_uninit(app, fd);
    } else {
        if (ev->events & EPOLLHUP) {
            tcp_on_r_pipe_closed(app, fd);
        }

        if (ev->events & EPOLLRDHUP) {
            tcp_on_w_pipe_closed(app, fd);
        }

        if (connection_error || (ev->events & EPOLLERR)) {
            tcp_gone(app, fd);
            assert(FD_SLOT_TYPE_FREE == app->fd_slot_ptr[fd].type);
        } else if (FD_SLOT_TYPE_TCP == app->fd_slot_ptr[fd].type) {
            tcp_on_change(app, fd);
        }
    }

    return true;
}

static bool fd_slot_reserve(app* app, int fd) {
    assert(app);

    if (fd >= app->fd_slot_capacity) {
        int const prev_capacity = app->fd_slot_capacity;

        app->fd_slot_capacity = fd + 1;
        app->fd_slot_ptr = realloc(app->fd_slot_ptr, sizeof(*app->fd_slot_ptr) * (size_t)app->fd_slot_capacity);

        if (!app->fd_slot_ptr){
            return false;
        }

        for (int i = prev_capacity; i < app->fd_slot_capacity; ++i) {
            fd_slot_init(app->fd_slot_ptr + i);
        }
    }

    if (app->event_count == app->event_capacity) {
        app->event_capacity *= 2;
        app->event_ptr = realloc(app->event_ptr, sizeof(*app->event_ptr) * app->event_capacity);

        if (!app->event_ptr) {
            return false;
        }
    }

    return true;
}

static bool epoll_reserve(app* app, size_t count)
{
    while (count > app->event_capacity) {
        app->event_capacity *= 2;
        app->event_ptr = realloc(app->event_ptr, sizeof(*app->event_ptr) * app->event_capacity);

        if (!app->event_ptr) {
            return false;
        }
    }

    return true;
}

static bool fetch_stats_glinksettings(app* app)
{
    assert(app);

fetch:
    if (app->glink_settings) {
        app->ifr.ifr_data = (caddr_t)app->glink_settings;

        if (-1 == ioctl(app->packet_socket_rx_fd, SIOCETHTOOL, &app->ifr)) {
            sys_error("ioctl SIOCETHTOOL, ETHTOOL_GLINKSETTINGS");
            return false;
        }

        if (app->glink_settings->link_mode_masks_nwords < 0) {
            app->glink_settings_link_mode_mask_words = -app->glink_settings->link_mode_masks_nwords;
            app->glink_settings = realloc(app->glink_settings, sizeof(*app->glink_settings) + 12 * app->glink_settings_link_mode_mask_words);

            if (app->glink_settings) {
                app->glink_settings->link_mode_masks_nwords = app->glink_settings_link_mode_mask_words;
                goto fetch;
            } else {
                sys_error("realloc");
                return false;
            }
        } else {
            app->stats_hdr.speed_mbps = app->glink_settings->speed;
            app->stats_hdr.auto_negotiation = app->glink_settings->autoneg;
            app->stats_hdr.duplex = app->glink_settings->duplex;
        }
    } else {
        app->glink_settings = calloc(1, sizeof(*app->glink_settings));

        if (likely(app->glink_settings)) {
            app->glink_settings->cmd = ETHTOOL_GLINKSETTINGS;
            goto fetch;
        } else {
            sys_error("calloc");
            return false;
        }
    }

    return true;
}

static bool fetch_stats(app* app)
{
    assert(app);

    struct {
           struct nlmsghdr nh;
           struct ifinfomsg info;
    } request;
    _Alignas(struct nlmsghdr) uint8_t response_buffer[4096];

    memset(&request, 0, sizeof(request));

    request.nh.nlmsg_len = NLMSG_LENGTH(sizeof(request.info));
    request.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    request.nh.nlmsg_type = RTM_GETLINK;
    request.nh.nlmsg_seq = ++app->netlink_seq_no;
    request.info.ifi_index = app->nic_index;
    request.info.ifi_change = 0xffffffff; // reserved for future use
    request.info.ifi_family = AF_UNSPEC;


    // submit request
    for (;;) {
        ssize_t w = send(app->netlink_socket_fd, &request, request.nh.nlmsg_len, 0);

        if (-1 == w) {
            switch (errno) {
            case EINTR:
                break;
            case EAGAIN:
                log_warn("rtnetlink send returned EAGAIN\n");
                return true;
            default:
                sys_error("rtnetlink send");
                return false;
            }
        } else if ((size_t)w < request.nh.nlmsg_len) {
            log_error("rtnetlink send short (%zi/%zu)\n", w, (size_t)request.nh.nlmsg_len);
            return false;
        } else {
            break;
        }
    }


    // read back response
    for (bool done = false; !done; ) {
        ssize_t r = recv(app->netlink_socket_fd, response_buffer, sizeof(response_buffer), 0);

        if (-1 == r) {
            switch (errno) {
            case EINTR:
                break;
            case EAGAIN:
                done = true;
                break;
            default:
                sys_error("rtnetlink recv");
                return false;
            }
        } else {
            for (struct nlmsghdr *nh = (struct nlmsghdr *)response_buffer; NLMSG_OK(nh, r); nh = NLMSG_NEXT(nh, r)) {
                if (nh->nlmsg_type == NLMSG_DONE) {
                    break;
                }

                void* data = NLMSG_DATA(nh);

                switch (nh->nlmsg_type) {
                case NLMSG_ERROR: {
                    struct nlmsgerr* error = data;

                    if (error->error) {
                        log_error("%s: %d\n", strerror(error->error), error->error);
                    }
                } break;
                case RTM_GETLINK:
                case RTM_NEWLINK:
                case RTM_DELLINK: {
                    struct ifinfomsg* ifinfomsg = (struct ifinfomsg*) data;

                    app->stats_hdr.link_detected  = (IFF_LOWER_UP & ifinfomsg->ifi_flags) == IFF_LOWER_UP;

                    for (struct rtattr *rta = IFLA_RTA(data); RTA_OK(rta, nh->nlmsg_len); rta = RTA_NEXT(rta, nh->nlmsg_len)) {
                        switch (rta->rta_type) {
                        case IFLA_STATS: {
                            struct rtnl_link_stats *stats = RTA_DATA(rta);

                            app->rtnetlink_stats = *stats;
                        } break;
                        case IFLA_MTU: {
                            app->stats_hdr.mtu = *(unsigned const*)RTA_DATA(rta);
                        } break;
                        }
                    }
                } break;
                default:
                    log_debug1("rtnetlink message type %u\n", nh->nlmsg_type);
                    break;
                }
            }
        }
    }

    return fetch_stats_glinksettings(app);
}

static void send_stats(app* app, int fd)
{
    assert(app);
    assert(fd >= 0);
    assert(fd < app->fd_slot_capacity);
    assert(app->fd_slot_ptr[fd].type == FD_SLOT_TYPE_TCP);

    struct teeth_eth_stats_hdr stats_hdr;
    struct tcp_slot* tcp = app->fd_slot_ptr[fd].data.tcp;
    struct teeth_nic_stats estats;

    app_assign_rtnetlink_stats(app, &estats);


    stats_hdr = app->stats_hdr;
    stats_hdr.tx_packets = estats.tx_packets - tcp->stats.tx_packets;
    stats_hdr.rx_packets = estats.rx_packets - tcp->stats.rx_packets;
    stats_hdr.tx_errors = estats.tx_errors - tcp->stats.tx_errors;
    stats_hdr.rx_errors = estats.rx_errors - tcp->stats.rx_errors;
    stats_hdr.rx_missed = estats.rx_missed - tcp->stats.rx_missed;

    // update client copy of counters
    tcp->stats = estats;

    if (likely(tcp->w_pipe_open)) {
        teeth_net_to_host_base(&stats_hdr.base);
        teeth_net_to_host_stats(&stats_hdr);

        if (!tcp_send(app, fd, &stats_hdr, sizeof(stats_hdr))) {
            tcp_on_change(app, fd);
        }
    }
}

static bool init_client(app* app, int fd)
{
    struct tcp_slot* tcp = NULL;
    socklen_t get_sndbuf_arg = 0;
    struct epoll_event ev;

    if (unlikely(!fd_slot_reserve(app, fd) || !epoll_reserve(app, app->event_count + 1))) {
        sys_error("realloc");
        return false;
    }

    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN | EPOLLET;

    tcp = tcp_new();

    if (unlikely(!tcp)) {
        goto Cleanup;
    }

    get_sndbuf_arg = sizeof(&tcp->tcp_send_buffer_size);

    if (-1 == getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &tcp->tcp_send_buffer_size, &get_sndbuf_arg)) {
        sys_error("failed to query TCP send buffer size");
        goto Cleanup;
    }

    log_debug2("TCP send buffer size %d (%d)\n", tcp->tcp_send_buffer_size, fd);

    if (tcp->tcp_send_buffer_size < 2 * TEETH_MAX_ETHER_PACKET_SIZE) {
        sys_error("TCP send buffer %d is too small (%d)\n", tcp->tcp_send_buffer_size, fd);
        goto Cleanup;
    }

    log_debug2("limit use of TCP send buffer to %d bytes (%d)\n", tcp->tcp_send_buffer_size, fd);

    tcp->tcp_send_buffer_size -= 2 * TEETH_MAX_ETHER_PACKET_SIZE;

    if (!tcp_disable_nagle(fd)) {
        log_warn("failed to disable Nagle's algorithm (%d)\n", fd);
    }

//    if (!sock_disable_linger(fd)) {
//        log_warn("failed to disable lingering (%d)\n", fd);
//    }

    if (!sock_set_nonblock(fd)) {
        sys_error("failed to make client socket non-blocking");
        goto Cleanup;
    }

    ev.data.fd = fd;

    if (-1 == epoll_ctl(app->epoll_fd, EPOLL_CTL_ADD, ev.data.fd, &ev)) {
        sys_error("failed to add client socket to epoll");
        goto Cleanup;
    }

    app_assign_rtnetlink_stats(app, &tcp->stats);

    log_debug1("client connected (%d)\n", fd);

    app->event_count += 1;


    app->fd_slot_ptr[fd].type = FD_SLOT_TYPE_TCP;
    ++app->fd_slot_ptr[fd].generation;
    app->fd_slot_ptr[fd].data.tcp = tcp;

Exit:
    return true;

Cleanup:
    shutdown(fd, SHUT_RDWR);
    safe_close(fd);

    goto Exit;
}

static struct tcp_slot* tcp_new()
{
    struct tcp_slot* tcp = calloc(1, sizeof(*tcp));

    if (likely(tcp)) {
        tcp->type = FD_SLOT_TYPE_TCP;
        tcp->w_pipe_open = 1;
        tcp->r_pipe_open = 1;
        tcp->state = STATE_READ_HEADER;
    }

    return tcp;
}

static bool on_packet_socket_event(app* app)
{
    struct teeth_eth_rx_hdr rx_hdr;
    struct teeth_eth_tx_res_hdr tx_res_hdr;
    bool fetch_stats = false;


    // rx
    for (;;) {
        size_t block_index = app->packet_ring_rx_block_current % app->packet_ring_setup.tp_block_nr;
        struct tpacket_block_desc* block_hdr = (struct tpacket_block_desc*)(app->packet_ring_rx_ptr + (block_index * app->packet_ring_setup.tp_block_size));

        assert(block_hdr->version == TPACKET_V3);

        if (!(__atomic_load_n(&block_hdr->hdr.bh1.block_status, __ATOMIC_ACQUIRE) & TP_STATUS_USER)) {
            break;
        }

        uint8_t* frame_base = (((uint8_t*)block_hdr) + block_hdr->hdr.bh1.offset_to_first_pkt);
        struct tpacket3_hdr* phdr = (struct tpacket3_hdr*)frame_base;


        for (size_t i = 0; i < block_hdr->hdr.bh1.num_pkts; ++i) {
            struct sockaddr_ll* ll = (struct sockaddr_ll*)(frame_base + TPACKET_ALIGN(sizeof(*phdr)));
            uint8_t *data = frame_base + phdr->tp_mac;


            if (g_log_level >= LOG_LEVEL_DEBUG3) {
                fprintf(
                            stdout,
                            "DEBUG: %011ld.%09ld %s wlen=%04u clen=%04u fcs=%02x%02x%02x%02x "
                            "%02x %02x %02x %02x %02x %02x %02x %02x "
                            "%02x %02x %02x %02x %02x %02x %02x %02x "
                            "...\n",
                            (long)phdr->tp_sec, (long)phdr->tp_nsec,
                            ll->sll_pkttype == PACKET_OUTGOING ? "TX" : "RX",
                            (unsigned)phdr->tp_len, (unsigned)phdr->tp_snaplen,
                            data[phdr->tp_snaplen-4], data[phdr->tp_snaplen-3], data[phdr->tp_snaplen-2], data[phdr->tp_snaplen-1],
                            data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
                        data[8], data[9], data[10], data[11], data[12], data[13], data[15], data[15]

                        );
            }

            uint64_t nanos = phdr->tp_nsec + UINT64_C(1000000000) * phdr->tp_sec;

            rx_hdr.base.version = TEETH_PROTOCOL_VERSION;
            rx_hdr.base.msg_type = TEETH_MT_ETH_RX;
            rx_hdr.base.len = sizeof(rx_hdr) + phdr->tp_snaplen;
            rx_hdr.flags = (((phdr->tp_status & TP_STATUS_COPY) == TP_STATUS_COPY) * TEETH_RX_FLAG_TRUNC);
            if (PACKET_OUTGOING == ll->sll_pkttype) {
                rx_hdr.flags |= TEETH_RX_FLAG_TX;
            } else {
                rx_hdr.flags |= app->rx_flags;
            }
            rx_hdr.ts_utc_nano = nanos;

            teeth_net_to_host_base(&rx_hdr.base);
            teeth_net_to_host_eth_rx(&rx_hdr);

            for (int fd = 0; fd < app->fd_slot_capacity; ++fd) {
                struct slot_entry *slot = &app->fd_slot_ptr[fd];
                struct tcp_slot *tcp = slot->data.tcp;

                if (slot->type != FD_SLOT_TYPE_TCP) {
                    continue;
                }

                if (!tcp->w_pipe_open) {
                    continue;
                }

                if (!tcp_send(app, fd, &rx_hdr, sizeof(rx_hdr)) || !tcp_send(app, fd, data, phdr->tp_snaplen)) {
                    tcp_on_change(app, fd);
                    continue;
                }
            }

            if (phdr->tp_status & TP_STATUS_LOSING) {
                fetch_stats = true;
            }

            frame_base += phdr->tp_next_offset;
            phdr = (struct tpacket3_hdr*)frame_base;
        }

        __atomic_store_n(&block_hdr->hdr.bh1.block_status, TP_STATUS_KERNEL, __ATOMIC_RELEASE);

        ++app->packet_ring_rx_block_current;
    }

     // tx
    while (app->packet_ring_tx_frame_get_no != app->packet_ring_tx_frame_put_no) {
        uint8_t* frame_base = app->packet_ring_tx_ptr + (app->packet_ring_tx_frame_get_no % app->packet_ring_setup.tp_frame_nr) * app->packet_ring_setup.tp_frame_size;
        struct tpacket3_hdr* phdr = (struct tpacket3_hdr*)frame_base;
        struct tx_ring_frame_data_priv* priv = (struct tx_ring_frame_data_priv*)(frame_base + app->packet_ring_setup.tp_frame_size - TX_PRIVATE_DATA_SIZE);

        tx_res_hdr.error = TEETH_TX_ERROR_NONE;

        uint32_t tp_status = __atomic_load_n(&phdr->tp_status, __ATOMIC_ACQUIRE);

        if (unlikely(tp_status & TP_STATUS_WRONG_FORMAT)) {
            log_debug1("malformed packet\n");
            tx_res_hdr.error = TEETH_TX_ERROR_MALFORMED;
            __atomic_store_n(&phdr->tp_status, TP_STATUS_AVAILABLE, __ATOMIC_RELEASE);
            tp_status = TP_STATUS_AVAILABLE;
        }

        if (tp_status & (TP_STATUS_SEND_REQUEST | TP_STATUS_SENDING)) {
            break;
        }

        log_debug3("tx get %lu\n", app->packet_ring_tx_frame_get_no % app->packet_ring_setup.tp_frame_nr);

        if (priv->tx_res.echo &&
            app->fd_slot_ptr[priv->tx_res.fd].generation == priv->tx_res.generation) {
            tx_res_hdr.base.len = sizeof(tx_res_hdr);
            tx_res_hdr.base.msg_type = TEETH_MT_ETH_TX_RES;
            tx_res_hdr.base.version = TEETH_PROTOCOL_VERSION;
            tx_res_hdr.track_id = priv->tx_res.track_id;
            tx_res_hdr.error = priv->tx_res.error;
            tx_res_hdr.ts_utc_nano = now_utc();

            teeth_net_to_host_base(&tx_res_hdr.base);
            teeth_net_to_host_eth_tx_res(&tx_res_hdr);

            if (!tcp_send(app, priv->tx_res.fd, &tx_res_hdr, sizeof(tx_res_hdr))) {
                tcp_on_change(app, priv->tx_res.fd);
            }
        }

        __atomic_store_n(&phdr->tp_status, TP_STATUS_AVAILABLE, __ATOMIC_RELEASE);

        ++app->packet_ring_tx_frame_get_no;
    }

    return true;
}

static bool packet_socket_set_time_stamping(int fd, char const* target_arg)
{
    struct ifreq ifr;
    struct ethtool_ts_info tsi;

    memset(&ifr, 0, sizeof(ifr));
    memset(&tsi, 0, sizeof(tsi));

    tsi.cmd = ETHTOOL_GET_TS_INFO;

    strncpy(ifr.ifr_name, target_arg, IFNAMSIZ-1);
    ifr.ifr_data = (caddr_t)&tsi;

    if (-1 == ioctl(fd, SIOCETHTOOL, &ifr)) {
        sys_error("ioctl(SIOCETHTOOL, ETHTOOL_GET_TS_INFO)");
        return false;
    }

    // and analyze the results
    if (tsi.so_timestamping & SOF_TIMESTAMPING_TX_HARDWARE) {
        log_info("%s supports hardware tx timestamps\n", ifr.ifr_name);
    }

    if (tsi.so_timestamping & SOF_TIMESTAMPING_TX_SOFTWARE) {
        log_info("%s supports software tx timestamps\n", ifr.ifr_name);
    }

    if (tsi.so_timestamping & SOF_TIMESTAMPING_RX_HARDWARE) {
        log_info("%s supports hardware rx timestamps\n", ifr.ifr_name);
    }

    if (tsi.so_timestamping & SOF_TIMESTAMPING_RX_SOFTWARE) {
        log_info("%s supports software rx timestamps\n", ifr.ifr_name);
    }


//        struct ifreq  req;
//        struct hwtstamp_config config;

//        memset(&req, 0, sizeof(req));
//        memset(&config, 0, sizeof(config));

//        config.tx_type = HWTSTAMP_TX_ON;
//        config.rx_filter = HWTSTAMP_FILTER_ALL;

//        strncpy(req.ifr_name, target_arg, IFNAMSIZ-1);
//        req.ifr_data = (caddr_t)&config;

//        if (-1 == ioctl(app.packet_socket_fd, SIOCSHWTSTAMP, &req)) {
//            switch (errno) {
//            case EOPNOTSUPP:
//                log_info("hw timestamping not available for %s, falling back to sw timestamping\n", target_arg);
//                break;
//            default:
//                sys_error("ioctl(SIOCSHWTSTAMP)");
//                error = 2;
//                goto Exit;
//            }
//        } else {
//            app.hw_ts_available = 1;
//            log_info("using available hw timestamping available for %s\n", target_arg);
//        }

    int flags =
            SOF_TIMESTAMPING_SOFTWARE |
            SOF_TIMESTAMPING_RX_SOFTWARE | // Request rx timestamps when data enters the kernel.
            SOF_TIMESTAMPING_TX_SOFTWARE;  // Request tx timestamps when data leaves the kernel.


//        const int so_timestampns = 1;
//        if (-1 == setsockopt(app.packet_socket_fd, SOL_SOCKET, SO_TIMESTAMPNS, &so_timestampns, sizeof(so_timestampns))) {
//            sys_error("setsockopt(SOL_SOCKET, SO_TIMESTAMPNS)");
//            error = 2;
//            goto Exit;
//        }

    if (-1 == setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags))) {
        sys_error("setsockopt(SOL_SOCKET, SO_TIMESTAMPING)");
        return false;
    }


    if (-1 == setsockopt(fd, SOL_PACKET, PACKET_TIMESTAMP, &flags, sizeof(flags))) {
        sys_error("setsockopt(SOL_PACKET, PACKET_TIMESTAMP)");
        return false;
    }

    return true;
}

static bool ethtool_try_set_feature(app* app, char const* feature_name, unsigned feature_index, unsigned feature_blocks, bool target_value, bool* out_feature_enabled)
{
    struct ifreq ifr;
    unsigned const feature_block_index = feature_index / 32;
    unsigned const feature_block_shift = feature_index - feature_block_index * 32;

    *out_feature_enabled = false;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, app->nic_name, IFNAMSIZ-1);

    struct ethtool_sfeatures* sfeatures = calloc(1, sizeof(*sfeatures) + sizeof(*sfeatures->features) * feature_blocks);
    if (sfeatures) {
        sfeatures->cmd = ETHTOOL_SFEATURES;
        sfeatures->size = feature_blocks;
        sfeatures->features[feature_block_index].requested = target_value ? (UINT32_C(1) << feature_block_shift) : 0;
        sfeatures->features[feature_block_index].valid = UINT32_C(1) << feature_block_shift;

        ifr.ifr_data = (caddr_t)sfeatures;

        if (-1 == ioctl(app->packet_socket_rx_fd, SIOCETHTOOL, &ifr)) {
            sys_error("ioctl(SIOCETHTOOL, ETHTOOL_SFEATURES)");
        }

        free(sfeatures);
        sfeatures = NULL;
    } else {
        sys_error("malloc");
        return false;
    }

    struct ethtool_gfeatures* gfeatures = calloc(1, sizeof(*gfeatures) + sizeof(*gfeatures->features) * feature_blocks);

    if (gfeatures) {
        gfeatures->cmd = ETHTOOL_GFEATURES;
        gfeatures->size = feature_blocks;

        ifr.ifr_data = (caddr_t)gfeatures;

        if (-1 == ioctl(app->packet_socket_rx_fd, SIOCETHTOOL, &ifr)) {
            sys_error("ioctl(SIOCETHTOOL, ETHTOOL_GFEATURES)");
        } else {
            uint32_t feature_bit = UINT32_C(1) << feature_block_shift;

            log_debug1(
                    "%s feat=%s available=%u requested=%u active=%u never_changed=%u\n",
                    app->nic_name,
                    feature_name,
                    (gfeatures->features[feature_block_index].available & feature_bit) != 0,
                    (gfeatures->features[feature_block_index].requested & feature_bit) != 0,
                    (gfeatures->features[feature_block_index].active & feature_bit) != 0,
                    (gfeatures->features[feature_block_index].never_changed & feature_bit) != 0);

            *out_feature_enabled = (gfeatures->features[feature_block_index].active & feature_bit) != 0;
        }

        free(gfeatures);
        gfeatures = NULL;
    } else {
        sys_error("malloc");
        return false;
    }

    return true;
}

static bool configure_nic(app* app)
{
    struct {
        struct ethtool_sset_info cmd;
        uint32_t set_lengths[ETH_SS_COUNT];
    } sset_info;

    const unsigned FEATURE_NOT_FOUND = ~0;
    unsigned rx_fcs_index = FEATURE_NOT_FOUND;
    unsigned tx_generic_segmentation_index = FEATURE_NOT_FOUND;
    unsigned features_set_length = FEATURE_NOT_FOUND;
    unsigned stats_set_length = FEATURE_NOT_FOUND;

    memset(&sset_info, 0, sizeof(sset_info));

    sset_info.cmd.cmd = ETHTOOL_GSSET_INFO;
    sset_info.cmd.sset_mask = (UINT64_C(1) << ETH_SS_COUNT) - 1;

    app->ifr.ifr_data = (caddr_t)&sset_info;

    if (-1 == ioctl(app->packet_socket_tx_fd, SIOCETHTOOL, &app->ifr)) {
        sys_error("ioctl(SIOCETHTOOL, ETHTOOL_GSSET_INFO)");
        return false;
    } else {
        uint32_t max = 0;

        for (unsigned ss = 0, j = 0; ss < ETH_SS_COUNT; ++ss) {
            uint32_t bit = UINT32_C(1) << ss;

            if (sset_info.cmd.sset_mask & bit) {
                uint32_t len = sset_info.set_lengths[j++];

                if (len > max) {
                    max = len;
                }

                switch (ss) {
                case ETH_SS_STATS:
                    stats_set_length = len;
                    break;
                case ETH_SS_FEATURES:
                    features_set_length = len;
                    break;
                }
            }
        }

        struct ethtool_gstrings* gstrings = (struct ethtool_gstrings*)malloc(sizeof(*gstrings) + ETH_GSTRING_LEN * max);

        if (!gstrings) {
            sys_error("malloc");
            return false;
        }

        gstrings->cmd = ETHTOOL_GSTRINGS;
        app->ifr.ifr_data = (caddr_t)gstrings;

        for (uint32_t ss = 0; ss < ETH_SS_COUNT; ++ss) {
            uint64_t bit = UINT64_C(1) << ss;

            if (sset_info.cmd.sset_mask & bit) {
                gstrings->len = 0;
                gstrings->string_set = ss;

                if (-1 == ioctl(app->packet_socket_tx_fd, SIOCETHTOOL, &app->ifr)) {
                    sys_error("ioctl(SIOCETHTOOL, ETHTOOL_GSTRINGS)");
                    return false;
                } else {
                    for (uint32_t j = 0; j < gstrings->len; ++j) {
                        char* str = &gstrings->data[j * ETH_GSTRING_LEN];

                        log_debug1("%s string set index %u, string index %u: %s\n", app->nic_name, ss, j, str);

                        switch (ss) {
                        case ETH_SS_FEATURES: {
                            if (0 == strcmp("rx-fcs", str)) {
                                rx_fcs_index = j;
                            } else if (0 == strcmp("tx-generic-segmentation", str)) {
                                tx_generic_segmentation_index = j;
                            }
                        } break;
                        }
                    }
                }
            }
        }

        free(gstrings);
    }

    if (features_set_length != FEATURE_NOT_FOUND) {
        unsigned const feature_blocks = (features_set_length + 31) / 32;

        if (FEATURE_NOT_FOUND != rx_fcs_index) {
            bool rx_fcs_reported = false;

            if (!ethtool_try_set_feature(app, "rx-fcs", rx_fcs_index, feature_blocks, true, &rx_fcs_reported)) {
                return false;
            }

            if (rx_fcs_reported) {
                app->rx_flags |= TEETH_RX_FLAG_FCS_PRESENT;
            } else {
                app->rx_flags &= ~TEETH_RX_FLAG_FCS_PRESENT;
            }
        }

        if (FEATURE_NOT_FOUND != tx_generic_segmentation_index) {
            bool on = false;

            if (!ethtool_try_set_feature(app, "tx-generic-segmentation", tx_generic_segmentation_index, feature_blocks, false, &on)) {
                return false;
            }

            if (on) {
                log_warn("%s failed to disable %s\n", app->nic_name, "tx-generic-segmentation");
            }
        }
    }

    app->stats_hdr.mtu = DEFAULT_MTU;
    app->ifr.ifr_mtu = app->stats_hdr.mtu;

    if (-1 == ioctl(app->packet_socket_rx_fd, SIOCSIFMTU, &app->ifr)) {
        sys_error("%s failed to set MTU to %u", app->nic_name, app->stats_hdr.mtu);
        return false;
    }

    return true;
}

static bool setup_packet_socket(app* app, char const* target_arg)
{
    int const packet_ring_version = TPACKET_V3;
    const int packet_ignore_outgoing = 0;
    const int packet_loss = 0;
    struct sockaddr_ll packet_socket_bind_address;
    int const protocol = htons(ETH_P_ALL);

    memset(&packet_socket_bind_address, 0, sizeof(packet_socket_bind_address));

    app->nic_name = target_arg;
    app->nic_index = if_nametoindex(target_arg);
    strncpy(app->ifr.ifr_name, app->nic_name, IFNAMSIZ-1);


    packet_socket_bind_address.sll_family = PF_PACKET;
    packet_socket_bind_address.sll_protocol = protocol;
    packet_socket_bind_address.sll_ifindex = app->nic_index;

    if (0 == app->nic_index) {
        sys_error("failed to get index for interface name %s", target_arg);
        return false;
    }

    app->packet_socket_rx_fd = socket(AF_PACKET, SOCK_RAW, protocol);
    if (-1 == app->packet_socket_rx_fd) {
        sys_error("failed to create raw ethernet socket");
        return false;
    }

    /* NOTE: we need a dedicated socket to send on, else we won't
     * get a TX echo frame.
     */
    app->packet_socket_tx_fd = socket(AF_PACKET, SOCK_RAW, protocol);
    if (-1 == app->packet_socket_tx_fd) {
        sys_error("failed to create raw ethernet socket");
        return false;
    }

    if (!packet_socket_set_time_stamping(app->packet_socket_rx_fd, target_arg)) {
        return false;
    }


//    // enable echo -> doesn't work on RX ring socket
//    if (-1 == ioctl(app->packet_socket_rx_fd, SIOCGIFFLAGS, &app->ifr)) {
//        sys_error("ioctl(SIOCGIFINDEX)");
//        return false;
//    }

//    app->ifr.ifr_flags |= IFF_ECHO;

//    if (-1 == ioctl(app->packet_socket_rx_fd, SIOCSIFFLAGS, &app->ifr)) {
//        sys_error("ioctl(SIOCSIFINDEX)");
//        return false;
//    }

    if (-1 == setsockopt(app->packet_socket_rx_fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &packet_ignore_outgoing, sizeof(packet_ignore_outgoing))) {
        sys_error("setsockopt(SOL_PACKET, PACKET_IGNORE_OUTGOING, %d)", packet_ignore_outgoing);
        return false;
    }


    if (-1 == setsockopt(app->packet_socket_tx_fd, SOL_PACKET, PACKET_LOSS, &packet_loss, sizeof(packet_loss))) {
        sys_error("setsockopt(SOL_PACKET, PACKET_LOSS, %d)", packet_loss);
        return false;
    }


    if (-1 == setsockopt(app->packet_socket_rx_fd, SOL_PACKET, PACKET_VERSION, &packet_ring_version, sizeof(packet_ring_version))) {
        sys_error("packet ring version 3 (%d) unsupported", packet_ring_version);
        return false;
    }

    if (-1 == setsockopt(app->packet_socket_tx_fd, SOL_PACKET, PACKET_VERSION, &packet_ring_version, sizeof(packet_ring_version))) {
        sys_error("packet ring version 3 (%d) unsupported", packet_ring_version);
        return false;
    }


    // setup ring
    {
        unsigned const page_size = sysconf(_SC_PAGESIZE);
        unsigned const frame_size = TPACKET_ALIGN(sizeof(struct tpacket3_hdr)) + TPACKET_ALIGN(sizeof(struct sockaddr_ll)) + TPACKET_ALIGN(TEETH_BUFFER_SIZE + TX_PRIVATE_DATA_SIZE);
//        unsigned frames_per_page = page_size / frame_size;

        app->packet_ring_setup.tp_frame_size = frame_size;
        app->packet_ring_setup.tp_block_size = page_size << 10;
        app->packet_ring_setup.tp_block_nr = (1u<<24) / app->packet_ring_setup.tp_block_size;  // 16MiB
        app->packet_ring_setup.tp_frame_nr = (app->packet_ring_setup.tp_block_size * app->packet_ring_setup.tp_block_nr) / app->packet_ring_setup.tp_frame_size;
        app->frames_per_block = app->packet_ring_setup.tp_block_size / app->packet_ring_setup.tp_frame_size;

        if (-1 == setsockopt(app->packet_socket_rx_fd, SOL_PACKET, PACKET_RX_RING, &app->packet_ring_setup, sizeof(app->packet_ring_setup))) {
            sys_error("packet ring rx setup");
            return false;
        }

        if (-1 == setsockopt(app->packet_socket_tx_fd, SOL_PACKET, PACKET_TX_RING, &app->packet_ring_setup, sizeof(app->packet_ring_setup))) {
            sys_error("packet ring rx setup");
            return false;
        }

        app->packet_ring_rx_ptr = mmap(NULL, app->packet_ring_setup.tp_block_nr * app->packet_ring_setup.tp_block_size, PROT_READ|PROT_WRITE, MAP_SHARED, app->packet_socket_rx_fd, 0);

        if (!app->packet_ring_rx_ptr) {
            sys_error("mmap");
            return false;
        }

        app->packet_ring_tx_ptr = mmap(NULL, app->packet_ring_setup.tp_block_nr * app->packet_ring_setup.tp_block_size, PROT_READ|PROT_WRITE, MAP_SHARED, app->packet_socket_tx_fd, 0);

        if (!app->packet_ring_tx_ptr) {
            sys_error("mmap");
            return false;
        }
    }


    if (-1 == bind(app->packet_socket_rx_fd, (struct sockaddr*)&packet_socket_bind_address, sizeof(packet_socket_bind_address))) {
        sys_error("failed to bind packet socket to %s", target_arg);
        return false;
    }

    if (-1 == bind(app->packet_socket_tx_fd, (struct sockaddr*)&packet_socket_bind_address, sizeof(packet_socket_bind_address))) {
        sys_error("failed to bind packet socket to %s", target_arg);
        return false;
    }

//    {
//        struct packet_mreq mreq;

//        memset(&mreq, 0, sizeof(mreq));

//        mreq.mr_ifindex = app->nic_index;
//        mreq.mr_type = PACKET_MR_PROMISC;
////        mreq.mr_alen = 6;

//        if (-1 == setsockopt(app->packet_socket_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
//            sys_error("failed to enable promiscuous mode for %s", target_arg);
//            return false;
//        }
//    }

//    if (!sock_set_nonblock(app->packet_socket_fd)) {
//        sys_error("failed to make socket non-blocking");
//        return false;
//    }

    app->netlink_socket_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (-1 == app->netlink_socket_fd) {
        sys_error("failed to create NETLINK_ROUTE socket to %s", target_arg);
        return false;
    }

    if (!sock_set_nonblock(app->netlink_socket_fd)) {
        sys_error("failed to make socket non-blocking");
        return false;
    }

    /* looks like we don't need to bind at all
     *
    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;


    if (-1 == bind(app->netlink_socket_fd, (struct sockaddr *) &sa, sizeof(sa))) {
        sys_error("failed to bind NETLINK_ROUTE socket");
        return false;
    }
    */


    if (!configure_nic(app)) {
        return false;
    }

    if (!fetch_stats(app)) {
        return false;
    }

    return true;
}
