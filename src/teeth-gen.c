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
#include <sys/epoll.h>
#include <stdint.h>
#include <assert.h>
#include <sys/timerfd.h>
#include <netdb.h>
#include <inttypes.h>



#include "lib.h"


#define DEFAULT_GEN_INTERVAL_MS 200

#define DEFAULT_ETHER_TYPE 0x1234
#define MIN_FRAME_LENGTH 64
#define DEFAULT_FRAME_LENGTH MIN_FRAME_LENGTH


enum tristate {
    TRISTATE_NOTSET = -1,
    TRISTATE_NO,
    TRISTATE_YES
};

static void usage(FILE* stream)
{
    fprintf(stream, "teeth [OPTIONS] HOST PORT\n\n");
    fprintf(stream, "  -d, --dst-mac MAC      default (ff:ff:ff:ff:ff:ff)\n");
    fprintf(stream, "  -h, --help             print this help\n");
    fprintf(stream, "  -e, --ether-type HEX   ether type (default %04x)\n", DEFAULT_ETHER_TYPE);
    fprintf(stream, "  -g MILLIS              interval in millis to generate packets (default %d)\n", DEFAULT_GEN_INTERVAL_MS);
    fprintf(stream, "      --length           frame length (default %d\n", DEFAULT_FRAME_LENGTH);
    fprintf(stream, "  -l, --local            make source MAC locally administered (default universal, that is globally unique)\n");
    fprintf(stream, "  -m, --multicast        make source MAC multicast (default unicast)\n");
    fprintf(stream, "  -n COUNT               number of packets to send (dfault continue sending)\n");
    fprintf(stream, "  -s, --src-mac MAC      defaults to randomly assigned MAC\n");
    fprintf(stream, "  -v, --verbose          increase verbosity\n");
    fprintf(stream, "\n");
}




enum {
    STATE_READ_HEADER,
    STATE_READ_DATA,
    STATE_OP,
};

static bool parse_mac(char const* str, uint8_t* mac)
{
    char* end;

    for (int i = 0; i < 6; ++i) {
        if (!*str) {
            return false;
        }

        if (*str == ':') {
            ++str;
        }

        end = NULL;

        mac[i] = strtoul(str, &end, 16);

        if (str == end) {
            return false;
        }

        str = end;
    }

    return true;
}

static bool send_to_server(int sock_fd, uint8_t const* ptr, size_t bytes)
{
    for (size_t offset = 0; offset < bytes; ) {
        ssize_t w = send(sock_fd, ptr + offset, bytes - offset, MSG_NOSIGNAL);

        if (-1 == w) {
            switch (errno) {
            case EINTR:
                break;
            case EAGAIN:
                log_error("server rx queue full");
                return false;
            default:
                log_error("socket failed");
                return false;
            }
        } else if (0 == w) {
            log_error("server connection closed");
            return false;
        } else {
            offset += w;
        }
    }

    return true;
}

static bool tcp_send(int fd, void const* ptr, size_t bytes)
{
    for (;;) {
        ssize_t w = send(fd, ptr, bytes, MSG_NOSIGNAL);

        if (-1 == w) {
            switch (errno) {
            case EINTR:
                break;
            default:
                return false;
            }
        } else if (0 == w) {
            return false;
        } else if ((size_t)w != bytes) {
            return false;
        } else {
            break;
        }
    }

    return true;
}


int main(int argc, char** argv)
{
    char* host_arg = NULL;
    char* port_arg = NULL;
    int sock_fd = -1;
    int error = 0;
    int epoll_fd = -1;
    int tcp_send_buffer_size = -1;
    int timer_fd = -1;
    int urandom_fd = -1;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    bool randomize_src_mac = true;
    long gen_interval_ms = DEFAULT_GEN_INTERVAL_MS;
    long target_frame_length = DEFAULT_FRAME_LENGTH;
    _Alignas(8) uint8_t tx_buffer[TEETH_MAX_ETHER_PACKET_SIZE + sizeof(struct teeth_eth_tx_req_hdr)];
    _Alignas(8) uint8_t rx_buffer[TEETH_MAX_ETHER_PACKET_SIZE + sizeof(struct teeth_eth_tx_req_hdr)];
    struct teeth_eth_tx_req_hdr* const tx = (struct teeth_eth_tx_req_hdr*)tx_buffer;
    uint64_t tx_counter = 0;
    int64_t want_count = -1;
    uint16_t ether_type_net = htons(DEFAULT_ETHER_TYPE);
    enum tristate multicast = TRISTATE_NO;
    enum tristate local = TRISTATE_NO;
    struct addrinfo* addresses = NULL;
    struct epoll_event events[3];

    memset(dst_mac, 0xff, sizeof(dst_mac));



    for (int option_index = 0;;) {
        static const struct option long_options[] = {
            {"dst-mac",     required_argument,  NULL, 'd' },
            {"ether-type",  required_argument,  NULL, 'e' },
            {"length",      required_argument,  NULL, 0x100 },
            {"local",       no_argument      ,  NULL, 'l' },
            {"help",        no_argument,        NULL, 'h' },
            {"multicast",   no_argument,        NULL, 'm' },
            {"verbose",     no_argument,        NULL, 'v' },
            {"src-mac",     required_argument,  NULL, 's' },
            {NULL,          0,                  NULL, 0 }
        };

        int c = getopt_long(argc, argv, "d:e:g:hn:s:v", long_options, &option_index);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 0:
            if (0 == strcmp("src-mac", long_options[option_index].name)) {
                goto parse_src_mac;
            } else if (0 == strcmp("dst-mac", long_options[option_index].name)) {
                goto parse_dst_mac;
            } else if (0 == strcmp("multicast", long_options[option_index].name)) {
                goto mulitcast;
            } else if (0 == strcmp("local", long_options[option_index].name)) {
                goto local;
            } else if (0 == strcmp("ether-type", long_options[option_index].name)) {
                goto ether_type;
            }
            break;
parse_dst_mac:
        case 'd':
            if (parse_mac(optarg, dst_mac)) {

            } else {
                log_error("failed to parse MAC from '%s'\n", optarg);
                error = 1;
                goto Exit;
            }
            break;
ether_type:
        case 'e':
            ether_type_net = htons((uint16_t)strtoul(optarg, NULL, 16));
            break;
        case 'g':
            gen_interval_ms = strtol(optarg, NULL, 10);
            break;
        case 'h':
            usage(stdout);
            goto Exit;
local:
        case 'l':
            local = TRISTATE_YES;
            break;
mulitcast:
        case 'm':
            multicast = TRISTATE_YES;
            break;
        case 'n':
            want_count = strtoll(optarg, NULL, 10);
            break;
parse_src_mac:
        case 's':
            if (parse_mac(optarg, src_mac)) {
                randomize_src_mac = false;
                local = TRISTATE_NOTSET;
                multicast = TRISTATE_NOTSET;
            } else {
                log_error("failed to parse MAC from '%s'\n", optarg);
                error = 1;
                goto Exit;
            }
            break;
        case 'v':
            ++g_log_level;
            break;
        case '?':
            // bad option
            error = 1;
            goto Exit;
        case ':':
            // missing arg
            break;
        case 0x100:
            target_frame_length = strtoll(optarg, NULL, 10);

            if (target_frame_length <= MIN_FRAME_LENGTH) {
                log_error("frame length '%s' invalid (min. length is %d bytes)\n", optarg, MIN_FRAME_LENGTH);
                error = 1;
                goto Exit;
            }
            break;
        default:
            printf("?? getopt returned character code 0%o ??\n", c);
            error = 1;
            goto Exit;
        }
    }

    if (optind + 2 != argc) {
        log_error("two non-option arguments required.\n");
        error = 1;
        goto Exit;
    }


    host_arg = argv[optind];
    port_arg = argv[optind+1];


    urandom_fd = open("/dev/urandom", O_RDONLY);
    if (-1 == urandom_fd) {
        sys_error("failed to open /dev/urandom for reading");
        error = 2;
        goto Exit;
    }

    if (randomize_src_mac) {
        for (bool done = false; !done; ) {
            ssize_t r = read(urandom_fd, src_mac, sizeof(src_mac));

            if (-1 == r) {
                switch (errno) {
                case EINTR:
                    break;
                default:
                    sys_error("failed to read from /dev/urandom");
                    error = 2;
                    goto Exit;
                }
            } else if ((size_t)r != sizeof(src_mac)) {
                log_error("failed to read from /dev/urandom\n");
                error = 2;
                goto Exit;
            } else {
                done = true;
            }
        }

        switch (multicast) {
        case TRISTATE_YES:
            src_mac[0] |= 0x01;
            break;
        case TRISTATE_NO:
            src_mac[0] &= ~0x01;
            break;
        }

        switch (local) {
        case TRISTATE_YES:
            src_mac[0] |= 0x02;
            break;
        case TRISTATE_NO:
            src_mac[0] &= ~0x02;
            break;
        }
    }

    {
        struct addrinfo hints;

        memset(&hints, 0, sizeof(hints));

        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_family = AF_INET6;
        hints.ai_flags = AI_V4MAPPED | AI_ADDRCONFIG;


        for (int i = 0; i < 10; ++i) {
            error = getaddrinfo(host_arg, port_arg, &hints, &addresses);

            if (0 == error) {
                break;
            }

            if (EAI_AGAIN == error) {
                usleep(100000);
            } else {
                log_error("failed to resolve %s:%s: %s (%d)\n", host_arg, port_arg, gai_strerror(error), error);
                error = 2;
                goto Exit;
            }
        }
    }

    sock_fd = socket(addresses->ai_family, addresses->ai_socktype, addresses->ai_protocol);
    if (-1 == sock_fd) {
        sys_error("failed to create socket");
        error = 2;
        goto Exit;
    }

    for (;;) {
        if (-1 == connect(sock_fd, addresses->ai_addr, addresses->ai_addrlen)) {
            switch (errno) {
            case EINTR:
                break;
            default:
                sys_error("failed to connect to %s %s", host_arg, port_arg);
                error = 2;
                goto Exit;
            }
        } else {
            break;
        }
    }

//    if (!sock_disable_linger(sock_fd)) {
//        log_warn("failed to disable lingering\n");
//    }

//    // shut down read half
//    if (-1 == shutdown(sock_fd, SHUT_RD)) {
//        sys_error("failed to shut down read half");
//        error = 2;
//        goto Exit;
//    }

    if (!sock_keep_alive(sock_fd)) {
        log_warn("failed to enable keep-alive\n");
    }

    {
        socklen_t get_sndbuf_arg = sizeof(tcp_send_buffer_size);

        if (-1 == getsockopt(sock_fd, SOL_SOCKET, SO_SNDBUF, &tcp_send_buffer_size, &get_sndbuf_arg)) {
            sys_error("failed to get TCP socket send buffer size");
            error = 2;
            goto Exit;
        }

        if (tcp_send_buffer_size <= 2 * TEETH_MAX_ETHER_PACKET_SIZE) {
            log_error("TCP send buffer %d is too small\n", tcp_send_buffer_size);
            error = 1;
            goto Exit;
        }

        // save some space so we don't run into writes that fail
        tcp_send_buffer_size -= TEETH_MAX_ETHER_PACKET_SIZE;
    }

    log_debug2("TCP send buffer size %d (%d)\n", tcp_send_buffer_size, sock_fd);

    if (!sock_set_nonblock(sock_fd)) {
        sys_error("failed to make socket non-blocking");
        error = 2;
        goto Exit;
    }


    timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (-1 == timer_fd) {
        sys_error("failed to create timer");
        error = 2;
        goto Exit;
    }

    {
        struct itimerspec spec;
        uint64_t interval_nanos = (gen_interval_ms > 0 ? (gen_interval_ms * UINT64_C(1000000)) : 1u);

        spec.it_value.tv_nsec = 1;
        spec.it_value.tv_sec = 0;
        spec.it_interval.tv_sec = interval_nanos / UINT64_C(1000000000);
        spec.it_interval.tv_nsec = interval_nanos - spec.it_interval.tv_sec * UINT64_C(1000000000);

        if (-1 == timerfd_settime(timer_fd, 0, &spec, NULL)) {
            sys_error("failed to set timer");
            error = 2;
            goto Exit;
        }
    }

    if (!teeth_signal_handler_init()) {
        sys_error("failed to initialize signal handler");
        error = 2;
        goto Exit;
    }


    epoll_fd = epoll_create1(0);
    if (-1 == epoll_fd) {
        sys_error("failed to create epoll instance");
        error = 2;
        goto Exit;
    }

    {
        memset(events, 0, sizeof(events));

        events[0].data.fd = sock_fd;
        events[0].events = EPOLLIN | EPOLLET;
        events[1].data.fd = timer_fd;
        events[1].events = EPOLLIN | EPOLLET;
        events[2].data.fd = teeth_signal_handler_fd;
        events[2].events = TEETH_SIGNAL_HANDLER_EPOLL_FLAGS;

        for (size_t i = 0; i < ARRAY_SIZE(events); ++i) {
            if (-1 == epoll_ctl(epoll_fd, EPOLL_CTL_ADD, events[i].data.fd, &events[i])) {
                sys_error("failed to register fd with epoll");
                error = 2;
                goto Exit;
            }
        }
    }

    teeth_signal_handler_arm();

    for (;;) {
        int count = epoll_wait(epoll_fd, events, ARRAY_SIZE(events), -1);

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
                if (sock_fd == events[i].data.fd) {
                    if (events[i].events & EPOLLERR) {
                        log_error("socket failed\n");
                        error = 2;
                        goto Exit;
                    }

                    // drain
                    for (bool done = false; !done; ) {
                        ssize_t r = recv(sock_fd, rx_buffer, sizeof(rx_buffer), 0);

                        if (-1 == r) {
                            switch (errno) {
                            case EINTR:
                                break;
                            case EAGAIN:
                                done = true;
                                break;
                            default:
                                sys_error("recv");
                                error = 2;
                                goto Exit;
                            }
                        } else if (0 == r) {
                            log_debug1("server closed connection\n");
                            goto Exit;
                        }
                    }
                } else if (timer_fd == events[i].data.fd) {
                    if (events[i].events & EPOLLERR) {
                        log_error("timer failed");
                        error = 2;
                        goto Exit;
                    }

                    if (!timerfd_drain(timer_fd)) {
                        error = 2;
                        goto Exit;
                    }

                    log_debug1("gen message %" PRIu64 "\n", tx_counter);

                    // assemble and send ethernet frame
                    uint8_t* frame = tx_buffer + sizeof(*tx);
                    size_t frame_length = 0;
                    memcpy(&frame[frame_length], dst_mac, sizeof(dst_mac));
                    frame_length += sizeof(dst_mac);
                    memcpy(&frame[frame_length], src_mac, sizeof(src_mac));
                    frame_length += sizeof(src_mac);
                    memcpy(&frame[frame_length], &ether_type_net, sizeof(ether_type_net));
                    frame_length += sizeof(ether_type_net);
                    int chars = sprintf(&frame[frame_length], "Hello, ethernet world!\nCounter = %013lu\n", tx_counter);
                    frame_length += chars;

                    if (frame_length < target_frame_length) {
                        frame_length = target_frame_length;
                    }

                    size_t const tx_len = sizeof(*tx) + frame_length;

                    tx->base.len = tx_len;
                    tx->base.msg_type = TEETH_MT_ETH_TX_REQ;
                    tx->base.version = TEETH_PROTOCOL_VERSION;
                    tx->flags = TEETH_TX_FLAG_SUPPRESS_RESPONSE;
                    tx->track_id = tx_counter;

                    teeth_net_to_host_base(&tx->base);
                    teeth_net_to_host_eth_tx_req(tx);

                    size_t tx_queued = 0;

                    if (!tcp_out_queued(sock_fd, &tx_queued)) {
                        sys_error("failed to get TCP socket pending byte count");
                        error = 2;
                        goto Exit;
                    }

                    if (tx_queued + tx_len <= tcp_send_buffer_size) {
                        if (!tcp_send(sock_fd, tx_buffer, tx_len)) {
                            sys_error("failed to send to server");
                            error = 2;
                            goto Exit;
                        }
                    } else {
                        log_debug3("no space in TCP output buffer\n");
                    }

                    ++tx_counter;

                    if (want_count > 0 && (uint64_t)want_count == tx_counter) {
                        log_debug3("target count of %ld reached, quitting", want_count);
                        goto Exit;
                    }
                } else if (teeth_signal_handler_fd == events[i].data.fd) {
                    log_info("shutting down\n");
                    goto Exit;
                }
            }

        }
    }


Exit:
    if (-1 != epoll_fd) {
        close(epoll_fd);
    }

    if (-1 != sock_fd) {
        close(sock_fd);
    }

    if (-1 != timer_fd) {
        close(timer_fd);
    }

    if (addresses) {
        freeaddrinfo(addresses);
    }

    if (-1 != urandom_fd) {
        close(urandom_fd);
    }

    teeth_signal_handler_uninit();

    fflush(stdout);

    return error;
}
