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
#include <inttypes.h>
#include <stdbool.h>
#include <netdb.h>

#include "lib.h"

#define DEFAULT_LENGTH 64


static void usage(FILE* stream)
{
    fprintf(stream, "teeth-dump [OPTIONS] HOST PORT\n\n");
    fprintf(stream, "-l, --length           number of bytes to print (default %d)\n", DEFAULT_LENGTH);
    fprintf(stream, "-v, --verbose          increase verbosity\n");
    fprintf(stream, "    --close-write-half \n");
    fprintf(stream, "\n");
}


enum {
    STATE_READ_HEADER,
    STATE_READ_DATA,
    STATE_OP,
};


int main(int argc, char** argv)
{
    char* host_arg = NULL;
    char* port_arg = NULL;
    int sock_fd = -1;
    int error = 0;
    int epoll_fd = -1;
    int print_len = DEFAULT_LENGTH;
    int state = STATE_READ_HEADER;
    bool close_write_half = false;
    struct addrinfo* addresses = NULL;
    struct epoll_event events[2];
    size_t rx_offset = 0;
    _Alignas(8) uint8_t rx_buffer[TEETH_BUFFER_SIZE];
    struct teeth_base_hdr* const base = (struct teeth_base_hdr*)rx_buffer;

    for (int option_index = 0;;) {
        static const struct option long_options[] = {
            {"close-write-half",    no_argument,        0, 0x100 },
            {"length",              required_argument,  0, 'l' },
            {"verbose",             no_argument,        0, 'v' },

            {0,                     0,                  0, 0 }
        };

        int c = getopt_long(argc, argv, "l:v", long_options, &option_index);

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'l': {
            char* end = NULL;

            print_len = strtol(optarg, &end, 10);

            if (!end || end == optarg || print_len < 0) {
                log_error("invalid argument '%s'\n", optarg);
                error = 1;
                goto Exit;
            }
        } break;
        case 'v':
            ++g_log_level;
            break;
        case 0x100:
            close_write_half = true;
            break;
        default:
            usage(stderr);
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

    if (!sock_keep_alive(sock_fd)) {
        log_warn("failed to enable keep-alive\n");
    }

    if (!sock_set_nonblock(sock_fd)) {
        sys_error("failed to make socket non-blocking");
        error = 2;
        goto Exit;
    }

    if (close_write_half) {
        // shut down write half
        if (-1 == shutdown(sock_fd, SHUT_WR)) {
            sys_error("failed to shut down write half");
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
        events[1].data.fd = teeth_signal_handler_fd;
        events[1].events = TEETH_SIGNAL_HANDLER_EPOLL_FLAGS;

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

                    for (;;) {
                        switch (state) {
                        case STATE_READ_HEADER: {
                            for (;;) {
                                ssize_t r = recv(sock_fd, rx_buffer + rx_offset, sizeof(*base) - rx_offset, 0);

                                if (-1 == r) {
                                    switch (errno) {
                                    case EINTR:
                                        break;
                                    case EAGAIN:
                                        goto done;
                                    default:
                                        sys_error("recv");
                                        error = 2;
                                        goto Exit;
                                    }
                                } else if (0 == r) {
                                    log_error("server closed connection\n");
                                    error = 3;
                                    goto Exit;
                                } else {
                                    rx_offset += r;

                                    if (rx_offset == sizeof(*base)) {
                                        teeth_net_to_host_base(base);

                                        switch (base->version) {
                                        case TEETH_PROTOCOL_VERSION:
                                            if (base->len < sizeof(*base)) {
                                                log_error("server sent short header, bailing\n");
                                                error = 4;
                                                goto Exit;
                                            }

                                            state = base->len == sizeof(*base) ? STATE_OP : STATE_READ_DATA;
                                            break;
                                        default:
                                            log_error("unknown protocol version %u\n", base->version);
                                            error = 4;
                                            goto Exit;
                                        }
                                        break;
                                    }
                                }
                            }
                        } break;
                        case STATE_READ_DATA: {
                            for (;;) {
                                ssize_t r = recv(sock_fd, rx_buffer + rx_offset, base->len - rx_offset, 0);

                                if (-1 == r) {
                                    switch (errno) {
                                    case EINTR:
                                        break;
                                    case EAGAIN:
                                        goto done;
                                    default:
                                        sys_error("recv");
                                        error = 2;
                                        goto Exit;
                                    }
                                } else if (0 == r) {
                                    log_error("server closed connection\n");
                                    error = 3;
                                    goto Exit;
                                } else {
                                    rx_offset += r;

                                    if (rx_offset == base->len) {
                                        state = STATE_OP;
                                        break;
                                    }
                                }
                            }
                        } break;
                        case STATE_OP: {
                            state = STATE_READ_HEADER;
                            rx_offset = 0;

                            switch (base->msg_type) {
                            case TEETH_MT_ETH_RX: {
                                struct teeth_eth_rx_hdr* rx = (struct teeth_eth_rx_hdr*)rx_buffer;
                                uint8_t* frame = rx_buffer + sizeof(*rx);

                                teeth_net_to_host_eth_rx(rx);


                                uint64_t seconds = rx->ts_utc_nano / UINT64_C(1000000000);
                                uint_least32_t nanos = rx->ts_utc_nano - UINT64_C(1000000000) * seconds;
                                unsigned frame_len = base->len - sizeof(*rx);
                                int len = frame_len;

                                if (len > print_len) {
                                    len = print_len;
                                }

                                fprintf(stdout, "%013" PRIu64 ".%09" PRIuLEAST32 " %05u %s ", seconds, nanos, frame_len, (rx->flags & TEETH_RX_FLAG_TX) ? "TX" : "RX");

                                for (int i = 0; i < len; ++i) {
                                    fprintf(stdout, "%02x ", frame[i]);
                                }

                                fprintf(stdout, "\n");
                            } break;
                            default:
                                break;
                            }
                        } break;
                        }
                    }
done:
                    ;

                } else if (teeth_signal_handler_fd == events[i].data.fd) {
                    log_info("shutting down\n");
                    goto Exit;
                }
            }

        }
    }


Exit:
    if (-1 != epoll_fd) {
        safe_close(epoll_fd);
    }

    if (-1 != sock_fd) {
        shutdown(sock_fd, SHUT_RDWR);
        safe_close(sock_fd);
    }

    if (addresses) {
        freeaddrinfo(addresses);
    }

    teeth_signal_handler_uninit();

    return error;
}
