/* SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2024 Jean Gressmann <jean@0x42.de>
 *
 */

#include <assert.h>
#include <unistd.h>
#include <sys/signalfd.h>
#include <signal.h>
#include <errno.h>

#include "lib.h"


int g_log_level = LOG_LEVEL_WARNING;

bool safe_close_ref(int* fd)
{
    assert(fd);

    if (-1 != *fd) {
        while (-1 == close(*fd) && errno == EINTR);

        *fd = -1;

        return true;
    }

    return false;
}


int teeth_signal_handler_fd = -1;
static sigset_t prev_sigset;

bool teeth_signal_handler_init()
{
    sigset_t sigset;

    sigemptyset(&sigset);

    if (-1 == sigprocmask(SIG_BLOCK, &sigset, &prev_sigset)) {
        return false;
    }

    teeth_signal_handler_fd = signalfd(-1, &sigset, SFD_NONBLOCK | SFD_CLOEXEC);

    return teeth_signal_handler_fd != -1;
}

bool teeth_signal_handler_arm()
{
    sigset_t sigset;

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGQUIT);

    if (-1 == sigprocmask(SIG_BLOCK, &sigset, NULL)) {
        return false;
    }

    teeth_signal_handler_fd = signalfd(teeth_signal_handler_fd, &sigset, 0);

    return teeth_signal_handler_fd != -1;
}

void teeth_signal_handler_uninit()
{
    safe_close_ref(&teeth_signal_handler_fd);

    sigprocmask(SIG_BLOCK, &prev_sigset, NULL);
}

bool timerfd_drain(int fd)
{
    // drain timer
    for (bool done = false; !done;) {
        uint64_t ts;
        ssize_t r = read(fd, &ts, sizeof(ts));

        if (-1 == r) {
            switch (errno) {
            case EINTR:
                break;
            case EAGAIN:
                done = true;
                break;
            default:
                sys_error("timer fd");
                return false;
            }
        } else if (0 == r) {
            log_error("timer fd read returned 0\n");
            return false;
        } else {
            // continue drain
        }
    }

    return true;
}
