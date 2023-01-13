/*
 * BNG Blaster (BBL) - Control Socket
 *
 * Christian Giese, January 2021
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_CTRL_H__
#define __BBL_CTRL_H__

typedef struct bbl_ctrl_thread_ {
    int socket;

    pthread_t thread;
    pthread_mutex_t mutex;
    pthread_cond_t cond;

    volatile bool active;

    /** Commands to be executed in main thread */
    struct {
        struct timer_ *timer;
        volatile size_t action;
        volatile int fd;
        volatile uint32_t session_id;
        volatile json_t *arguments;
    } main;
} bbl_ctrl_thread_s;

int
bbl_ctrl_status(int fd, const char *status, uint32_t code, const char *message);

bool
bbl_ctrl_socket_init();

bool
bbl_ctrl_socket_close();

#endif