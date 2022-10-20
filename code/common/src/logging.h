/*
 * Logging Functions
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __COMMON_LOGGING_H__
#define __COMMON_LOGGING_H__
#include "common.h"

extern char *g_log_file;

extern FILE *g_log_fp;
extern keyval_t log_names[];

/*
 * List of log-ids.
 */
enum {
    LOG_ID_MIN,
    NORMAL,
    DEBUG,
    IGMP,
    TIMER,
    TIMER_DETAIL,
    IO,
    CTRL,
    PPPOE,
    INFO,
    ERROR,
    PCAP,
    IP,
    LOSS,
    L2TP,
    DHCP,
    ISIS,
    BGP,
    TCP,
    LSDB,
    LSP,
    LAG,
    LOG_ID_MAX
};

struct __attribute__((__packed__)) log_id_
{
    uint8_t enable;
    void (*filter_cb)(struct log_id_ *, void *); /* Callback function for filtering */
    void *filter_arg;
};

#ifdef NCURSES_ENABLED
extern bool g_interactive; /* interactive mode using ncurses */

#define LOG_BUF_STR_LEN 1024
#define LOG_BUF_LINES 128

extern char *g_log_buf;
extern uint8_t g_log_buf_cur;

#define LOG(log_id_, fmt_, ...) \
    do { \
        if(g_log_fp) { \
            if (log_id[log_id_].enable) { \
                fprintf(g_log_fp, "%s "fmt_, log_format_timestamp(), ##__VA_ARGS__); \
            }\
        } \
        if(g_interactive) { \
            if (log_id[log_id_].enable) { \
                wprintw(log_win, "%s "fmt_, log_format_timestamp(), ##__VA_ARGS__); \
                wrefresh(log_win); \
            } \
        } else { \
            if (log_id[log_id_].enable) { \
                fprintf(stdout, "%s "fmt_, log_format_timestamp(), ##__VA_ARGS__); \
                if(g_log_buf) { \
                    snprintf((g_log_buf+((g_log_buf_cur++)*LOG_BUF_STR_LEN)), (LOG_BUF_STR_LEN-1), "%s "fmt_, log_format_timestamp(), ##__VA_ARGS__); \
                    if(g_log_buf_cur >= LOG_BUF_LINES) { \
                        g_log_buf_cur = 0; \
                    } \
                } \
            } \
        } \
     } while(0)

#define LOG_NOARG(log_id_, fmt_) \
    do { \
        if(g_log_fp) { \
            if (log_id[log_id_].enable) { \
                fprintf(g_log_fp, "%s "fmt_, log_format_timestamp()); \
            }\
        } \
        if(g_interactive) { \
            if (log_id[log_id_].enable) { \
                wprintw(log_win, "%s "fmt_, log_format_timestamp()); \
                wrefresh(log_win);  \
            } \
        } else { \
            if (log_id[log_id_].enable) { \
                fprintf(stdout, "%s "fmt_, log_format_timestamp()); \
                if(g_log_buf) { \
                    snprintf((g_log_buf+((g_log_buf_cur++)*LOG_BUF_STR_LEN)), (LOG_BUF_STR_LEN-1), "%s "fmt_, log_format_timestamp()); \
                    if(g_log_buf_cur >= LOG_BUF_LINES) { \
                        g_log_buf_cur = 0; \
                    } \
                } \
            } \
        } \
     } while(0)

#else 
#define LOG(log_id_, fmt_, ...) \
    do { \
        if(g_log_fp) { \
            if (log_id[log_id_].enable) { \
                fprintf(g_log_fp, "%s "fmt_, log_format_timestamp(), ##__VA_ARGS__); \
            }\
        } else { \
            if (log_id[log_id_].enable) { \
                fprintf(stdout, "%s "fmt_, log_format_timestamp(), ##__VA_ARGS__); \
            } \
        } \
     } while(0)

#define LOG_NOARG(log_id_, fmt_) \
    do { \
        if(g_log_fp) { \
            if (log_id[log_id_].enable) { \
                fprintf(g_log_fp, "%s "fmt_, log_format_timestamp()); \
            }\
        } else { \
            if (log_id[log_id_].enable) { \
                fprintf(stdout, "%s "fmt_, log_format_timestamp()); \
            } \
        } \
     } while(0)
#endif



extern struct log_id_ log_id[];
extern char * log_format_timestamp(void);

void
log_enable(char *log_name);

void
log_open();

void
log_close();

char *
log_format_timestamp(void);

char *
log_usage();

#endif