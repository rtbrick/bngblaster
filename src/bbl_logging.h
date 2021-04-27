/*
 * BNG Blaster (BBL) - Logging Functions
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#ifndef __BBL_LOGGING_H__
#define __BBL_LOGGING_H__

extern bool g_interactive; // interactive mode using ncurses

extern char *g_log_file;
extern FILE *g_log_fp;

/*
 * List of log-ids.
 */
enum {
    LOG_ID_MIN,
    DEBUG,
    IGMP,
    TIMER,
    TIMER_DETAIL,
    IO,
    PPPOE,
    NORMAL,
    ERROR,
    PCAP,
    IP,
    LOSS,
    L2TP,
    DHCP,
    LOG_ID_MAX
};

struct keyval_ {
    u_int val;       /* value */
    const char *key; /* key */
};

struct __attribute__((__packed__)) log_id_
{
    uint8_t enable;
    void (*filter_cb)(struct log_id_ *, void *); /* Callback function for filtering */
    void *filter_arg;
};

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
                wrefresh(log_win);  \
            } \
        } else { \
            if (log_id[log_id_].enable) { \
                fprintf(stdout, "%s "fmt_, log_format_timestamp(), ##__VA_ARGS__); \
            } \
        } \
     } while (0) \


extern struct log_id_ log_id[];
extern char * log_format_timestamp(void);

void
log_enable (char *log_name);

void
log_open ();

void
log_close ();

char *
log_format_timestamp (void);

char *
log_usage ();

#endif
