/*
 * Logging Functions
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "logging.h"

/* Globals */

struct log_id_ log_id[LOG_ID_MAX];

FILE *g_log_fp = NULL;
char *g_log_file = NULL;

/*
 * Format the logging timestamp.
 */
char *
log_format_timestamp(void)
{
    static char ts_str[sizeof("Jun 19 08:07:13.711541")];
    struct timespec now;
    struct tm tm;
    int len;

    clock_gettime(CLOCK_REALTIME, &now);
    localtime_r(&now.tv_sec, &tm);

    len = strftime(ts_str, sizeof(ts_str), "%b %d %H:%M:%S", &tm);
    snprintf(ts_str+len, sizeof(ts_str) - len, ".%06lu", now.tv_nsec / 1000);

    return ts_str;
}

/*
 * Enable logging.
 */
void
log_enable(char *log_name)
{
    int idx;
    if(!log_name) {
        return;
    }
    idx = 0;
    while(log_names[idx].key) {
        if (strcmp(log_names[idx].key, log_name) == 0) {
            log_id[log_names[idx].val].enable = 1;
        }
        idx++;
    }
}

/*
 * Open log file.
 */
void
log_open()
{
    if(!g_log_file) {
        return;
    }
    g_log_fp = fopen(g_log_file, "a");
}

/*
 * Close log file.
 */
void
log_close()
{
    if(g_log_fp) {
        fclose(g_log_fp);
        g_log_fp = NULL;
    }
}

/*
 * Return log usage string.
 */
char *
log_usage()
{
    static char buf[128];
    struct keyval_ *ptr;
    int len = 0;

    ptr = log_names;
    while(ptr->key) {
        len += snprintf(buf+len, sizeof(buf)-len, "%s%s", len ? "|" : " ", ptr->key);
        ptr++;
    }
    return buf;
}