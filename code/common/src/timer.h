/*
 * A O(1) Timer library
 *
 * Hannes Gredler, July 2020
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __COMMON_TIMER_H__
#define __COMMON_TIMER_H__
#include "common.h"

#define MSEC    1000000UL       /* 1 million nanoseconds == 1 milliseconds */
#define MSEC100 100000000UL     /* 100 million nanoseconds == 100 milliseconds */
#define SEC     1000000000UL    /* 1 billion nanoseconds == 1 second */

/*  Top level data structure for timers. */
typedef struct timer_root_
{
    CIRCLEQ_HEAD(timer_bucket_root_, timer_bucket_ ) timer_bucket_qhead; /* Bucket list  */
    CIRCLEQ_HEAD(timer_gc_root_, timer_ ) timer_gc_qhead; /* Garbage collection list */
    CIRCLEQ_HEAD(timer_change_root_, timer_ ) timer_change_qhead; /* Change timers list */

    uint32_t buckets; /* # of buckets hanging off */
    uint32_t gc; /* # of timers waiting for GC */

} timer_root_s;

/* Group each like timers (e.g. all 100ms, 1s, 5s timers) into a timer bucket.
 * All buckets hang off the timer root.
 * Since time does not run backwards, timer insertion becomes a O(1) operation as one needs
 * only to locate the appropriate bucket and insert at the tail of the per bucket queue. */
typedef struct timer_bucket_
{
    CIRCLEQ_HEAD(timer_bucket_head_, timer_ ) timer_qhead; /* head of timers */
    CIRCLEQ_ENTRY(timer_bucket_) timer_bucket_qnode; /* node in bucket list */

    struct timer_root_ *timer_root; /* back pointer */

    time_t sec;
    long nsec;

    uint32_t timers; /* # of timers hanging off this bucket */
} timer_bucket_s;

/* Timer which hangs off the bucket list. */
typedef struct timer_
{
    CIRCLEQ_ENTRY(timer_) timer_qnode;
    CIRCLEQ_ENTRY(timer_) timer_change_qnode;
    struct timespec expire; /* expiration interval */
    struct timespec *timestamp;
    struct timer_bucket_ *timer_bucket; /* back pointer */
    struct timer_ **ptimer; /* where this timer pointer gets stored */
    void *data; /* misc. data */
    void (*cb)(struct timer_ *); /* callback function. */
    bool expired;
    bool periodic; /* auto restart timer ? */
    bool reset; /* reset reference/start time */
    bool delete; /* timer has been deleted */
    bool on_change_list; /* node is on change list */
    char name[32];
} timer_s;

/* Public API */

void 
timespec_add(struct timespec *, struct timespec *, struct timespec *);

void 
timespec_sub(struct timespec *, struct timespec *, struct timespec *);

char *
timespec_format(struct timespec *x);

void 
timer_smear_bucket(timer_root_s *, time_t, long);

void 
timer_smear_all_buckets(timer_root_s *root);

void 
timer_del(timer_s *timer);

void
timer_add(timer_root_s *root, timer_s **ptimer, char *name,
          time_t sec, long nsec,
          void *data, void (*cb)(timer_s *));

void
timer_add_periodic(timer_root_s *root, timer_s **ptimer, char *name,
                   time_t sec, long nsec, 
                   void *data, void (*cb)(timer_s *));

void
timer_walk(timer_root_s *root);

void
timer_init_root(timer_root_s *timer_root);

void
timer_flush_root(timer_root_s *timer_root);

#endif /* __TIMER_H__ */
