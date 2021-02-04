/*
 * BNG Blaster (BBL) - A O(1) Timer library
 *
 * Hannes Gredler, July 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#ifndef __BBL_TIMER_H__
#define __BBL_TIMER_H__

#define MSEC 1000*1000 /* 1 million nanoseconds */

/*
 * Top level data structure for timers.
 */
typedef struct timer_root_
{
    CIRCLEQ_HEAD(timer_bucket_root_, timer_bucket_ ) timer_bucket_qhead; /* Bucket list  */
    CIRCLEQ_HEAD(timer_gc_root_, timer_ ) timer_gc_qhead; /* Garbage collection list */
    CIRCLEQ_HEAD(timer_change_root_, timer_ ) timer_change_qhead; /* Change timers list */

    uint buckets; /* # of buckets hanging off */
    uint gc; /* # of timers waiting for GC */

} timer_root_s;

/*
 * Group each like timers (e.g. all 100ms, 1s, 5s timers) into a timer bucket.
 * All buckets hang off the timer root.
 * Since time does not run backwards, timer insertion becomes a O(1) operation as one needs
 * only to locate the appropriate bucket and insert at the tail of the per bucket queue.
 */
typedef struct timer_bucket_
{
    CIRCLEQ_HEAD(timer_bucket_head_, timer_ ) timer_qhead; /* head of timers */
    CIRCLEQ_ENTRY(timer_bucket_) timer_bucket_qnode; /* node in bucket list */

    struct timer_root_ *timer_root; /* back pointer */

    time_t sec;
    long nsec;

    uint timers; /* # of timers hanging off this bucket */
} timer_bucket_s;

/*
 * Timer which hangs off the bucket list.
 */
typedef struct timer_
{
    CIRCLEQ_ENTRY(timer_) timer_qnode;
    CIRCLEQ_ENTRY(timer_) timer_change_qnode;
    struct timer_bucket_ *timer_bucket; /* back pointer */

    char name[16];
    void *data; /* Misc. data */
    struct timer_ **ptimer; /* Where this timer pointer gets stored */
    void (*cb)(struct timer_ *); /* Callback function. */
    struct timespec expire; /* Expiration interval */
    uint expired:1,
    periodic:1, /* auto restart timer ? */
    delete:1, /* timer has been deleted */
    on_change_list:1; /* node is on change list */
 } timer_s;

/*
 * Prototypes
 */
void timer_set_expire(timer_s *, time_t, long);

/*
 * Public API.
 */
void timer_init_root(timer_root_s *);
void timer_flush_root(timer_root_s *);
void timer_test(void *);
void timer_add(timer_root_s *, timer_s **, char *, time_t , long , void *, void *);
void timer_add_periodic(timer_root_s *, timer_s **, char *, time_t , long , void *, void *);
void timer_del(timer_s *);
void timer_smear_bucket(timer_root_s *, time_t, long);
void timer_walk(struct timer_root_ *);

void timespec_add(struct timespec *, struct timespec *, struct timespec *);
void timespec_sub(struct timespec *, struct timespec *, struct timespec *);

#endif /* __BBL_TIMER_H__ */
