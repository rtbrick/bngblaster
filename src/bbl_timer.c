/*
 * BNG Blaster (BBL) - A O(1) Timer library
 *
 * Hannes Gredler, July 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/queue.h>

#include "bbl.h"
#include "bbl_timer.h"

/*
 * Add two timestamps x and y, storing the result in result.
 */
void
timespec_add (struct timespec *result, struct timespec *x, struct timespec *y)
{

  result->tv_sec = x->tv_sec + y->tv_sec;
  result->tv_nsec = x->tv_nsec + y->tv_nsec;

  /*
   * Avoid overflow of result->tv_nsec
   */
  if (result->tv_nsec >= 1e9) {
      result->tv_nsec -= 1e9;
      result->tv_sec += 1;
  }
}

/*
 * Subtract the timestamps x and y, storing the result in result.
 */
void
timespec_sub (struct timespec *result, struct timespec *x, struct timespec *y)
{

    if (x->tv_sec < y->tv_sec) {
        result->tv_sec = 0;
        result->tv_nsec = 0;
        return;
    }

    /*
     * Avoid overflow of result->tv_nsec
     */
    if (x->tv_nsec < y->tv_nsec) {
        result->tv_nsec = x->tv_nsec + 1e9 - y->tv_nsec;
        result->tv_sec = x->tv_sec - y->tv_sec - 1;
    } else {
        result->tv_sec = x->tv_sec - y->tv_sec;
        result->tv_nsec = x->tv_nsec - y->tv_nsec;
    }
}

/*
 * Format a timestamp in one of four buffers.
 * This way we can format upto 4 timespecs in one printf() call.
 */
char *
timespec_format (struct timespec *x)
{
    static char buffer[4][32];
    static int idx = 0;
    char *ret;

    ret = buffer[idx];
    idx = (idx+1) & 3;

    snprintf(ret, 32, "%lu.%06lus", x->tv_sec, x->tv_nsec / 1000);

    return ret;
}

/*
 * Enqueue a timer for change processing.
 */
void
timer_change (timer_s *timer)
{
    timer_root_s *timer_root;

    /*
     * Are we already on the timer change queue ?
     */
    if (timer->on_change_list) {
	    return;
    }

    timer_root = timer->timer_bucket->timer_root;
    CIRCLEQ_INSERT_TAIL(&timer_root->timer_change_qhead, timer, timer_change_qnode);
    timer->on_change_list = true;
}

void
timer_enqueue_bucket (timer_root_s *root, timer_s *timer, time_t sec, long nsec)
{
    timer_bucket_s *timer_bucket;

    /*
     * Find the bucket for insertion.
     */
    CIRCLEQ_FOREACH(timer_bucket, &root->timer_bucket_qhead, timer_bucket_qnode) {
        if (timer_bucket->sec != sec ||  timer_bucket->nsec != nsec) {
            continue;
        }

        /*
         * Found it !
         */
        goto insert;
    }

    /*
     * No bucket found that matches the timer values. Create a fresh bucket.
     */
    timer_bucket = calloc(1, sizeof(timer_bucket_s));
    if (!timer_bucket) {
        return;
    }

    CIRCLEQ_INSERT_TAIL(&root->timer_bucket_qhead, timer_bucket, timer_bucket_qnode);
    CIRCLEQ_INIT(&timer_bucket->timer_qhead);
    timer_bucket->sec = sec;
    timer_bucket->nsec = nsec;
    timer_bucket->timer_root = root;
    root->buckets++;

    LOG(TIMER_DETAIL, "Add timer bucket %lu.%06lus\n",
	timer_bucket->sec, timer_bucket->nsec/1000);

 insert:
    timer->timer_bucket = timer_bucket;
    CIRCLEQ_INSERT_TAIL(&timer_bucket->timer_qhead, timer, timer_qnode);
    timer_bucket->timers++;
}

/*
 * Smear all the timer of a given bucket to expire equi-distant.
 * Call this function periodically to avoid clustering of timers.
 */
void
timer_smear_bucket (timer_root_s *root, time_t sec, long nsec)
{
    timer_bucket_s *timer_bucket;
    timer_s *timer, *last_timer;
    struct timespec now, diff, step;
    long step_nsec;

    /*
     * Find the bucket for smearing.
     */
    CIRCLEQ_FOREACH(timer_bucket, &root->timer_bucket_qhead, timer_bucket_qnode) {
        if (timer_bucket->sec != sec ||  timer_bucket->nsec != nsec) {
            continue;
        }

        /*
         * Found the bucket. Next compute the timespan between now and last timer.
         */
        last_timer = CIRCLEQ_LAST(&timer_bucket->timer_qhead);
        if (!last_timer) {
            return;
        }
        clock_gettime(CLOCK_MONOTONIC, &now);
        timespec_sub(&diff, &last_timer->expire, &now);
        step_nsec = (diff.tv_sec * 1e9 + diff.tv_nsec) / (timer_bucket->timers); /* calculate smear step */
        step.tv_sec = step_nsec / 1e9;
        step.tv_nsec = step_nsec - (step.tv_sec * 1e9);

        LOG(TIMER_DETAIL, "Smear %u timers in bucket %lu.%06lus\n", timer_bucket->timers, sec, nsec);
        LOG(TIMER_DETAIL, "Now %s, last expire %s, step %s\n", timespec_format(&now),
                          timespec_format(&last_timer->expire), timespec_format(&step));

        /*
        * Now walk all timers and space them <step> apart.
        */
        CIRCLEQ_FOREACH(timer, &timer_bucket->timer_qhead, timer_qnode) {
            timespec_add(&timer->expire, &now, &step);
            now = timer->expire;
            LOG(TIMER_DETAIL, "  Smear %s -> expire %s\n", timer->name, timespec_format(&timer->expire));
        }
	    return;
    }
}

/*
 * Dequeue a timer from its timer_bucket.
 */
void
timer_dequeue_bucket (timer_s *timer)
{
    timer_root_s *timer_root;
    timer_bucket_s *timer_bucket;

    timer_bucket = timer->timer_bucket;
    timer_root = timer_bucket->timer_root;

    CIRCLEQ_REMOVE(&timer_bucket->timer_qhead, timer, timer_qnode);
    timer_bucket->timers--;
    timer->timer_bucket = NULL;

    /*
     * If the last timer of a bucket is gone, remove the bucket as well.
     */
    if (!timer_bucket->timers) {
	CIRCLEQ_REMOVE(&timer_root->timer_bucket_qhead, timer_bucket, timer_bucket_qnode);

	LOG(TIMER_DETAIL, "  Delete timer bucket %lu.%06lus\n",
	    timer_bucket->sec, timer_bucket->nsec/1000);

	free(timer_bucket);
	timer_root->buckets--;
    }
}

void
timer_requeue (timer_s *timer, time_t sec, long nsec)
{
    timer_root_s *timer_root;
    timer_bucket_s *timer_bucket;

    timer_bucket = timer->timer_bucket;
    timer_root = timer_bucket->timer_root;

    timer_set_expire(timer, sec, nsec);

    /*
     * If the expiration {sec,nsec} matches the bucket, then simply
     * timer dequeue and enqueue to keep correct temporal ordering.
     * If there is no match, do a slightly more expensive
     * bucket dequeue and enqueue.
     */
    if (timer_bucket->sec == sec && timer_bucket->nsec == nsec) {
        CIRCLEQ_REMOVE(&timer_bucket->timer_qhead, timer, timer_qnode);
        CIRCLEQ_INSERT_TAIL(&timer_bucket->timer_qhead, timer, timer_qnode);
    } else {
        timer_dequeue_bucket(timer);
        timer_enqueue_bucket(timer_root, timer, sec, nsec);
    }

    LOG(TIMER_DETAIL, "  Reset %s timer, expire in %lu.%06lus\n", timer->name, sec, nsec/1000);
}

/*
 * We do not delete timers, but rather dequeue them and move them to
 * the garbage collection queue, where they may get recycled.
 */
void
timer_del_internal (timer_s *timer)
{
    timer_root_s *timer_root;
    timer_bucket_s *timer_bucket;

    timer_bucket = timer->timer_bucket;
    timer_root = timer_bucket->timer_root;

    LOG(TIMER, "  Delete %s timer\n", timer->name);

    timer_dequeue_bucket(timer);

    /* Add to GC list */
    CIRCLEQ_INSERT_TAIL(&timer_root->timer_gc_qhead, timer, timer_qnode);
    timer_root->gc++;

    *timer->ptimer = NULL; /* delete references to this timer */
    timer->ptimer= NULL;
}

/*
 * Mark a timer for deletion.
 */
void
timer_del (timer_s *timer)
{
    if(timer) {
        timer->delete = true;
        timer_change(timer);
    }
}

/*
 * Set timer expiration.
 */
void
timer_set_expire (timer_s *timer, time_t sec, long nsec)
{
    clock_gettime(CLOCK_MONOTONIC, &timer->expire);
    timer->expire.tv_sec += sec;
    timer->expire.tv_nsec += nsec;

    /*
     * Handle nsec overflow.
     */
    if (timer->expire.tv_nsec >= 1e9) {
        timer->expire.tv_nsec -= 1e9;
        timer->expire.tv_sec++;
    }

    timer->expired = false;
}

/*
 * Deferred processing of all timers.
 */
void
timer_process_changes (timer_root_s *root)
{
    timer_s *timer;
    timer_bucket_s *timer_bucket;

    while (!CIRCLEQ_EMPTY(&root->timer_change_qhead)) {
        timer = CIRCLEQ_FIRST(&root->timer_change_qhead);
        timer_bucket = timer->timer_bucket;

        /*
        * Changes are only processed once.
        * Take this timer off the change list.
        */
        CIRCLEQ_REMOVE(&root->timer_change_qhead, timer, timer_change_qnode);
        timer->on_change_list = false;

        /*
        * Delete.
        */
        if (timer->delete) {
            timer_del_internal(timer);
            continue;
        }

        /*
        * Requeue.
        */
        if (timer->periodic) {
            timer_requeue(timer, timer_bucket->sec, timer_bucket->nsec);
            continue;
        }
    }
}

/*
 * Enqueue a timer with a given callback function onto the hierarchical timer list.
 */
void
timer_add (timer_root_s *root,
           timer_s **ptimer,
           char *name,
           time_t sec,
           long nsec,
           void *data,
           void (*cb))
{
    timer_s *timer;

    timer = *ptimer;

    /*
     * This timer already is enqueued. Requeue.
     */
    if (timer) {
        timer_requeue(timer, sec, nsec);
        /*
        * Update data and cb if there was a change.
        * Do the reformatting of name only during a change due to snprintf() being expensive.
        */
        if (timer->data != data || timer->cb != cb) {
            snprintf(timer->name, sizeof(timer->name), "%s", name);
            timer->data = data;
            timer->cb = cb;
        }
	    return;
    }

    if (CIRCLEQ_EMPTY(&root->timer_gc_qhead)) {

        /*
         * GC queue is empty, make a fresh allocation.
         */
        timer = calloc(1, sizeof(timer_s));
    } else {

        /*
         * Dequeue the first entry on the GC list and recycle.
         */
        timer = CIRCLEQ_FIRST(&root->timer_gc_qhead);
        CIRCLEQ_REMOVE(&root->timer_gc_qhead, timer, timer_qnode);
        root->gc--;
	    memset(timer, 0, sizeof(timer_s));
    }

    if (!timer) {
        return;
    }

    /*
     * Store name, data, callback and misc. data.
     */
    snprintf(timer->name, sizeof(timer->name), "%s", name);
    timer->data = data;
    timer->cb = cb;
    timer_set_expire(timer, sec, nsec);
    timer->ptimer = ptimer;
    *ptimer = timer;

    /*
     * Enqueue it into the correct timer bucket.
     */
    timer_enqueue_bucket(root, timer, sec, nsec);

    LOG(TIMER, "Add %s timer, expire in %lu.%06lus\n", timer->name, sec, nsec/1000);
}

void
timer_add_periodic (timer_root_s *root, timer_s **ptimer, char *name,
		            time_t sec, long nsec, void *data, void (*cb))
{
    timer_s *timer;

    timer_add(root, ptimer, name, sec, nsec, data, cb);

    timer = *ptimer;
    if (timer) {
        timer->periodic = true;
    }
}

/*
 * Compare two timespecs.
 *
 * return -1 if ts1 is older than ts2
 * return +1 if ts1 is newer than ts2
 * return  0 if ts1 is equal to ts2
 */
int
timespec_compare (struct timespec *ts1, struct timespec *ts2)
{
    if (ts1->tv_sec < ts2->tv_sec) {
        return -1;
    }

    if (ts1->tv_sec > ts2->tv_sec) {
        return +1;
    }

    if (ts1->tv_nsec < ts2->tv_nsec) {
        return -1;
    }

    if (ts1->tv_nsec > ts2->tv_nsec) {
        return +1;
    }

    return 0;
}

/*
 * Process the timer queue.
 */
void
timer_walk (timer_root_s *root)
{
    timer_s *timer;
    timer_bucket_s *timer_bucket;
    struct timespec now, min, sleep, rem;
    int res;

    while (true) {

        /*
         * No buckets filled and we're done.
         */
        if (CIRCLEQ_EMPTY(&root->timer_bucket_qhead)) {
            return;
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        LOG(TIMER_DETAIL, "Walk timer queue, now %s\n", timespec_format(&now));
        min.tv_sec = 0;
        min.tv_nsec = 0;

        /*
         * Walk all buckets.
         */
        CIRCLEQ_FOREACH(timer_bucket, &root->timer_bucket_qhead, timer_bucket_qnode) {

            LOG(TIMER_DETAIL, "  Checking timer bucket %lu.%06lus\n",
                timer_bucket->sec, timer_bucket->nsec/1000);

            /*
             * First pass. Call into expired nodes.
             */
            CIRCLEQ_FOREACH(timer, &timer_bucket->timer_qhead, timer_qnode) {

                /*
                 * Hitting the first non-expired timer means
                 * we're done processing this buckets queue.
                 */
                if ((timespec_compare(&timer->expire, &now) == 1)) {
                    break;
                }

                /*
                 * Everything from here one is expired.
                 */
                timer->expired = true;

                /* Execute callback */
                if (timer->cb) {
                    LOG(TIMER_DETAIL, "  Firing %s timer\n", timer->name);
                    (*timer->cb)(timer);
                }

                if (timer->periodic) {
                    /*
                     * Periodic timers are simple de-queued and
                     * re-inserted at the tail of this buckets queue.
                     */
		            timer_change(timer);
                } else {
                    /*
                     * Everything else gets deleted.
                     */
                    timer_del(timer);
                }
            }
        }

        /*
        * Process all changes from the last timer run.
        */
        timer_process_changes(root);

        /*
        * Second pass. Figure out min sleep time.
        */
        CIRCLEQ_FOREACH(timer_bucket, &root->timer_bucket_qhead, timer_bucket_qnode) {
            CIRCLEQ_FOREACH(timer, &timer_bucket->timer_qhead, timer_qnode) {

                /*
                * Ignore deleted timers that wait for change processing.
                */
                if (timer->delete) {
                    continue;
                }

                /*
                * First timer in the queue becomes the actual minimum.
                */
                if (min.tv_sec == 0 && min.tv_nsec == 0) {
                    min.tv_sec = timer->expire.tv_sec;
                    min.tv_nsec = timer->expire.tv_nsec;
                }

                /*
                 * Find the min timer.
                 */
                if (timespec_compare(&timer->expire, &min) == -1) {
                    min.tv_sec = timer->expire.tv_sec;
                    min.tv_nsec = timer->expire.tv_nsec;
                    LOG(TIMER_DETAIL, "New minimum sleep (%s) timer, found %s\n", 
                        timer->name, timespec_format(&min));
                }

                /*
                 * Hitting the first non-expired timer means
                 * we're done processing this buckets queue.
                 */
                if ((timespec_compare(&timer->expire, &now) == 1)) {
                    break;
                }
            }
        }

        /*
        * Calculate the sleep timer.
        */
        LOG(TIMER_DETAIL, "  Now %s\n", timespec_format(&now));
        LOG(TIMER_DETAIL, "  Min %s\n", timespec_format(&min));

        clock_gettime(CLOCK_MONOTONIC, &now);
        if (timespec_compare(&now, &min) == -1) {
            timespec_sub(&sleep, &min, &now);
        } else {
            //sleep.tv_sec = 0;
            //sleep.tv_nsec = 1 * MSEC; /* sleep time is negative, sleep at least some time */
            continue;
        }

        LOG(TIMER_DETAIL, "  Sleep %s\n", timespec_format(&sleep));
        res = nanosleep(&sleep, &rem);
        if (res == -1) {
            LOG(TIMER, "  nanosleep(): error %s (%d)\n", strerror(errno), errno);
            return;
        }
    }
}

/*
 * Init a timer root.
 */
void
timer_init_root (timer_root_s *timer_root)
{
    CIRCLEQ_INIT(&timer_root->timer_bucket_qhead);
    CIRCLEQ_INIT(&timer_root->timer_gc_qhead);
    CIRCLEQ_INIT(&timer_root->timer_change_qhead);
}

/*
 * Flush all timers hanging off a timer root.
 */
void
timer_flush_root (timer_root_s *timer_root)
{
    timer_s *timer;
    timer_bucket_s *timer_bucket;

    /*
     * First step. Walk all timers and move them onto the GC thread.
     */
    CIRCLEQ_FOREACH(timer_bucket, &timer_root->timer_bucket_qhead, timer_bucket_qnode) {
	CIRCLEQ_FOREACH(timer, &timer_bucket->timer_qhead, timer_qnode) {
	    timer_del(timer);
	}
    }
    timer_process_changes(timer_root);

    /*
     * Second step. Run the GC queue.
     */
    while (!CIRCLEQ_EMPTY(&timer_root->timer_gc_qhead)) {
        timer = CIRCLEQ_FIRST(&timer_root->timer_gc_qhead);
        CIRCLEQ_REMOVE(&timer_root->timer_gc_qhead, timer, timer_qnode);
	timer_root->gc--;
	free(timer);
    }
}

void
timer_test_cb (timer_s *timer)
{
    bbl_ctx_s *ctx;
    ctx = timer->data;
    LOG(TIMER, "  CB %s, ctx %p\n", timer->name, ctx);
}

void
timer_test (void *ctx)
{
    timer_root_s root;
    timer_s *t11, *t21, *t31;
    timer_s *t12, *t22, *t32;
    timer_s *t41;
    timer_s *t5[10];
    int idx;
    char timer_name[8];

    memset(&root, 0, sizeof(root));
    timer_init_root(&root);

    t11 = t21 = t31 = NULL;
    t12 = t22 = t32 = NULL;
    t41 = NULL;

    timer_add(&root, &t11, "t1.1", 1, 0, ctx, timer_test_cb);
    timer_add(&root, &t12, "t1.2", 1, 0, ctx, timer_test_cb);

    timer_add(&root, &t21, "t2.1", 2, 0, ctx, timer_test_cb);
    timer_add(&root, &t22, "t2.2", 2, 0, ctx, timer_test_cb);

    timer_add(&root, &t31, "t3.1", 5, 0, ctx, timer_test_cb);
    timer_add(&root, &t32, "t3.2", 5, 0, ctx, timer_test_cb);

    timer_add_periodic(&root, &t41, "t4.1 periodic", 4, 0, ctx, timer_test_cb);

    for (idx = 0; idx < 10; idx++) {
        t5[idx] = NULL;
        snprintf(timer_name, sizeof(timer_name), "t5.%u", idx+1);
        timer_add(&root, &t5[idx], timer_name, 10, 0, ctx, timer_test_cb);
    }
    timer_smear_bucket(&root, 10, 0);

    timer_walk(&root);
}
