/*
 * Common Timer Tests
 *
 * Christian Giese, April 2026
 * 
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <cmocka.h>
#include <timer.h>
#include <logging.h>

static int g_callback_counter;
static timer_s *g_last_timer;

struct keyval_ log_names[] = {
    { TIMER,         "timer" },
    { TIMER_DETAIL,  "timer-detail" },
    { 0, NULL}
};

static void
reset_globals(void)
{
    /* ENABLE timer logging to stdout here */
    log_id[TIMER].enable = true;
    log_id[TIMER_DETAIL].enable = true;
    /* RESET test variables */
    g_callback_counter = 0;
    g_last_timer = NULL;
}

static void
single_shot_cb(timer_s *timer)
{
    g_callback_counter++;
    g_last_timer = timer;
}

static void
none_cb(timer_s *timer)
{
    (void)timer;
}

static void
delete_from_callback_cb(timer_s *timer)
{
    g_callback_counter++;
    g_last_timer = timer;
    timer_del(timer);
}

static void
periodic_cb(timer_s *timer)
{
    (void)timer;
    g_callback_counter++;
}

static void
rearm_from_callback_cb(timer_s *timer)
{
    timer_root_s *root = timer->data;
    timer_s **ptimer = timer->ptimer;

    g_callback_counter++;
    g_last_timer = timer;

    assert_non_null(root);
    assert_non_null(ptimer);

    timer_add(root, ptimer, "REARM", 0, 5 * MSEC, root, rearm_from_callback_cb);
}

static void
sleep_ms(long ms)
{
    struct timespec ts;
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (ms % 1000) * MSEC;
    nanosleep(&ts, NULL);
}

static int
setup_timer_root(void **state)
{
    timer_root_s *root = calloc(1, sizeof(timer_root_s));
    assert_non_null(root);
    timer_init_root(root);
    reset_globals();
    *state = root;
    return 0;
}

static int
teardown_timer_root(void **state)
{
    timer_root_s *root = *state;
    timer_flush_root(root);
    free(root);
    return 0;
}

static void
test_timer_add_and_expire_once(void **state)
{
    timer_root_s *root = *state;
    timer_s *timer = NULL;
    timer_add(root, &timer, "ONESHOT", 0, 10 * MSEC, NULL, single_shot_cb);
    assert_non_null(timer);
    assert_string_equal(timer->name, "ONESHOT");
    assert_false(timer->expired);
    assert_false(timer->delete);

    sleep_ms(20);
    timer_walk(root);

    assert_null(timer);
    assert_non_null(g_last_timer);
    assert_string_equal(g_last_timer->name, "ONESHOT");
    assert_int_equal(g_callback_counter, 1);
}

static void
test_timer_del_before_expire(void **state)
{
    timer_root_s *root = *state;
    timer_s *timer_periodic = NULL;
    timer_s *timer = NULL;

    timer_add_periodic(root, &timer_periodic, "PERIODIC", 0, 5 * MSEC, NULL, none_cb);
    timer_add(root, &timer, "DELETE", 0, 50 * MSEC, NULL, single_shot_cb);
    assert_non_null(timer_periodic);
    assert_non_null(timer);
    timer_walk(root);
    assert_int_equal(g_callback_counter, 0);
    timer_del(timer);
    timer_walk(root);
    sleep_ms(100);
    timer_walk(root);
    timer_del(timer_periodic);
    timer_walk(root);
    assert_int_equal(g_callback_counter, 0);
    assert_null(timer);
}

static void
test_timer_add_reuses_same_pointer(void **state)
{
    timer_root_s *root = *state;
    timer_s *timer = NULL;
    timer_s *first;

    timer_add(root, &timer, "REUSE", 0, 20 * MSEC, NULL, single_shot_cb);
    assert_non_null(timer);
    first = timer;

    timer_add(root, &timer, "REUSE", 0, 30 * MSEC, NULL, single_shot_cb);

    assert_ptr_equal(timer, first);
    assert_non_null(timer->timer_bucket);
    assert_false(timer->delete);
}

static void
test_timer_rearm_from_callback(void **state)
{
    timer_root_s *root = *state;
    timer_s *timer = NULL;

    timer_add(root, &timer, "REARM", 0, 5 * MSEC, root, rearm_from_callback_cb);
    assert_non_null(timer);

    sleep_ms(15);
    timer_walk(root);
    assert_true(g_callback_counter >= 1);
    assert_non_null(timer);

    sleep_ms(15);
    timer_walk(root);
    assert_true(g_callback_counter >= 2);
    assert_non_null(timer);
}

static void
test_timer_delete_from_callback(void **state)
{
    timer_root_s *root = *state;
    timer_s *timer = NULL;

    timer_add(root, &timer, "DELETE-CB", 0, 5 * MSEC, NULL, delete_from_callback_cb);
    assert_non_null(timer);

    sleep_ms(15);
    timer_walk(root);
    assert_int_equal(g_callback_counter, 1);

    timer_walk(root);
    assert_null(timer);
}

static void
test_periodic_timer_fires_multiple_times(void **state)
{
    timer_root_s *root = *state;
    timer_s *timer = NULL;

    timer_add_periodic(root, &timer, "PERIODIC", 0, 5 * MSEC, NULL, periodic_cb);
    assert_non_null(timer);
    assert_true(timer->periodic);

    sleep_ms(10);
    timer_walk(root);
    sleep_ms(10);
    timer_walk(root);
    sleep_ms(10);
    timer_walk(root);

    assert_true(g_callback_counter >= 2);
    assert_non_null(timer);
}

static void
test_timer_smear_preserves_bucket_membership(void **state)
{
    timer_root_s *root = *state;
    timer_s *timer_a = NULL;
    timer_s *timer_b = NULL;
    struct timespec delta;

    timer_add(root, &timer_a, "SMEAR-A", 0, 100 * MSEC, NULL, single_shot_cb);
    timer_add(root, &timer_b, "SMEAR-B", 0, 100 * MSEC, NULL, single_shot_cb);

    assert_non_null(timer_a);
    assert_non_null(timer_b);
    assert_ptr_equal(timer_a->timer_bucket, timer_b->timer_bucket);
    assert_int_equal(timer_a->timer_bucket->timers, 2);

    timespec_sub(&delta, &timer_b->expire, &timer_a->expire);
    assert_int_equal(delta.tv_sec, 0);
    assert_true((unsigned long)delta.tv_nsec < 10 * MSEC);

    timer_smear_bucket(root, 0, 100 * MSEC);

    assert_ptr_equal(timer_a->timer_bucket, timer_b->timer_bucket);
    assert_int_equal(timer_a->timer_bucket->timers, 2);
    assert_true(timer_b->expire.tv_sec > timer_a->expire.tv_sec ||
                (timer_b->expire.tv_sec == timer_a->expire.tv_sec &&
                 timer_b->expire.tv_nsec >= timer_a->expire.tv_nsec));

    timespec_sub(&delta, &timer_b->expire, &timer_a->expire);
    assert_int_equal(delta.tv_sec, 0);
    assert_true((unsigned long)delta.tv_nsec > 45 * MSEC);
    assert_true((unsigned long)delta.tv_nsec < 55 * MSEC);

    timer_del(timer_a);
    timer_del(timer_b);
    timer_walk(root);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_timer_add_and_expire_once,
                                        setup_timer_root,
                                        teardown_timer_root),
        cmocka_unit_test_setup_teardown(test_timer_del_before_expire,
                                        setup_timer_root,
                                        teardown_timer_root),
        cmocka_unit_test_setup_teardown(test_timer_add_reuses_same_pointer,
                                        setup_timer_root,
                                        teardown_timer_root),
        cmocka_unit_test_setup_teardown(test_timer_rearm_from_callback,
                                        setup_timer_root,
                                        teardown_timer_root),
        cmocka_unit_test_setup_teardown(test_timer_delete_from_callback,
                                        setup_timer_root,
                                        teardown_timer_root),
        cmocka_unit_test_setup_teardown(test_periodic_timer_fires_multiple_times,
                                        setup_timer_root,
                                        teardown_timer_root),
        cmocka_unit_test_setup_teardown(test_timer_smear_preserves_bucket_membership,
                                        setup_timer_root,
                                        teardown_timer_root),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}