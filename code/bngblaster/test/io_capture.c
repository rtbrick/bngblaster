/*
 * BNG Blaster (BBL) - IO Stream Capture Tests
 *
 * Christian Giese, Andreas Zimber, October 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../src/io/io.h"

/* Logging (normally defined in bbl.c) */
struct keyval_ log_names[] = {
    { ERROR, "error" },
    { 0, NULL}
};
bool g_interactive = false;
WINDOW *log_win = NULL;
char *g_log_buf = NULL;
uint8_t g_log_buf_cur = 0;

bbl_ctx_s *g_ctx;
static bbl_ctx_s context;
static bbl_interface_s interface;
static bbl_link_config_s link_config;
static io_handle_s io;
static io_thread_s thread;
static uint8_t write_buf[1];
static timer_s capture_timer;

static uint8_t packet[9000];
static unsigned captured, flushed, timers;
static uint32_t captured_flags;
static uint16_t captured_vlan_tpid, captured_vlan_tci;
static bool concurrent;
static bool fail_allocation;

/* Linked with --wrap=realloc */
void *__real_realloc(void *ptr, size_t size);

void *
__wrap_realloc(void *ptr, size_t size)
{
    return fail_allocation ? NULL : __real_realloc(ptr, size);
}

void
pcapng_push_packet_header_vlan(struct timespec *ts, uint8_t *data, uint32_t packet_length,
                               uint32_t ifindex, uint32_t direction,
                               uint16_t vlan_tpid, uint16_t vlan_tci)
{
    uint32_t sequence;

    assert_int_equal(ifindex, 42);
    if(concurrent) {
        assert_int_equal(packet_length, sizeof(sequence));
        memcpy(&sequence, data, sizeof(sequence));
        assert_int_equal(sequence, captured);
        assert_int_equal(ts->tv_nsec, sequence);
    } else {
        assert_int_equal(packet_length, sizeof(packet));
        assert_memory_equal(data, packet, packet_length);
        assert_int_equal(ts->tv_sec, 123);
    }
    captured_flags = direction;
    captured_vlan_tpid = vlan_tpid;
    captured_vlan_tci = vlan_tci;
    captured++;
}

void
pcapng_fflush()
{
    flushed++;
}

void
timer_add_periodic(timer_root_s *root, timer_s **ptimer, char *name,
                   time_t sec, long nsec, void *data, void (*cb)(timer_s *))
{
    (void)root; (void)name; (void)sec; (void)nsec;
    capture_timer.data = data;
    capture_timer.cb = cb;
    *ptimer = &capture_timer;
    timers++;
}

void
timer_del(timer_s *timer)
{
    assert_ptr_equal(timer, &capture_timer);
    timers--;
}

static int
setup(void **state)
{
    (void)state;
    memset(&context, 0, sizeof(context));
    memset(&interface, 0, sizeof(interface));
    memset(&link_config, 0, sizeof(link_config));
    memset(&io, 0, sizeof(io));
    memset(&thread, 0, sizeof(thread));
    memset(packet, 0xa5, sizeof(packet));
    g_ctx = &context;
    g_ctx->pcap.write_buf = write_buf;
    interface.ifindex = 42;
    interface.name = "eth0";
    interface.config = &link_config;
    io.interface = &interface;
    io.direction = IO_INGRESS;
    io.thread = &thread;
    io.timestamp.tv_sec = 123;
    thread.io = &io;
    captured = flushed = timers = 0;
    captured_flags = 0;
    concurrent = fail_allocation = false;
    return 0;
}

static int
teardown(void **state)
{
    (void)state;
    io_capture_free(&thread);
    assert_null(thread.capture);
    assert_int_equal(timers, 0);
    return 0;
}

static void
capture(void)
{
    if(io_capture_active(&thread)) {
        io_capture_packet(&io, packet, sizeof(packet));
    }
}

static void
test_rx_capture(void **state)
{
    (void)state;
    assert_true(io_capture_init(&thread, 4));
    assert_int_equal(timers, 1);
    capture();
    assert_int_equal(captured, 0);
    /* Drained by the periodic job of the main thread. */
    capture_timer.cb(&capture_timer);
    assert_int_equal(captured, 1);
    assert_int_equal(captured_flags, PCAPNG_EPB_FLAGS_INBOUND);
    assert_int_equal(captured_vlan_tpid, 0);
    assert_int_equal(flushed, 1);
}

static void
test_rx_vlan(void **state)
{
    (void)state;
    assert_true(io_capture_init(&thread, 4));
    io.vlan_tci = (5 << 13) | 3000;
    io.vlan_tpid = ETH_TYPE_QINQ;
    capture();
    io_capture_drain(&thread);
    assert_int_equal(captured, 1);
    assert_int_equal(captured_vlan_tpid, ETH_TYPE_QINQ);
    assert_int_equal(captured_vlan_tci, (5 << 13) | 3000);
    /* VLAN 0 without priority is restored as well. */
    io.vlan_tci = 0;
    io.vlan_tpid = ETH_TYPE_VLAN;
    capture();
    io_capture_drain(&thread);
    assert_int_equal(captured, 2);
    assert_int_equal(captured_vlan_tpid, ETH_TYPE_VLAN);
    assert_int_equal(captured_vlan_tci, 0);
}

static void
test_tx_copy_and_final_drain(void **state)
{
    uint8_t source[sizeof(packet)];
    (void)state;
    io.direction = IO_EGRESS;
    io.vlan_tci = 3000;
    io.vlan_tpid = ETH_TYPE_VLAN;
    assert_true(io_capture_init(&thread, 4));
    memcpy(source, packet, sizeof(source));
    io_capture_packet(&io, source, sizeof(source));
    memset(source, 0, sizeof(source));
    io_capture_free(&thread);
    assert_int_equal(captured, 1);
    assert_int_equal(captured_flags, PCAPNG_EPB_FLAGS_OUTBOUND);
    assert_int_equal(captured_vlan_tpid, 0);
}

static void
test_overflow(void **state)
{
    (void)state;
    assert_true(io_capture_init(&thread, 2));
    capture();
    capture();
    io_capture_drain(&thread);
    assert_int_equal(captured, 1);
    assert_int_equal(thread.capture->dropped_total, 1);
    capture();
    io_capture_drain(&thread);
    assert_int_equal(captured, 2);
    assert_int_equal(thread.capture->dropped_total, 1);
}

static void
test_allocation_failure(void **state)
{
    (void)state;
    assert_true(io_capture_init(&thread, 4));
    fail_allocation = true;
    capture();
    io_capture_drain(&thread);
    assert_int_equal(captured, 0);
    assert_int_equal(thread.capture->alloc_failed_total, 1);
    fail_allocation = false;
    capture();
    io_capture_drain(&thread);
    assert_int_equal(captured, 1);
}

static void
test_pcap_stop_start(void **state)
{
    (void)state;
    /* Queue allocated without PCAP, which can be started later. */
    g_ctx->pcap.write_buf = NULL;
    assert_true(io_capture_init(&thread, 4));
    assert_false(io_capture_active(&thread));
    g_ctx->pcap.write_buf = write_buf;
    io_capture_drain(&thread);
    assert_true(io_capture_active(&thread));
    capture();
    /* Packets queued when PCAP is stopped are discarded. */
    g_ctx->pcap.write_buf = NULL;
    io_capture_drain(&thread);
    assert_false(io_capture_active(&thread));
    assert_int_equal(captured, 0);
    assert_int_equal(flushed, 0);
    assert_int_equal(atomic_load(&thread.capture->read), atomic_load(&thread.capture->write));
    capture();
    io_capture_drain(&thread);
    assert_int_equal(captured, 0);
    g_ctx->pcap.write_buf = write_buf;
    io_capture_drain(&thread);
    capture();
    io_capture_drain(&thread);
    assert_int_equal(captured, 1);
}

static void *
producer(void *arg)
{
    uint32_t sequence;
    (void)arg;
    for(sequence = 0; sequence < 100000; sequence++) {
        io.timestamp.tv_nsec = sequence;
        /* Wait for the consumer instead of dropping. */
        while((atomic_load(&thread.capture->write) + 1) % thread.capture->size ==
              atomic_load(&thread.capture->read));
        io_capture_packet(&io, (uint8_t*)&sequence, sizeof(sequence));
    }
    return NULL;
}

static void
test_concurrent(void **state)
{
    pthread_t producer_thread;
    (void)state;
    concurrent = true;
    assert_true(io_capture_init(&thread, 64));
    assert_int_equal(pthread_create(&producer_thread, NULL, producer, NULL), 0);
    while(captured < 100000) io_capture_drain(&thread);
    assert_int_equal(pthread_join(producer_thread, NULL), 0);
    assert_int_equal(thread.capture->dropped_total, 0);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_rx_capture, setup, teardown),
        cmocka_unit_test_setup_teardown(test_rx_vlan, setup, teardown),
        cmocka_unit_test_setup_teardown(test_tx_copy_and_final_drain, setup, teardown),
        cmocka_unit_test_setup_teardown(test_overflow, setup, teardown),
        cmocka_unit_test_setup_teardown(test_allocation_failure, setup, teardown),
        cmocka_unit_test_setup_teardown(test_pcap_stop_start, setup, teardown),
        cmocka_unit_test_setup_teardown(test_concurrent, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
