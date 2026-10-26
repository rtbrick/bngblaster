#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../src/io/io.h"

static unsigned errors;
static bool fail_allocation;
static void *capture_realloc(void *ptr, size_t size)
{
    return fail_allocation ? NULL : realloc(ptr, size);
}

#undef LOG
#define LOG(log_id_, fmt_, ...) do { \
    errors++; \
    if(0) printf(fmt_, ##__VA_ARGS__); \
} while(0)
#define realloc capture_realloc
#include "../src/io/io_thread.c"
#undef realloc

bbl_ctx_s *g_ctx;
static bbl_ctx_s context;
static bbl_interface_s interface;
static io_handle_s io;
static io_thread_s thread;
static uint8_t packet[9000];
static uint8_t expected_packet[9004];
static uint16_t expected_length;
static unsigned captured, flushed;
static uint16_t captured_flags;
static bool concurrent;

void
pcapng_push_packet_header(struct timespec *ts, uint8_t *data, uint32_t length,
                         uint32_t ifindex, uint32_t flags)
{
    assert_int_equal(ifindex, 42);
    if(concurrent) {
        uint32_t sequence;
        memcpy(&sequence, data, sizeof(sequence));
        assert_int_equal(sequence, captured);
        assert_int_equal(ts->tv_nsec, sequence);
    } else {
        assert_int_equal(length, expected_length);
        assert_memory_equal(data, expected_packet, length);
        assert_int_equal(ts->tv_sec, 123);
    }
    captured_flags = flags;
    captured++;
}

void
pcapng_fflush(void)
{
    flushed++;
}

bool
packet_is_bbl(uint8_t *buf, uint16_t len)
{
    (void)buf; (void)len;
    return true;
}

protocol_error_t
decode_ethernet(uint8_t *buf, uint16_t len, uint8_t *sp, uint16_t sp_len,
                bbl_ethernet_header_s **eth)
{
    static bbl_ethernet_header_s header;
    (void)buf; (void)len; (void)sp; (void)sp_len;
    *eth = &header;
    return PROTOCOL_SUCCESS;
}

bool
bbl_rx_thread(bbl_interface_s *iface, bbl_ethernet_header_s *eth)
{
    (void)iface; (void)eth;
    return true;
}

static int
setup(void **state)
{
    (void)state;
    memset(&context, 0, sizeof(context));
    memset(&interface, 0, sizeof(interface));
    memset(&io, 0, sizeof(io));
    memset(&thread, 0, sizeof(thread));
    memset(packet, 0xa5, sizeof(packet));
    memcpy(expected_packet, packet, sizeof(packet));
    expected_length = sizeof(packet);
    g_ctx = &context;
    g_ctx->io_threads = &thread;
    interface.ifindex = 42;
    io.interface = &interface;
    io.direction = IO_INGRESS;
    io.thread = &thread;
    io.timestamp.tv_sec = 123;
    io.buf = packet;
    io.buf_len = sizeof(packet);
    thread.io = &io;
    errors = captured = flushed = 0;
    fail_allocation = concurrent = false;
    return 0;
}

static int
teardown(void **state)
{
    (void)state;
    io_thread_stop_all();
    assert_null(thread.capture);
    return 0;
}

static void
test_rx_fast_path(void **state)
{
    (void)state;
    assert_true(io_thread_capture_init(&thread, 4));
    assert_int_equal(io_thread_rx_handler(&thread, &io), IO_SUCCESS);
    assert_int_equal(captured, 0);
    io_thread_capture_drain(&thread);
    assert_int_equal(captured, 1);
    assert_int_equal(captured_flags, PCAPNG_EPB_FLAGS_INBOUND);
    assert_int_equal(flushed, 1);
    assert_int_equal(errors, 0);
}

static void
test_rx_vlan_restore(void **state)
{
    uint16_t value;
    (void)state;
    assert_true(io_thread_capture_init(&thread, 4));
    io.vlan_tci = (5 << 13) | 3000;
    io.vlan_tpid = ETH_TYPE_QINQ;
    memcpy(expected_packet, packet, ETH_SRC_DST_ADDR_LEN);
    value = htobe16(io.vlan_tpid);
    memcpy(expected_packet + ETH_SRC_DST_ADDR_LEN, &value, sizeof(value));
    value = htobe16(io.vlan_tci);
    memcpy(expected_packet + ETH_SRC_DST_ADDR_LEN + 2, &value, sizeof(value));
    memcpy(expected_packet + ETH_SRC_DST_ADDR_LEN + 4,
           packet + ETH_SRC_DST_ADDR_LEN, sizeof(packet) - ETH_SRC_DST_ADDR_LEN);
    expected_length += BBL_ETH_VLAN_LEN;
    assert_int_equal(io_thread_rx_handler(&thread, &io), IO_SUCCESS);
    io_thread_capture_drain(&thread);
    assert_int_equal(captured, 1);
    io.vlan_tpid = 0;
    value = htobe16(ETH_TYPE_VLAN);
    memcpy(expected_packet + ETH_SRC_DST_ADDR_LEN, &value, sizeof(value));
    io_thread_capture(&io, packet, sizeof(packet));
    io_thread_capture_drain(&thread);
    assert_int_equal(captured, 2);
    assert_int_equal(errors, 0);
}

static void
test_tx_copy_and_final_drain(void **state)
{
    uint8_t source[sizeof(packet)];
    (void)state;
    io.direction = IO_EGRESS;
    io.vlan_tci = 3000;
    assert_true(io_thread_capture_init(&thread, 4));
    memcpy(source, packet, sizeof(source));
    io_thread_capture(&io, source, sizeof(source));
    memset(source, 0, sizeof(source));
    io_thread_stop_all();
    assert_int_equal(captured, 1);
    assert_int_equal(captured_flags, PCAPNG_EPB_FLAGS_OUTBOUND);
}

static void
test_disabled_and_overflow(void **state)
{
    (void)state;
    io_thread_capture(&io, packet, sizeof(packet));
    assert_int_equal(captured, 0);
    assert_true(io_thread_capture_init(&thread, 2));
    io_thread_capture(&io, packet, sizeof(packet));
    io_thread_capture(&io, packet, sizeof(packet));
    io_thread_capture_drain(&thread);
    assert_int_equal(captured, 1);
    assert_int_equal(errors, 1);
    io_thread_capture(&io, packet, sizeof(packet));
    io_thread_capture_drain(&thread);
    assert_int_equal(captured, 2);
    assert_int_equal(errors, 1);
}

static void
test_allocation_failure(void **state)
{
    (void)state;
    assert_true(io_thread_capture_init(&thread, 4));
    fail_allocation = true;
    io_thread_capture(&io, packet, sizeof(packet));
    io_thread_capture_drain(&thread);
    assert_int_equal(captured, 0);
    assert_int_equal(errors, 1);
    fail_allocation = false;
    io_thread_capture(&io, packet, sizeof(packet));
    io_thread_capture_drain(&thread);
    assert_int_equal(captured, 1);
}

static void *
producer(void *arg)
{
    uint32_t sequence;
    (void)arg;
    for(sequence = 0; sequence < 10000; sequence++) {
        io.timestamp.tv_nsec = sequence;
        io_thread_capture(&io, (uint8_t *)&sequence, sizeof(sequence));
    }
    return NULL;
}

static void
test_concurrent_capture(void **state)
{
    pthread_t producer_thread;
    (void)state;
    concurrent = true;
    assert_true(io_thread_capture_init(&thread, 16384));
    assert_int_equal(pthread_create(&producer_thread, NULL, producer, NULL), 0);
    while(captured < 10000) io_thread_capture_drain(&thread);
    assert_int_equal(pthread_join(producer_thread, NULL), 0);
    assert_int_equal(errors, 0);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_rx_fast_path, setup, teardown),
        cmocka_unit_test_setup_teardown(test_rx_vlan_restore, setup, teardown),
        cmocka_unit_test_setup_teardown(test_tx_copy_and_final_drain, setup, teardown),
        cmocka_unit_test_setup_teardown(test_disabled_and_overflow, setup, teardown),
        cmocka_unit_test_setup_teardown(test_allocation_failure, setup, teardown),
        cmocka_unit_test_setup_teardown(test_concurrent_capture, setup, teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
