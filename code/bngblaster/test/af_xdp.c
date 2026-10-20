/*
 * BNG Blaster (BBL) - AF_XDP NIC Configuration Tests
 *
 * The NIC configuration functions of io_af_xdp.c are tested against a
 * simulated NIC, which replaces the ethtool ioctl calls and enforces the
 * kernel rules relevant for the order of changes.
 *
 * Christian Giese, October 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

#include "../src/io/io.h"

static int test_socket(int domain, int type, int protocol);
static int test_close(int fd);
static int test_ioctl(int fd, unsigned long request, ...);
static unsigned int test_if_nametoindex(const char *ifname);
static int test_nanosleep(const struct timespec *req, struct timespec *rem);

/* Log messages are not printed, but their format is still checked. */
#undef LOG
#define LOG(log_id_, fmt_, ...) do { if(0) printf(fmt_, ##__VA_ARGS__); } while(0)
#define socket test_socket
#define close test_close
#define ioctl test_ioctl
#define if_nametoindex test_if_nametoindex
#define nanosleep test_nanosleep
#include "../src/io/io_af_xdp.c"
#undef socket
#undef close
#undef ioctl
#undef if_nametoindex
#undef nanosleep

#define TEST_FD             42
#define TEST_KERNEL_INDEX   7
#define NIC_INDIR_SIZE      32
#define NIC_KEY_SIZE        4

static struct {
    uint32_t channels;
    uint32_t indir[NIC_INDIR_SIZE];
    bool indir_configured; /* table written by the user (IFF_RXFH_CONFIGURED) */
    uint32_t rx_ring;
    uint32_t rx_ring_max;
    uint32_t flags;
    uint32_t kernel_index;
    uint32_t xsk_bound; /* channel changes refused while AF_XDP sockets are released */
    bool reject_channels;
    uint32_t invalid; /* requests the kernel would refuse */
    uint32_t writes;
} nic;

static int
test_socket(int domain, int type, int protocol)
{
    (void)domain; (void)type; (void)protocol;
    return TEST_FD;
}

static int
test_close(int fd)
{
    assert_int_equal(fd, TEST_FD);
    return 0;
}

static unsigned int
test_if_nametoindex(const char *ifname)
{
    (void)ifname;
    return nic.kernel_index;
}

static int
test_nanosleep(const struct timespec *req, struct timespec *rem)
{
    (void)req; (void)rem;
    return 0;
}

static void
nic_indir_default()
{
    for(uint32_t i = 0; i < NIC_INDIR_SIZE; i++) {
        nic.indir[i] = i % nic.channels;
    }
    nic.indir_configured = false;
}

static int
nic_error(int error)
{
    errno = error;
    return -1;
}

static int
test_ioctl(int fd, unsigned long request, ...)
{
    struct ifreq *ifr;
    va_list args;

    assert_int_equal(fd, TEST_FD);
    assert_int_equal(request, SIOCETHTOOL);
    va_start(args, request);
    ifr = va_arg(args, struct ifreq *);
    va_end(args);

    switch(*(uint32_t*)ifr->ifr_data) {
        case ETHTOOL_GCHANNELS: {
            struct ethtool_channels *ch = (void*)ifr->ifr_data;
            ch->max_combined = 16;
            ch->combined_count = nic.channels;
            return 0;
        }
        case ETHTOOL_SCHANNELS: {
            struct ethtool_channels *ch = (void*)ifr->ifr_data;
            nic.writes++;
            if(nic.reject_channels) {
                return nic_error(EIO);
            }
            if(ch->combined_count < nic.channels && nic.xsk_bound) {
                nic.xsk_bound--;
                return nic_error(EINVAL);
            }
            for(uint32_t i = 0; i < NIC_INDIR_SIZE && nic.indir_configured; i++) {
                if(nic.indir[i] >= ch->combined_count) {
                    nic.invalid++;
                    return nic_error(EINVAL);
                }
            }
            nic.channels = ch->combined_count;
            if(!nic.indir_configured) {
                nic_indir_default();
            }
            return 0;
        }
        case ETHTOOL_GRSSH: {
            struct ethtool_rxfh *rxfh = (void*)ifr->ifr_data;
            uint32_t indir_size = rxfh->indir_size;
            uint32_t key_size = rxfh->key_size;
            rxfh->indir_size = NIC_INDIR_SIZE;
            rxfh->key_size = NIC_KEY_SIZE;
            if(indir_size) {
                assert_int_equal(indir_size, NIC_INDIR_SIZE);
                memcpy(rxfh->rss_config, nic.indir, sizeof(nic.indir));
            }
            if(key_size) {
                assert_int_equal(key_size, NIC_KEY_SIZE);
                memset((uint8_t*)&rxfh->rss_config[indir_size], 0xab, NIC_KEY_SIZE);
            }
            return 0;
        }
        case ETHTOOL_SRSSH: {
            struct ethtool_rxfh *rxfh = (void*)ifr->ifr_data;
            nic.writes++;
            if(!rxfh->indir_size) {
                nic_indir_default();
                return 0;
            }
            assert_int_equal(rxfh->indir_size, NIC_INDIR_SIZE);
            for(uint32_t i = 0; i < NIC_INDIR_SIZE; i++) {
                if(rxfh->rss_config[i] >= nic.channels) {
                    nic.invalid++;
                    return nic_error(EINVAL);
                }
            }
            memcpy(nic.indir, rxfh->rss_config, sizeof(nic.indir));
            nic.indir_configured = true;
            return 0;
        }
        case ETHTOOL_GRINGPARAM: {
            struct ethtool_ringparam *ring = (void*)ifr->ifr_data;
            if(!nic.rx_ring_max) {
                return nic_error(EOPNOTSUPP);
            }
            ring->rx_max_pending = nic.rx_ring_max;
            ring->rx_pending = nic.rx_ring;
            return 0;
        }
        case ETHTOOL_SRINGPARAM: {
            struct ethtool_ringparam *ring = (void*)ifr->ifr_data;
            nic.writes++;
            if(ring->rx_pending > nic.rx_ring_max) {
                nic.invalid++;
                return nic_error(EINVAL);
            }
            nic.rx_ring = ring->rx_pending;
            return 0;
        }
        case ETHTOOL_GFLAGS: {
            struct ethtool_value *eval = (void*)ifr->ifr_data;
            eval->data = nic.flags;
            return 0;
        }
        case ETHTOOL_SFLAGS: {
            struct ethtool_value *eval = (void*)ifr->ifr_data;
            nic.writes++;
            nic.flags = eval->data;
            return 0;
        }
        default:
            fail_msg("unexpected ethtool command 0x%x", *(uint32_t*)ifr->ifr_data);
    }
    return nic_error(EOPNOTSUPP);
}

static bbl_link_config_s test_config;
static bbl_interface_s test_interface;

static int
test_setup(void **unused)
{
    (void)unused;
    memset(&nic, 0x0, sizeof(nic));
    nic.channels = 2;
    nic.rx_ring = 512;
    nic.rx_ring_max = 8160;
    nic.flags = ETH_FLAG_RXVLAN | ETH_FLAG_RXHASH;
    nic.kernel_index = TEST_KERNEL_INDEX;
    nic_indir_default();

    memset(&test_config, 0x0, sizeof(test_config));
    test_config.io_slots_rx = 4096;
    memset(&test_interface, 0x0, sizeof(test_interface));
    test_interface.name = "test0";
    test_interface.kernel_index = TEST_KERNEL_INDEX;
    test_interface.config = &test_config;
    return 0;
}

static int
test_teardown(void **unused)
{
    (void)unused;
    if(test_interface.io.af_xdp_state) {
        free(test_interface.io.af_xdp_state->rss_indir);
        free(test_interface.io.af_xdp_state);
        test_interface.io.af_xdp_state = NULL;
    }
    return 0;
}

/* AF_XDP initialization steps changing the NIC configuration. */
static void
test_init(uint16_t rx_queues, uint16_t tx_queues)
{
    assert_true(io_af_xdp_save_state(&test_interface));
    assert_true(io_af_xdp_disable_rxvlan_offload(&test_interface));
    assert_true(io_af_xdp_set_channels(&test_interface, rx_queues + tx_queues));
    io_af_xdp_prepare_rx_ring(&test_interface);
    assert_true(io_af_xdp_constrain_rss(&test_interface, rx_queues, rx_queues + tx_queues));
}

static void
test_af_xdp_rss_clamp(void **unused)
{
    (void)unused;
    bool changed;

    nic.channels = 4;
    for(uint32_t i = 0; i < NIC_INDIR_SIZE; i++) {
        nic.indir[i] = 1;
    }
    nic.indir[0] = 3;
    nic.indir_configured = true;

    /* Only entries beyond the limit are remapped. */
    assert_true(io_af_xdp_clamp_rss_indir(&test_interface, 2, false, &changed));
    assert_true(changed);
    for(uint32_t i = 0; i < NIC_INDIR_SIZE; i++) {
        assert_int_equal(nic.indir[i], 1);
    }
    assert_true(io_af_xdp_clamp_rss_indir(&test_interface, 2, false, &changed));
    assert_false(changed);

    /* Rebalancing spreads a collapsed table over all queues. */
    assert_true(io_af_xdp_clamp_rss_indir(&test_interface, 2, true, &changed));
    assert_true(changed);
    for(uint32_t i = 0; i < NIC_INDIR_SIZE; i++) {
        assert_int_equal(nic.indir[i], i % 2);
    }
    assert_int_equal(nic.invalid, 0);
}

static void
test_af_xdp_restore_default(void **unused)
{
    (void)unused;

    /* Grow from 2 to 4 channels with 2 RX queues, which writes the RSS
     * table. The default table is reset to the driver default on restore,
     * also if the kernel releases the AF_XDP sockets with delay. */
    test_init(2, 2);
    assert_int_equal(nic.channels, 4);
    assert_true(nic.indir_configured);
    assert_int_equal(nic.flags & ETH_FLAG_RXVLAN, 0);

    nic.xsk_bound = 3;
    assert_true(io_af_xdp_restore_state(&test_interface));
    assert_null(test_interface.io.af_xdp_state);
    assert_int_equal(nic.channels, 2);
    assert_false(nic.indir_configured);
    for(uint32_t i = 0; i < NIC_INDIR_SIZE; i++) {
        assert_int_equal(nic.indir[i], i % 2);
    }
    assert_int_equal(nic.flags, ETH_FLAG_RXVLAN | ETH_FLAG_RXHASH);
    assert_int_equal(nic.invalid, 0);
}

static void
test_af_xdp_restore_configured(void **unused)
{
    (void)unused;
    uint32_t saved[NIC_INDIR_SIZE];

    /* Shrink from 4 channels with a configured table referencing all
     * queues, which must be clamped before changing the channels, and
     * restore the table after the channels. */
    nic.channels = 4;
    for(uint32_t i = 0; i < NIC_INDIR_SIZE; i++) {
        nic.indir[i] = 3 - (i % 4);
    }
    nic.indir_configured = true;
    memcpy(saved, nic.indir, sizeof(saved));

    test_init(1, 1);
    assert_int_equal(nic.channels, 2);
    for(uint32_t i = 0; i < NIC_INDIR_SIZE; i++) {
        assert_int_equal(nic.indir[i], 0);
    }

    assert_true(io_af_xdp_restore_state(&test_interface));
    assert_int_equal(nic.channels, 4);
    assert_true(nic.indir_configured);
    assert_memory_equal(nic.indir, saved, sizeof(saved));
    assert_int_equal(nic.invalid, 0);
}

static void
test_af_xdp_restore_failed(void **unused)
{
    (void)unused;
    uint32_t writes;

    /* The RSS table is not restored if the channels can't be restored,
     * as it might reference queues that do not exist. */
    test_init(2, 2);
    nic.reject_channels = true;
    writes = nic.writes;
    assert_false(io_af_xdp_restore_state(&test_interface));
    assert_null(test_interface.io.af_xdp_state);
    assert_int_equal(nic.channels, 4);
    assert_true(nic.indir_configured);
    assert_int_equal(nic.rx_ring, 512);
    assert_true(nic.flags & ETH_FLAG_RXVLAN);
    /* Failed channel change, RX ring and flags. */
    assert_int_equal(nic.writes, writes + 3);

    /* Nothing is restored to a removed or recreated interface. */
    test_setup(NULL);
    test_init(2, 2);
    nic.kernel_index++;
    writes = nic.writes;
    assert_false(io_af_xdp_restore_state(&test_interface));
    assert_null(test_interface.io.af_xdp_state);
    assert_int_equal(nic.writes, writes);
}

static void
test_af_xdp_rx_ring(void **unused)
{
    (void)unused;

    /* The RX ring is increased and the RX frames sized automatically. */
    test_init(1, 1);
    assert_int_equal(nic.rx_ring, AF_XDP_RX_RING);
    assert_int_equal(test_interface.io.af_xdp_state->rx_frames, 2 * AF_XDP_RX_RING);
    assert_true(io_af_xdp_restore_state(&test_interface));
    assert_int_equal(nic.rx_ring, 512);

    /* A larger RX ring is kept. */
    test_setup(NULL);
    nic.rx_ring = 8160;
    test_init(1, 1);
    assert_int_equal(nic.rx_ring, 8160);
    assert_int_equal(test_interface.io.af_xdp_state->rx_frames, 16384);
    assert_false(test_interface.io.af_xdp_state->ring_changed);
    assert_true(io_af_xdp_restore_state(&test_interface));
    assert_int_equal(nic.rx_ring, 8160);

    /* A larger io-slots-rx is kept. */
    test_setup(NULL);
    test_config.io_slots_rx = 30000;
    test_init(1, 1);
    assert_int_equal(test_interface.io.af_xdp_state->rx_frames, 32768);
    assert_true(io_af_xdp_restore_state(&test_interface));

    /* An explicit io-slots-rx is not changed. */
    test_setup(NULL);
    test_config.io_slots_rx_set = true;
    test_init(1, 1);
    assert_int_equal(nic.rx_ring, AF_XDP_RX_RING);
    assert_int_equal(test_interface.io.af_xdp_state->rx_frames, 4096);
    assert_true(io_af_xdp_restore_state(&test_interface));

    /* The RX ring is limited to the NIC maximum. */
    test_setup(NULL);
    nic.rx_ring = 256;
    nic.rx_ring_max = 1024;
    test_init(1, 1);
    assert_int_equal(nic.rx_ring, 1024);
    assert_int_equal(test_interface.io.af_xdp_state->rx_frames, 4096);
    assert_true(io_af_xdp_restore_state(&test_interface));
    assert_int_equal(nic.rx_ring, 256);

    /* Drivers without RX ring support use io-slots-rx. */
    test_setup(NULL);
    nic.rx_ring_max = 0;
    test_config.io_slots_rx = 1000;
    test_init(1, 1);
    assert_int_equal(test_interface.io.af_xdp_state->rx_frames, 1024);
    assert_true(io_af_xdp_restore_state(&test_interface));
    assert_int_equal(nic.invalid, 0);
}

int
main()
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_af_xdp_rss_clamp, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_af_xdp_restore_default, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_af_xdp_restore_configured, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_af_xdp_restore_failed, test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_af_xdp_rx_ring, test_setup, test_teardown),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
