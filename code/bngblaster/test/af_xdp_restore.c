#include "io/io.h"
#include <assert.h>
#include <stdarg.h>

static int test_socket(int domain, int type, int protocol);
static int test_close(int fd);
static int test_ioctl(int fd, unsigned long request, ...);
static unsigned test_if_nametoindex(const char *name);

#undef LOG
#define LOG(...) ((void)0)
#define socket test_socket
#define close test_close
#define ioctl test_ioctl
#define if_nametoindex test_if_nametoindex
#include "../src/io/io_af_xdp.c"
#undef socket
#undef close
#undef ioctl
#undef if_nametoindex

#define RSS_SIZE 32
#define KEY_SIZE 4

static uint32_t active_queues;
static uint32_t indirection[RSS_SIZE];
static uint8_t rss_key[KEY_SIZE] = {1, 2, 3, 4};
static unsigned invalid_writes;
static unsigned rss_writes;
static unsigned channel_writes;
static unsigned ring_writes;
static unsigned flag_writes;
static bool reject_channels;
static bool reject_rss;
static bool separate_channels;

static int
test_socket(int domain, int type, int protocol)
{
    (void)domain;
    (void)type;
    (void)protocol;
    return 42;
}

static int
test_close(int fd)
{
    assert(fd == 42);
    return 0;
}

static unsigned
test_if_nametoindex(const char *name)
{
    assert(strcmp(name, "test0") == 0);
    return 7;
}

static int
test_ioctl(int fd, unsigned long request, ...)
{
    va_list args;
    struct ifreq *ifr;
    assert(fd == 42 && request == SIOCETHTOOL);
    va_start(args, request);
    ifr = va_arg(args, struct ifreq *);
    va_end(args);
    uint32_t command = *(uint32_t*)ifr->ifr_data;
    switch(command) {
        case ETHTOOL_GCHANNELS: {
            struct ethtool_channels *channels = (void*)ifr->ifr_data;
            if(separate_channels) {
                channels->rx_count = channels->tx_count = active_queues;
                channels->max_rx = channels->max_tx = 16;
            } else {
                channels->combined_count = active_queues;
                channels->max_combined = 16;
            }
            return 0;
        }
        case ETHTOOL_SCHANNELS: {
            struct ethtool_channels *channels = (void*)ifr->ifr_data;
            uint32_t target = channels->combined_count ?
                channels->combined_count : channels->rx_count;
            channel_writes++;
            if(reject_channels) break;
            for(unsigned i = 0; i < RSS_SIZE; i++) {
                if(indirection[i] >= target) {
                    invalid_writes++;
                    errno = EINVAL;
                    return -1;
                }
            }
            active_queues = target;
            return 0;
        }
        case ETHTOOL_GRSSH: {
            struct ethtool_rxfh *rss = (void*)ifr->ifr_data;
            if(!rss->indir_size) {
                rss->indir_size = RSS_SIZE;
                rss->key_size = KEY_SIZE;
            } else {
                assert(rss->indir_size == RSS_SIZE && rss->key_size == KEY_SIZE);
                memcpy(rss->rss_config, indirection, sizeof(indirection));
                memcpy((uint8_t*)(rss->rss_config + RSS_SIZE), rss_key, KEY_SIZE);
            }
            return 0;
        }
        case ETHTOOL_SRSSH: {
            struct ethtool_rxfh *rss = (void*)ifr->ifr_data;
            rss_writes++;
            if(reject_rss) break;
            for(unsigned i = 0; i < RSS_SIZE; i++) {
                if(rss->rss_config[i] >= active_queues) {
                    invalid_writes++;
                    errno = EINVAL;
                    return -1;
                }
            }
            memcpy(indirection, rss->rss_config, sizeof(indirection));
            memcpy(rss_key, (uint8_t*)(rss->rss_config + RSS_SIZE), KEY_SIZE);
            return 0;
        }
        case ETHTOOL_SRINGPARAM:
            ring_writes++;
            return 0;
        case ETHTOOL_SFLAGS:
            flag_writes++;
            return 0;
        default:
            assert(false);
    }
    errno = EINVAL;
    return -1;
}

static void
test_restore(uint32_t original, uint32_t current, bool expected)
{
    bbl_interface_s interface = {.name = "test0", .kernel_index = 7};
    io_af_xdp_state_s *state = calloc(1, sizeof(*state));
    assert(state);
    state->interface = &interface;
    state->channels.cmd = ETHTOOL_GCHANNELS;
    if(separate_channels) {
        state->channels.rx_count = state->channels.tx_count = original;
    } else {
        state->channels.combined_count = original;
    }
    state->rings.cmd = ETHTOOL_GRINGPARAM;
    state->flags.cmd = ETHTOOL_GFLAGS;
    state->rss = calloc(1, sizeof(*state->rss) + sizeof(indirection) + KEY_SIZE);
    assert(state->rss);
    state->rss->indir_size = RSS_SIZE;
    state->rss->key_size = KEY_SIZE;
    uint32_t saved[RSS_SIZE];
    for(unsigned i = 0; i < RSS_SIZE; i++) {
        saved[i] = (RSS_SIZE - i) % original;
        state->rss->rss_config[i] = saved[i];
        indirection[i] = i % current;
    }
    uint8_t saved_key[KEY_SIZE] = {5, 6, 7, 8};
    memcpy((uint8_t*)(state->rss->rss_config + RSS_SIZE), saved_key, KEY_SIZE);
    active_queues = current;
    af_xdp_states = state;
    assert(io_af_xdp_cleanup() == expected);
    assert(!af_xdp_states && !af_xdp_queues);
    assert(invalid_writes == 0);
    assert(ring_writes == 1 && flag_writes == 1);
    if(expected) {
        assert(active_queues == original);
        assert(memcmp(indirection, saved, sizeof(saved)) == 0);
        assert(memcmp(rss_key, saved_key, KEY_SIZE) == 0);
    }
    assert(io_af_xdp_cleanup());
}

int
main(int argc, char **argv)
{
    assert(argc == 2);
    if(strcmp(argv[1], "expand") == 0) {
        test_restore(16, 3, true);
    } else if(strcmp(argv[1], "shrink") == 0) {
        test_restore(3, 16, true);
    } else if(strcmp(argv[1], "unchanged") == 0) {
        test_restore(16, 16, true);
    } else if(strcmp(argv[1], "separate-expand") == 0) {
        separate_channels = true;
        test_restore(16, 3, true);
    } else if(strcmp(argv[1], "separate-shrink") == 0) {
        separate_channels = true;
        test_restore(3, 16, true);
    } else if(strcmp(argv[1], "channels-fail") == 0) {
        reject_channels = true;
        test_restore(16, 3, false);
        assert(rss_writes == 0);
    } else if(strcmp(argv[1], "rss-fail") == 0) {
        reject_rss = true;
        test_restore(16, 3, false);
        assert(channel_writes == 1);
    } else if(strcmp(argv[1], "clamp-fail") == 0) {
        reject_rss = true;
        test_restore(3, 16, false);
        assert(channel_writes == 0 && rss_writes == 1);
    } else if(strcmp(argv[1], "preserve") == 0) {
        bbl_interface_s interface = {.name = "test0"};
        bool changed;
        active_queues = 16;
        for(unsigned i = 0; i < RSS_SIZE; i++) indirection[i] = 1;
        assert(io_af_xdp_clamp_rss_indir(&interface, 3, false, &changed));
        assert(!changed && rss_writes == 0);
        indirection[0] = 15;
        assert(io_af_xdp_clamp_rss_indir(&interface, 3, false, &changed));
        assert(changed && indirection[0] < 3 && rss_writes == 1);
        for(unsigned i = 1; i < RSS_SIZE; i++) assert(indirection[i] == 1);
    } else if(strcmp(argv[1], "rebalance") == 0) {
        bbl_interface_s interface = {.name = "test0"};
        bool changed;
        active_queues = 3;
        assert(io_af_xdp_clamp_rss_indir(&interface, 3, true, &changed));
        assert(changed && rss_writes == 1);
        for(unsigned i = 0; i < RSS_SIZE; i++) assert(indirection[i] == i % 3);
        assert(io_af_xdp_clamp_rss_indir(&interface, 3, true, &changed));
        assert(!changed && rss_writes == 1);
    } else if(strcmp(argv[1], "handles") == 0) {
        io_handle_s io = {.fd = 42};
        io_af_xdp_queue_s *queue = calloc(1, sizeof(*queue));
        assert(queue);
        io.af_xdp_queue = queue;
        queue->io = &io;
        af_xdp_queues = queue;
        assert(io_af_xdp_cleanup());
        assert(!io.af_xdp_queue && io.fd == -1 && !af_xdp_queues);
        assert(io_af_xdp_cleanup());
    } else if(strcmp(argv[1], "setup-expand") == 0 ||
              strcmp(argv[1], "setup-shrink") == 0) {
        bbl_interface_s interface = {.name = "test0"};
        uint32_t target = strcmp(argv[1], "setup-expand") == 0 ? 16 : 3;
        active_queues = target == 16 ? 3 : 16;
        for(unsigned i = 0; i < RSS_SIZE; i++) indirection[i] = i % active_queues;
        assert(io_af_xdp_set_channels(&interface, target));
        assert(active_queues == target && invalid_writes == 0);
        assert(io_af_xdp_constrain_rss(&interface, target - 1, target));
        for(unsigned i = 0; i < RSS_SIZE; i++) assert(indirection[i] == i % (target - 1));
    } else {
        assert(false);
    }
    return 0;
}
