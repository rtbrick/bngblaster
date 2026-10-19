#include "io/io.h"
#include <assert.h>
#include <stdarg.h>

static int test_socket(int domain, int type, int protocol);
static int test_close(int fd);
static int test_ioctl(int fd, unsigned long request, ...);

#undef LOG
#define LOG(...) ((void)0)
#define socket test_socket
#define close test_close
#define ioctl test_ioctl
#include "../src/io/io_af_xdp.c"
#undef socket
#undef close
#undef ioctl

static uint32_t pending;
static uint32_t maximum;
static unsigned writes;
static bool unsupported;
static bool reject;
static bool mismatch;

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

static int
test_ioctl(int fd, unsigned long request, ...)
{
    va_list args;
    struct ifreq *ifr;
    struct ethtool_ringparam *ring;
    assert(fd == 42);
    assert(request == SIOCETHTOOL);
    va_start(args, request);
    ifr = va_arg(args, struct ifreq *);
    va_end(args);
    ring = (void*)ifr->ifr_data;
    if(unsupported) {
        errno = EOPNOTSUPP;
        return -1;
    }
    if(ring->cmd == ETHTOOL_GRINGPARAM) {
        ring->rx_pending = pending;
        ring->rx_max_pending = maximum;
        return 0;
    }
    assert(ring->cmd == ETHTOOL_SRINGPARAM);
    writes++;
    if(reject) {
        errno = EINVAL;
        return -1;
    }
    if(!mismatch) pending = ring->rx_pending;
    return 0;
}

int
main(void)
{
    bbl_link_config_s config = {.io_slots_rx = 8192};
    bbl_interface_s interface = {.name = "test0", .config = &config};

    pending = 512;
    maximum = 4096;
    assert(io_af_xdp_prepare_rx_ring(&interface));
    assert(pending == 4096 && writes == 1);
    assert(io_af_xdp_prepare_rx_ring(&interface));
    assert(writes == 1);

    pending = 512;
    maximum = 2048;
    assert(io_af_xdp_prepare_rx_ring(&interface));
    assert(pending == 2048 && writes == 2);

    pending = 512;
    maximum = 4096;
    config.io_slots_rx = 4096;
    assert(!io_af_xdp_prepare_rx_ring(&interface));
    assert(pending == 512 && writes == 2);
    pending = 4096;
    assert(!io_af_xdp_prepare_rx_ring(&interface));
    assert(writes == 2);

    config.io_slots_rx = 8192;
    pending = 512;
    reject = true;
    assert(!io_af_xdp_prepare_rx_ring(&interface));
    reject = false;
    mismatch = true;
    assert(!io_af_xdp_prepare_rx_ring(&interface));
    mismatch = false;
    unsupported = true;
    assert(io_af_xdp_prepare_rx_ring(&interface));
    return 0;
}
