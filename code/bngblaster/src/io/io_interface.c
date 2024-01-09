/*
 * BNG Blaster (BBL) - IO Interface Functions
 *
 * Christian Giese, July 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"
#include "ifaddrs.h"

static bool
set_kernel_info(bbl_interface_s *interface)
{
    struct ifreq ifr = {0};

    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        LOG(ERROR, "Getting MAC address error %s (%d) for interface %s\n",
            strerror(errno), errno, interface->name);
        close(fd);
        return false;
    }
    memcpy(&interface->mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);
    if(ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        LOG(ERROR, "Get interface index error %s (%d) for interface %s\n",
            strerror(errno), errno, interface->name);
        close(fd);
        return false;
    }
    interface->kernel_index = ifr.ifr_ifindex;

    close(fd);
    return true;
}

/* Set interface in promisc mode. */
static bool
set_promisc(bbl_interface_s *interface) {
    /* Taken and adapted from:
     * https://stackoverflow.com/questions/41678219/how-to-properly-put-network-interface-into-promiscuous-mode-on-linux
     * This prevents the ioctl get flags / set flags race condition. */
    struct packet_mreq mreq = {0};
    int sfd;

    LOG(DEBUG, "Set interface %s (%d) in promiscuous mode\n", interface->name, interface->kernel_index);

    /* This socket is only opened, but not closed. Closing the socket would reset
     * its flags - effectively removing the just added promisc mode.
     * We want to keep the interface in promisc mode until the end of the program. */
    if((sfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        LOG_NOARG(ERROR, "Unable to open control socket for promiscuous mode activation\n");
        return false;
    }

    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_ifindex = interface->kernel_index;
    if(setsockopt(sfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) != 0) {
        LOG(ERROR, "Failed to put interface %s in promiscuous mode\n", interface->name);
        return false;
    }
    return true;
}

static bool
io_interface_init_rx(bbl_interface_s *interface)
{
    bbl_link_config_s *config = interface->config;
    io_handle_s *io;
    
    uint8_t count = 1;
    if(config->rx_threads) {
        count = config->rx_threads;
    }

    while(count) {
        io = calloc(1, sizeof(io_handle_s));
        if(!io) return false;
        io->id = --count;
        io->mode = config->io_mode;
        if(io->mode == IO_MODE_PACKET_MMAP_RAW) {
            io->mode = IO_MODE_PACKET_MMAP;
        }
        io->direction = IO_INGRESS;
        io->next = interface->io.rx;
        interface->io.rx = io;
        io->interface = interface;
        CIRCLEQ_INIT(&io->stream_tx_qhead);
        if(config->rx_threads) {
            if(!io_thread_init(io)) {
                return false;
            }
        }
        switch(io->mode) {
            case IO_MODE_PACKET_MMAP:
                if(!io_packet_mmap_init(io)) {
                    return false;
                }
                break;
            case IO_MODE_RAW:
                if(!io_raw_init(io)) {
                    return false;
                }
                break;
            default:
                return false;
        }
    }
    return true;
}

static bool
io_interface_init_tx(bbl_interface_s *interface)
{
    bbl_link_config_s *config = interface->config;
    io_handle_s *io;
    
    uint8_t count = 1;
    if(config->tx_threads) {
        count = config->tx_threads;
    }

    while(count) {
        io = calloc(1, sizeof(io_handle_s));
        if(!io) return false;
        io->id = --count;
        io->mode = config->io_mode;
        if(io->mode == IO_MODE_PACKET_MMAP_RAW) {
            io->mode = IO_MODE_RAW;
        }
        io->direction = IO_EGRESS;
        io->next = interface->io.tx;
        interface->io.tx = io;
        io->interface = interface;
        CIRCLEQ_INIT(&io->stream_tx_qhead);
        if(config->tx_threads) {
            if(!io_thread_init(io)) {
                return false;
            }
        }
        switch(io->mode) {
            case IO_MODE_PACKET_MMAP:
                if(!io_packet_mmap_init(io)) {
                    return false;
                }
                break;
            case IO_MODE_RAW:
                if(!io_raw_init(io)) {
                    return false;
                }
                break;
            default:
                return false;
        }
    }
    return true;
}

static void
address_warning(bbl_interface_s *interface)
{
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;
    struct sockaddr_in *ipv4;
    struct sockaddr_in6 *ipv6;

    char address[INET6_ADDRSTRLEN];

    static bool warning = false;

    if(getifaddrs(&ifaddr) == 0) {
        for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if(strcmp(ifa->ifa_name, interface->name) == 0) {
                if(ifa->ifa_addr->sa_family == AF_INET) {
                    ipv4 = (struct sockaddr_in *) ifa->ifa_addr;
                    inet_ntop(AF_INET, &(ipv4->sin_addr), address, INET6_ADDRSTRLEN);
                } else if(ifa->ifa_addr->sa_family == AF_INET6) {
                    ipv6 = (struct sockaddr_in6 *) ifa->ifa_addr;
                    inet_ntop(AF_INET6, &(ipv6->sin6_addr), address, INET6_ADDRSTRLEN);
                } else {
                    continue;
                }

                if(!warning) {
                    warning = true;
                    LOG_NOARG(INFO, "Warning: Interfaces must not have an IP address configured in the host OS!\n");
                }

                LOG(INFO, "Warning: IP address %s on interface %s is conflicting!\n",
                    address, interface->name);
            }
        }
    }
    freeifaddrs(ifaddr);
}

/**
 * io_interface_init
 *
 * @param interface interface.
 */
bool
io_interface_init(bbl_interface_s *interface)
{
    bbl_link_config_s *config = interface->config;

#ifdef BNGBLASTER_DPDK
    if(config->io_mode == IO_MODE_DPDK) {
        if(!io_dpdk_interface_init(interface)) {
            return false;
        }
    }
#endif

    if(config->io_mode != IO_MODE_DPDK) {
        address_warning(interface);
        if(!set_kernel_info(interface)) {
            return false;
        }
        if(!set_promisc(interface)) {
            return false;
        }
        if(*(uint32_t*)config->mac) {
            memcpy(interface->mac, config->mac, ETH_ADDR_LEN);
        }
        if(!io_interface_init_rx(interface)) {
            return false;
        }
        if(!io_interface_init_tx(interface)) {
            return false;
        }
    }
    return true;
}