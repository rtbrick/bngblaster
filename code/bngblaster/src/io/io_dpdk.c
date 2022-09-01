/*
 * BNG Blaster (BBL) - IO DPDK Functions (EXPERIMENTAL/WIP)
 *
 * TESTED WITH DPDK 21.11.1
 * 
 * Christian Giese, September 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"

//#ifndef BNGBLASTER_DPDK
//#define BNGBLASTER_DPDK 1
//#endif

#ifdef BNGBLASTER_DPDK

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ethdev.h>

bool
io_dpdk_init()
{
    int ret;
    uint16_t portid;
    uint16_t dpdk_ports;

    struct rte_eth_dev_info dev_info;    
    
    char *dpdk_args[2];
    char **argv=dpdk_args;

    dpdk_args[0] = "bngblaster";
    dpdk_args[1] = "-v";

    rte_eal_init(2, argv);
    dpdk_ports = rte_eth_dev_count_avail();

    LOG(DEBUG, "DPDK: %u ports available\n", dpdk_ports);

    RTE_ETH_FOREACH_DEV(portid) {
        ret = rte_eth_dev_info_get(portid, &dev_info);
        if(ret != 0) {
            LOG(DEBUG, "DPDK: Error during getting device (port %u) info: %s\n",
                portid, strerror(-ret));
            return false;
        }
        LOG(DEBUG, "DPDK: %s (port %u)\n",
            dev_info.device->name, portid);
    }
    return true;
}

#endif