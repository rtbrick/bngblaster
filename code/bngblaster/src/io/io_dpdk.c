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
#include <rte_malloc.h>

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 128

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.split_hdr_size = 0,
	},
	.txmode = {
		.mq_mode = RTE_ETH_MQ_TX_NONE,
	},
};

struct rte_mempool *mbuf_pool;

static bool
io_dpdk_dev_info(uint16_t portid, struct rte_eth_dev_info *dev_info)
{
    int ret = rte_eth_dev_info_get(portid, dev_info);
    if(ret != 0) {
        LOG(ERROR, "DPDK: Error during getting device (port %u) info: %s\n",
            portid, strerror(-ret));
        return false;
    }
    return true;
}

bool
io_dpdk_init()
{
    uint16_t portid;
    uint16_t dpdk_ports;

    struct rte_eth_dev_info dev_info;    
    
    if(!g_ctx->dpdk) {
        return true;
    }

    char *dpdk_args[2];
    char **argv=dpdk_args;

    dpdk_args[0] = "bngblaster";
    dpdk_args[1] = "-v";

    LOG_NOARG(DPDK, "DPDK: init the EAL\n");
    rte_eal_init(2, argv);
    dpdk_ports = rte_eth_dev_count_avail();

    LOG(DPDK, "DPDK: %u ports available\n", dpdk_ports);

    RTE_ETH_FOREACH_DEV(portid) {
        if(!io_dpdk_dev_info(portid, &dev_info)) {
            return false;
        }
        LOG(DPDK, "DPDK: %s (port %u)\n",
            dev_info.device->name, portid);
    }

    mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
        NUM_MBUFS * dpdk_ports, MBUF_CACHE_SIZE, 0,
        RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if(!mbuf_pool) {
        LOG(ERROR, "DPDK: failed to create mbuf pool\n");
        return false;
    }

    return true;
}

void
io_dpdk_close()
{
    if(g_ctx->dpdk) {
        LOG_NOARG(DPDK, "DPDK: clean up the EAL\n");
        rte_eal_cleanup();
    }
}

/**
 * This job is for DPDK RX in main thread!
 */
void
io_dpdk_rx_job(timer_s *timer)
{
    io_handle_s *io = timer->data;
    bbl_interface_s *interface = io->interface;

    bbl_ethernet_header_s *eth;

    struct rte_mbuf *pkts_burst[BURST_SIZE];
	struct rte_mbuf *packet;
    uint16_t nb_rx;
    uint16_t i;

    protocol_error_t decode_result;
    bool pcap = false;

    assert(io->mode == IO_MODE_DPDK);
    assert(io->direction == IO_INGRESS);
    assert(io->thread == NULL);

    /* Get RX timestamp */
    clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
    nb_rx = rte_eth_rx_burst(interface->portid, io->queue, pkts_burst, BURST_SIZE);
    for(i = 0; i < nb_rx; i++) {
        packet = pkts_burst[i];
        io->buf = rte_pktmbuf_mtod(packet, uint8_t *);
        io->buf_len = packet->pkt_len;
        io->stats.packets++;
        io->stats.bytes += io->buf_len;
        decode_result = decode_ethernet(io->buf, io->buf_len, g_ctx->sp, SCRATCHPAD_LEN, &eth);
        if(decode_result == PROTOCOL_SUCCESS) {
            /* Copy RX timestamp */
            eth->timestamp.tv_sec = io->timestamp.tv_sec;
            eth->timestamp.tv_nsec = io->timestamp.tv_nsec;
            bbl_rx_handler(interface, eth);
        } else if(decode_result == UNKNOWN_PROTOCOL) {
            io->stats.unknown++;
        } else {
            io->stats.protocol_errors++;
        }
        /* Dump the packet into pcap file */
        if(g_ctx->pcap.write_buf && (!eth->bbl || g_ctx->pcap.include_streams)) {
            pcap = true;
            pcapng_push_packet_header(&io->timestamp, io->buf, io->buf_len,
                                      interface->pcap_index, PCAPNG_EPB_FLAGS_INBOUND);
        }
    }
    if(pcap) {
        pcapng_fflush();
    }
}

/*
 * This job is for DPDK TX in main thread!
 */
void
io_dpdk_tx_job(timer_s *timer)
{
    io_handle_s *io = timer->data;

    assert(io->mode == IO_MODE_DPDK);
    assert(io->direction == IO_EGRESS);
    assert(io->thread == NULL);

    io_update_stream_token_bucket(io);
}

void
io_dpdk_thread_rx_run_fn(io_thread_s *thread)
{
    io_handle_s *io = thread->io;
    bbl_interface_s *interface = io->interface;

    struct rte_mbuf *pkts_burst[BURST_SIZE];
    struct rte_mbuf *packet;

    uint16_t portid = interface->portid;
    uint16_t nb_rx;
    uint16_t i;

    assert(io->mode == IO_MODE_DPDK);
    assert(io->direction == IO_INGRESS);
    assert(io->thread);

    struct timespec sleep, rem;
    sleep.tv_sec = 0;
    sleep.tv_nsec = 0;

    while(thread->active) {
        nb_rx = rte_eth_rx_burst(portid, io->queue, pkts_burst, BURST_SIZE);
        if(nb_rx == 0) {
            sleep.tv_nsec = 1000; /* 0.001ms */
            nanosleep(&sleep, &rem);
            continue;
        }
        /* Get RX timestamp */
        clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
        for(i = 0; i < nb_rx; i++) {
            packet = pkts_burst[i];
            io->buf = rte_pktmbuf_mtod(packet, uint8_t *);
            io->buf_len = packet->pkt_len;
            /* Process packet */
            io_thread_rx_handler(thread, io);
        }
    }
}

/**
 * This job is for DPDK TX in worker thread!
 */
void
io_dpdk_thread_tx_job(timer_s *timer)
{
    io_thread_s *thread = timer->data;
    io_handle_s *io = thread->io;

    assert(io->mode == IO_MODE_DPDK);
    assert(io->direction == IO_EGRESS);
    assert(io->thread);

    io_update_stream_token_bucket(io);
}

bool
io_dpdk_interface_init(bbl_interface_s *interface)
{
    bbl_link_config_s *config = interface->config;

    int ret;
    bool found = false;

    uint16_t portid;
    uint16_t queue;
    uint16_t id;
    uint16_t nb_rx_queue = 1;
    uint16_t nb_tx_queue = 1;
    struct rte_eth_dev_info dev_info;
    struct rte_eth_conf local_port_conf = port_conf;
    struct rte_eth_rxconf rx_conf;
    struct rte_eth_txconf tx_conf;
    struct rte_ether_addr mac;
    io_handle_s *io;

    RTE_ETH_FOREACH_DEV(portid) {
        if(io_dpdk_dev_info(portid, &dev_info)) {
            if(strcmp(dev_info.device->name, interface->name) == 0) {
                found = true;
                interface->portid = portid;
                break;
            }
        }
    }
    if(!found) {
        LOG(ERROR, "DPDK: interface %s not found\n", interface->name);
        return false;
    }

    /* Get MAC address */
    if(*(uint32_t*)config->mac) {
        memcpy(interface->mac, config->mac, ETH_ADDR_LEN);
    } else {
        if(rte_eth_macaddr_get(portid, &mac) < 0) {
            LOG(ERROR, "DPDK: failed to get MAC from interface %s\n", interface->name);
            return false;
        }
        memcpy(interface->mac, mac.addr_bytes, ETH_ADDR_LEN);
    }

    /* Configure interface */
    if(config->tx_threads) {
        nb_tx_queue = config->tx_threads;
    }
    if(config->rx_threads) {
        nb_rx_queue = config->rx_threads;
    }
    if(dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE) {
        local_port_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;
    }
    ret = rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, &local_port_conf);
    if(ret < 0) {
        LOG(ERROR, "DPDK: failed to configure interface %s (error %d)\n",
            interface->name, ret);
        return false;
    }
    ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &config->io_slots_rx, &config->io_slots_tx);
    if(ret < 0) {
        LOG(ERROR, "DPDK: failed to adjust number of descriptors for interface %s (error %d)\n",
            interface->name, ret);
        return false;
    }

    id = nb_rx_queue;
    for(queue = 0; queue < nb_rx_queue; queue++) {
        io = calloc(1, sizeof(io_handle_s));
        if(!io) return false;
        io->id = --id;
        io->mode = config->io_mode;
        io->direction = IO_INGRESS;
        io->next = interface->io.rx;
        interface->io.rx = io;
        io->interface = interface;
        CIRCLEQ_INIT(&io->stream_tx_qhead);
        if(config->rx_threads) {
            if(!io_thread_init(io)) {
                return false;
            }
            io->thread->run_fn = io_dpdk_thread_rx_run_fn;
        } else {
            timer_add_periodic(&g_ctx->timer_root, &interface->io.rx_job, "RX", 0, 
                config->rx_interval, io, &io_dpdk_rx_job);
        }
        io->queue = queue;
#if 0
        io->mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL",
            NUM_MBUFS, MBUF_CACHE_SIZE, 0,
            RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
        if(!io->mbuf_pool) {
            LOG(ERROR, "DPDK: failed to create mbuf pool for interface %s queue %u (error %d)\n",
                interface->name, queue, ret);
            return false;
        }
#endif
        rx_conf = dev_info.default_rxconf;
        rx_conf.offloads = local_port_conf.rxmode.offloads;
        ret = rte_eth_rx_queue_setup(portid, queue, config->io_slots_rx,
                                     rte_eth_dev_socket_id(portid), 
                                     &rx_conf, mbuf_pool);
        if(ret < 0) {
            LOG(ERROR, "DPDK: failed to setup RX queue %u for interface %s (error %d)\n",
                queue, interface->name, ret);
            return false;
        }
    }

    id = nb_tx_queue;
    for(queue = 0; queue < nb_tx_queue; queue++) {
        io = calloc(1, sizeof(io_handle_s));
        if(!io) return false;
        io->id = --id;
        io->mode = config->io_mode;
        io->direction = IO_EGRESS;
        io->next = interface->io.tx;
        interface->io.tx = io;
        io->interface = interface;
        io->buf = malloc(IO_BUFFER_LEN);
        CIRCLEQ_INIT(&io->stream_tx_qhead);
        if(config->tx_threads) {
            if(!io_thread_init(io)) {
                return false;
            }
            timer_add_periodic(&io->thread->timer.root, &io->thread->timer.io, "TX (threaded)", 0, 
                config->tx_interval, io->thread, &io_dpdk_thread_tx_job);
            io->thread->timer.io->reset = false;
        } else {
            timer_add_periodic(&g_ctx->timer_root, &interface->io.tx_job, "TX", 0, 
                config->tx_interval, io, &io_dpdk_tx_job);
            interface->io.tx_job->reset = false;
        }

        tx_conf = dev_info.default_txconf;
        tx_conf.offloads = local_port_conf.txmode.offloads;
        ret = rte_eth_tx_queue_setup(portid, queue, config->io_slots_tx,
                                    rte_eth_dev_socket_id(portid),
                                    &tx_conf);
        if(ret < 0) {
            LOG(ERROR, "DPDK: failed to setup TX queue %u for interface %s (error %d)\n",
                queue, interface->name, ret);
            return false;
        }

        /* Initialize TX buffers */
        io->tx_buffer = rte_zmalloc_socket("tx_buffer",
                RTE_ETH_TX_BUFFER_SIZE(BURST_SIZE), 0,
                rte_eth_dev_socket_id(portid));
        if (!io->tx_buffer) {
            LOG(ERROR, "DPDK: failed to allocate TX buffer for interface %s queue %u (error %d)\n",
                interface->name, queue, ret);
            return false;
        }
        rte_eth_tx_buffer_init(io->tx_buffer, BURST_SIZE);
        ret = rte_eth_tx_buffer_set_err_callback(io->tx_buffer, 
            rte_eth_tx_buffer_count_callback, &io->stats.dropped);
        if(ret < 0) {
            LOG(ERROR, "DPDK: failed to set TX error callback for interface %s queue %u (error %d)\n",
                interface->name, queue, ret);
            return false;
        }
    }

    ret = rte_eth_dev_set_ptypes(portid, RTE_PTYPE_UNKNOWN, NULL, 0);
    if (ret < 0) {
        LOG(ERROR, "DPDK: failed to disable ptype parsing for interface %s (error %d)\n",
            interface->name, ret);
        return false;
    }
 
    ret = rte_eth_dev_start(portid);
    if (ret < 0) {
        LOG(ERROR, "DPDK: failed to start interface %s (error %d)\n",
            interface->name, ret);
        return false;
    }

    ret = rte_eth_promiscuous_enable(portid);
    if (ret < 0) {
        LOG(ERROR, "DPDK: failed to enable promiscuous mode for interface %s (error %d)\n",
            interface->name, ret);
        return false;
    }

    return true;
}

#endif