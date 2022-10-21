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

#ifndef BNGBLASTER_DPDK
#define BNGBLASTER_DPDK 1
#endif

#ifdef BNGBLASTER_DPDK

#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>

#define NUM_MBUFS 4096
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

static struct rte_eth_conf port_conf = {
    .rxmode = {
        .split_hdr_size = 0,
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
};

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

    return true;
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

    struct rte_mbuf *packet_burst[BURST_SIZE];
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
    while(true) {
        nb_rx = rte_eth_rx_burst(interface->portid, io->queue, packet_burst, BURST_SIZE);
        if(nb_rx == 0) {
            break;
        }
        for(i = 0; i < nb_rx; i++) {
            packet = packet_burst[i];
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
            rte_pktmbuf_free(packet);
        }
    }
    if(pcap) {
        pcapng_fflush();
    }
}

static bool
io_dpdk_mbuf_alloc(io_handle_s *io)
{
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(io->mbuf_pool);
    if(!mbuf) {
        io->stats.no_buffer++;
        return false;
    }
    if(rte_pktmbuf_append(mbuf, 2048) == NULL) {
        rte_pktmbuf_free(mbuf);
        io->stats.no_buffer++;
        return false;
    }
    mbuf->data_len = 0;
    mbuf->next = NULL;
    
    io->mbuf = mbuf;
    io->buf = rte_pktmbuf_mtod(mbuf, uint8_t *);
    io->buf_len = 0;
    return true;
}

/*
 * This job is for DPDK TX in main thread!
 */
void
io_dpdk_tx_job(timer_s *timer)
{
    io_handle_s *io = timer->data;
    bbl_interface_s *interface = io->interface;

    uint32_t stream_packets = 0;
    bool ctrl = true;
    bool pcap = false;

    assert(io->mode == IO_MODE_DPDK);
    assert(io->direction == IO_EGRESS);
    assert(io->thread == NULL);

    io_update_stream_token_bucket(io);

    /* Get TX timestamp */
    clock_gettime(CLOCK_MONOTONIC, &io->timestamp);
    while(true) {
        /* If sendto fails, the failed packet remains in TX buffer to be retried
         * in the next interval. */
        if(io->buf_len) {
            if(packet_is_bbl(io->buf, io->buf_len)) {
                /* Update timestamp if BBL traffic is retried. */
                *(uint32_t*)(io->buf + (io->buf_len - 8)) = io->timestamp.tv_sec;
                *(uint32_t*)(io->buf + (io->buf_len - 4)) = io->timestamp.tv_nsec;
            }
        } else {
            if(!io->mbuf) {
                if(!io_dpdk_mbuf_alloc(io)) {
                    break;
                }
            }
            if(ctrl) {
                /* First send all control traffic which has higher priority. */
                if(bbl_tx(interface, io->buf, &io->buf_len) != PROTOCOL_SUCCESS) {
                    io->buf_len = 0;
                    ctrl = false;
                    continue;
                }
            } else {
                /* Send traffic streams up to allowed burst. */
                if(++stream_packets > io->stream_burst) {
                    break;
                }
                if(bbl_stream_tx(io, io->buf, &io->buf_len) != PROTOCOL_SUCCESS) {
                    break;
                }
            }
        }
        io->mbuf->data_len = io->buf_len;
        /* Transmit the packet. */
        if(rte_eth_tx_burst(interface->portid, io->queue, &io->mbuf, 1) == 0) {
            /* This packet will be retried next interval 
             * because io->buf_len is not reset to zero. */
            if(pcap) {
                pcapng_fflush();
            }
            return;
        }
        /* Dump the packet into pcap file. */
        if(g_ctx->pcap.write_buf && (ctrl || g_ctx->pcap.include_streams)) {
            pcap = true;
            pcapng_push_packet_header(&io->timestamp, io->buf, io->buf_len,
                                      interface->pcap_index, PCAPNG_EPB_FLAGS_OUTBOUND);
        }
        io->stats.packets++;
        io->stats.bytes += io->buf_len;
        io->mbuf = NULL;
        io->buf = 0;
        io->buf_len = 0;
    }
    if(pcap) {
        pcapng_fflush();
    }
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
            sleep.tv_nsec = 10;
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
            rte_pktmbuf_free(packet);
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
    bbl_interface_s *interface = io->interface;

    bbl_txq_s *txq = thread->txq;
    bbl_txq_slot_t *slot;

    uint32_t stream_packets = 0;
    bool ctrl = true;

    assert(io->mode == IO_MODE_DPDK);
    assert(io->direction == IO_EGRESS);
    assert(io->thread);

    io_update_stream_token_bucket(io);

    while(true) {
        /* If sendto fails, the failed packet remains in TX buffer to be retried
         * in the next interval. */
        if(io->buf_len) {
            if(packet_is_bbl(io->buf, io->buf_len)) {
                /* Update timestamp if BBL traffic is retried. */
                *(uint32_t*)(io->buf + (io->buf_len - 8)) = io->timestamp.tv_sec;
                *(uint32_t*)(io->buf + (io->buf_len - 4)) = io->timestamp.tv_nsec;
            }
        } else {
            if(!io->mbuf) {
                if(!io_dpdk_mbuf_alloc(io)) {
                    break;
                }
            }
            if(ctrl) {
                /* First send all control traffic which has higher priority. */
                slot = bbl_txq_read_slot(txq);
                if(slot) {
                    io->buf_len = slot->packet_len;
                    memcpy(io->buf, slot->packet, slot->packet_len);
                    bbl_txq_read_next(txq);
                } else {
                    ctrl = false;
                    continue;
                }
            } else {
                /* Send traffic streams up to allowed burst. */
                if(++stream_packets > io->stream_burst) {
                    break;
                }
                if(bbl_stream_tx(io, io->buf, &io->buf_len) != PROTOCOL_SUCCESS) {
                    break;
                }
            }
        }
        io->mbuf->data_len = io->buf_len;
        /* Transmit the packet. */
        if(rte_eth_tx_burst(interface->portid, io->queue, &io->mbuf, 1) == 0) {
            /* This packet will be retried next interval 
             * because io->buf_len is not reset to zero. */
            return;
        }
        io->stats.packets++;
        io->stats.bytes += io->buf_len;
        io->mbuf = NULL;
        io->buf = 0;
        io->buf_len = 0;
    }
}

bool
io_dpdk_add_mbuf_pool(io_handle_s *io)
{
    struct rte_mempool *mbuf_pool;
    char buf[16] = {0};
    char *name;
    static uint16_t id = 0;

    snprintf(buf, sizeof(buf), "MBUF_POOL_%u", ++id);
    name = strdup(buf);
    if(!name) return false; /* very unlikely... */

    mbuf_pool = rte_pktmbuf_pool_create(name,
            NUM_MBUFS, MBUF_CACHE_SIZE, 0,
            RTE_MBUF_DEFAULT_BUF_SIZE, 
            rte_eth_dev_socket_id(io->interface->portid));
    if(!mbuf_pool) {
        free(name);
        return false;
    }
    io->mbuf_pool = mbuf_pool;
    return true;
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

    local_port_conf.rxmode.mq_mode = RTE_ETH_MQ_RX_RSS;
    local_port_conf.rx_adv_conf.rss_conf.rss_hf =
        (RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP) &
        dev_info.flow_type_rss_offloads;

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
        if(!io_dpdk_add_mbuf_pool(io)) {
            LOG(ERROR, "DPDK: failed to create RX mbuf pool for interface %s queue %u\n",
                interface->name, queue);
            return false;
        }

        rx_conf = dev_info.default_rxconf;
        rx_conf.offloads = local_port_conf.rxmode.offloads;
        ret = rte_eth_rx_queue_setup(portid, queue, config->io_slots_rx,
                                     rte_eth_dev_socket_id(portid), 
                                     &rx_conf, io->mbuf_pool);
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
            io->thread->set_cpu_affinity = true;
        } else {
            timer_add_periodic(&g_ctx->timer_root, &interface->io.tx_job, "TX", 0, 
                config->tx_interval, io, &io_dpdk_tx_job);
            interface->io.tx_job->reset = false;
        }
        io->queue = queue;
        if(!io_dpdk_add_mbuf_pool(io)) {
            LOG(ERROR, "DPDK: failed to create TX mbuf pool for interface %s queue %u\n",
                interface->name, queue);
            return false;
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