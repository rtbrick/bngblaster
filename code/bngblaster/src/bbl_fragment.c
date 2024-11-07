/*
 * BNG Blaster (BBL) - IP Fragmentation
 *
 * Christian Giese, October 2024
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

static void
bbl_fragment_free(bbl_fragment_s *ipv4_fragment)
{
    if(ipv4_fragment->next) {
        ipv4_fragment->next->prev = ipv4_fragment->prev;
    }
    if(ipv4_fragment->prev) {
        ipv4_fragment->prev->next = ipv4_fragment->next;
    } else {
        g_ctx->ipv4_fragments = ipv4_fragment->next;
    }
    free(ipv4_fragment);
}

/**
 * bbl_fragment_rx
 * 
 * This function stores incoming IPv4 fragments in fragmentation buffers, 
 * which are organized as a doubly-linked list. A cleanup job periodically 
 * removes outdated buffers. Once all fragments of a single packet have been received, 
 * the packet is reassembled and processed. 
 * 
 * Currently, this function supports BBL stream traffic only!
 * 
 * @param access_interface pointer to access interface on which packet was received
 * @param network_interface pointer to network interface on which packet was received
 * @param eth pointer to ethernet header structure of received packet
 * @param ipv4 pointer to IPv4 header structure of received packet
 */
void 
bbl_fragment_rx(bbl_access_interface_s *access_interface,
                bbl_network_interface_s *network_interface,
                bbl_ethernet_header_s *eth, bbl_ipv4_s *ipv4)
{
    if(!g_ctx->config.traffic_reassemble_fragments) return;

    bbl_fragment_s *fragment = g_ctx->ipv4_fragments;
    bbl_stream_s *stream = NULL;

    uint8_t  *bbl_start;
    bbl_bbl_s bbl;

    uint16_t offset;

    while(fragment) {
        if(fragment->id == ipv4->id && 
           fragment->src == ipv4->src && 
           fragment->dst == ipv4->dst) {
            break;
        }
        fragment = fragment->next;
    }
    if(!fragment) {
        fragment = calloc(1, sizeof(bbl_fragment_s));
        fragment->id = ipv4->id;
        fragment->src = ipv4->src;
        fragment->dst = ipv4->dst;
        if(g_ctx->ipv4_fragments) {
            g_ctx->ipv4_fragments->prev = fragment;
            fragment->next = g_ctx->ipv4_fragments;
        }
        g_ctx->ipv4_fragments = fragment;
    }

    offset = (ipv4->offset & 0x1FFF) * 8;
    if(offset+ipv4->payload_len > sizeof(fragment->buf)) {
        LOG(INFO, "IPv4 fragmented packet to big (%u)\n", (offset+ipv4->payload_len));
        bbl_fragment_free(fragment);
        return;
    }

    if(eth->length > fragment->max_length) {
        fragment->max_length = eth->length;
    }
    if(offset > fragment->max_offset) {
        fragment->max_offset = offset;
    }

    fragment->fragments++;
    fragment->timestamp = eth->timestamp.tv_sec;

    memcpy(fragment->buf+offset, ipv4->payload, ipv4->payload_len);
    fragment->recived += ipv4->payload_len;

    if(!(ipv4->offset & IPV4_MF)) {
        /* Last fragment recieved. */
        fragment->expected = offset + ipv4->payload_len;
    }
    if(fragment->recived == fragment->expected) {
        /* All fragments received. */
        if(packet_is_bbl(fragment->buf, fragment->recived)) {
            /* Currently, we support only the reassembly of BBL stream packets. */
            bbl_start = fragment->buf + (fragment->recived-BBL_HEADER_LEN);
            bbl.type = *(bbl_start+8);
            bbl.sub_type = *(bbl_start+9);
            bbl.direction = *(bbl_start+10);
            bbl.tos = *(bbl_start+11);
            bbl.session_id = *(uint32_t*)(bbl_start+12);
            if(bbl.type == BBL_TYPE_UNICAST) {
                bbl.ifindex = *(uint32_t*)(bbl_start+16);
                bbl.outer_vlan_id = *(uint16_t*)(bbl_start+20);
                bbl.inner_vlan_id = *(uint16_t*)(bbl_start+22);
                bbl.mc_source = 0;
                bbl.mc_source = 0;
            } else {
                bbl.mc_source = *(uint32_t*)(bbl_start+16);
                bbl.mc_source = *(uint32_t*)(bbl_start+20);
                bbl.ifindex = 0;
                bbl.outer_vlan_id = 0;
                bbl.inner_vlan_id = 0;
            }
            bbl.flow_id = *(uint64_t*)(bbl_start+24);
            bbl.flow_seq = *(uint64_t*)(bbl_start+32);
            bbl.timestamp.tv_sec = *(uint32_t*)(bbl_start+40);
            bbl.timestamp.tv_nsec = *(uint32_t*)(bbl_start+44);

            eth->bbl = &bbl;
            eth->length = fragment->max_length;

            if(access_interface) {
                stream = bbl_stream_rx(eth, NULL);
                if(stream && stream->rx_access_interface == NULL) {
                    stream->rx_access_interface = access_interface;
                }
            } else if (network_interface) {
                stream = bbl_stream_rx(eth, network_interface->mac);
                if(stream && stream->rx_network_interface != network_interface) {
                    if(stream->rx_network_interface) {
                        /* RX interface has changed! */
                        stream->rx_interface_changes++;
                        stream->rx_interface_changed_epoch = eth->timestamp.tv_sec;
                    }
                    stream->rx_network_interface = network_interface;
                }
            }
            if(stream) {
                if(fragment->fragments > stream->rx_fragments) {
                    stream->rx_fragments = fragment->fragments;
                }
                if(fragment->max_offset > stream->rx_fragment_offset) {
                    stream->rx_fragment_offset = fragment->max_offset;
                }
            }
        }
        bbl_fragment_free(fragment);
    }
}

void
bbl_fragment_cleanup_job(timer_s *timer)
{
    bbl_fragment_s *fragment = g_ctx->ipv4_fragments;
    bbl_fragment_s *next = fragment;

    /* Delete all fragments older than 10 seconds. */
    uint32_t timestamp = timer->timestamp->tv_sec - 10;
    while(next) {
        fragment = next;
        next = fragment->next;
        if(fragment->timestamp < timestamp) {
            bbl_fragment_free(fragment);
        } 
    }
}

void
bbl_fragment_init()
{
    if(!g_ctx->config.traffic_reassemble_fragments) return;

    timer_add_periodic(&g_ctx->timer_root, &g_ctx->fragmentation_timer, 
                       "FRAGMENT", 3, 0, NULL,
                       &bbl_fragment_cleanup_job);
}