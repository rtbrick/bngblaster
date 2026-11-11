/*
 * BNG Blaster (BBL) - IP Fragmentation
 *
 * Christian Giese, October 2024
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

static uint32_t
bbl_fragment_hash(bbl_ipv4_s *ipv4)
{
    return (ipv4->src ^ ipv4->dst ^ (ipv4->id * 2654435761U) ^ ipv4->protocol) % BBL_FRAGMENT_HASH_SIZE;
}

static void
bbl_fragment_free(bbl_fragment_s *ipv4_fragment)
{
    if(ipv4_fragment->next) {
        ipv4_fragment->next->prev = ipv4_fragment->prev;
    } else {
        g_ctx->ipv4_fragments_tail = ipv4_fragment->prev;
    }
    if(ipv4_fragment->prev) {
        ipv4_fragment->prev->next = ipv4_fragment->next;
    } else {
        g_ctx->ipv4_fragments = ipv4_fragment->next;
    }
    if(ipv4_fragment->hash_next) {
        ipv4_fragment->hash_next->hash_prev = ipv4_fragment->hash_prev;
    }
    if(ipv4_fragment->hash_prev) {
        ipv4_fragment->hash_prev->hash_next = ipv4_fragment->hash_next;
    } else {
        g_ctx->ipv4_fragment_hash[(ipv4_fragment->src ^ ipv4_fragment->dst ^
                                   (ipv4_fragment->id * 2654435761U) ^ ipv4_fragment->protocol) %
                                  BBL_FRAGMENT_HASH_SIZE] = ipv4_fragment->hash_next;
    }
    g_ctx->ipv4_fragment_count--;
    free(ipv4_fragment);
}

/* Mark the 8 byte blocks of a fragment as received and
 * return the number of new blocks (duplicates and overlaps
 * are not counted, RFC 791 reassembly by fragment offset). */
static uint16_t
bbl_fragment_blocks(bbl_fragment_s *fragment, uint16_t offset, uint16_t length)
{
    uint16_t block = offset / 8;
    uint16_t last = (offset + length + 7) / 8;
    uint16_t added = 0;
    uint64_t bit;

    while(block < last && block < BBL_FRAGMENT_BLOCKS) {
        bit = 1ULL << (block % 64);
        if(!(fragment->blocks[block / 64] & bit)) {
            fragment->blocks[block / 64] |= bit;
            added++;
        }
        block++;
    }
    return added;
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
 * @param session pointer to session (access interface only)
 * @param eth pointer to ethernet header structure of received packet (NULL for PPPoL2TP)
 * @param ipv4 pointer to IPv4 header structure of received packet
 */
void
bbl_fragment_rx(bbl_access_interface_s *access_interface,
                bbl_network_interface_s *network_interface,
                bbl_session_s *session,
                bbl_ethernet_header_s *eth, bbl_ipv4_s *ipv4)
{
    if(!g_ctx->config.traffic_reassemble_fragments) return;

    bbl_fragment_s *fragment = g_ctx->ipv4_fragments;
    bbl_stream_s *stream = NULL;

    uint8_t  *bbl_start;
    bbl_bbl_s bbl;
    bbl_ethernet_header_s eth_local;

    uint16_t offset;
    uint16_t length;
    time_t timestamp;

    uint32_t hash;

    if(!g_ctx->ipv4_fragment_hash) return;

    hash = bbl_fragment_hash(ipv4);
    fragment = g_ctx->ipv4_fragment_hash[hash];
    while(fragment) {
        if(fragment->id == ipv4->id &&
           fragment->src == ipv4->src &&
           fragment->dst == ipv4->dst &&
           fragment->protocol == ipv4->protocol) {
            break;
        }
        fragment = fragment->hash_next;
    }
    if(!fragment) {
        if(g_ctx->ipv4_fragment_count >= BBL_FRAGMENT_MAX) {
            /* Limit the memory by evicting the oldest entry, which is
             * likely incomplete because of loss (entries expire after
             * 10 seconds), instead of refusing all new packets. */
            if(!g_ctx->ipv4_fragments_evicted) {
                LOG(INFO, "IPv4 reassembly of more than %u packets, oldest are evicted\n",
                    BBL_FRAGMENT_MAX);
            }
            g_ctx->ipv4_fragments_evicted++;
            bbl_fragment_free(g_ctx->ipv4_fragments_tail);
        }
        fragment = calloc(1, sizeof(bbl_fragment_s));
        if(!fragment) {
            return;
        }
        fragment->id = ipv4->id;
        fragment->src = ipv4->src;
        fragment->dst = ipv4->dst;
        fragment->protocol = ipv4->protocol;
        if(g_ctx->ipv4_fragments) {
            g_ctx->ipv4_fragments->prev = fragment;
            fragment->next = g_ctx->ipv4_fragments;
        } else {
            g_ctx->ipv4_fragments_tail = fragment;
        }
        g_ctx->ipv4_fragments = fragment;
        if(g_ctx->ipv4_fragment_hash[hash]) {
            g_ctx->ipv4_fragment_hash[hash]->hash_prev = fragment;
            fragment->hash_next = g_ctx->ipv4_fragment_hash[hash];
        }
        g_ctx->ipv4_fragment_hash[hash] = fragment;
        g_ctx->ipv4_fragment_count++;
    }

    offset = (ipv4->offset & 0x1FFF) * 8;
    if(offset+ipv4->payload_len > sizeof(fragment->buf)) {
        LOG(INFO, "IPv4 fragmented packet to big (%u)\n", (offset+ipv4->payload_len));
        bbl_fragment_free(fragment);
        return;
    }

    if(eth) {
        length = eth->length;
        timestamp = eth->timestamp.tv_sec;
    } else {
        /* PPPoL2TP (LAC) traffic has no ethernet header. */
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        length = ipv4->len;
        timestamp = now.tv_sec;
    }

    if(length > fragment->max_length) {
        fragment->max_length = length;
    }
    if(offset > fragment->max_offset) {
        fragment->max_offset = offset;
    }

    fragment->fragments++;
    fragment->timestamp = timestamp;

    memcpy(fragment->buf+offset, ipv4->payload, ipv4->payload_len);
    fragment->received += bbl_fragment_blocks(fragment, offset, ipv4->payload_len);

    if(!(ipv4->offset & IPV4_MF)) {
        /* Last fragment received. */
        fragment->expected = offset + ipv4->payload_len;
    }
    if(fragment->expected && fragment->received == (fragment->expected + 7) / 8) {
        /* All fragments received. */
        if(packet_is_bbl(fragment->buf, fragment->expected)) {
            /* Currently, we support only the reassembly of BBL stream packets. */
            bbl_start = fragment->buf + (fragment->expected-BBL_HEADER_LEN);
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
                bbl.mc_group = 0;
            } else {
                bbl.mc_source = *(uint32_t*)(bbl_start+16);
                bbl.mc_group = *(uint32_t*)(bbl_start+20);
                bbl.ifindex = 0;
                bbl.outer_vlan_id = 0;
                bbl.inner_vlan_id = 0;
            }
            bbl.flow_id = *(uint32_t*)(bbl_start+24);
            bbl.flow_seq = *(uint64_t*)(bbl_start+32);
            bbl.timestamp.tv_sec = *(uint32_t*)(bbl_start+40);
            bbl.timestamp.tv_nsec = *(uint32_t*)(bbl_start+44);

            if(!eth && session) {
                /* PPPoL2TP (LAC) traffic has no ethernet header, the
                 * stream is verified with the reassembled IPv4 packet
                 * and the client MAC address of the session. */
                memset(&eth_local, 0x0, sizeof(eth_local));
                eth_local.dst = session->client_mac;
                eth_local.type = ETH_TYPE_IPV4;
                eth_local.next = ipv4;
                eth_local.tos = ipv4->tos;
                eth_local.ttl = ipv4->ttl;
                clock_gettime(CLOCK_MONOTONIC, &eth_local.timestamp);
                eth = &eth_local;
            }
            if(eth) {
                eth->bbl = &bbl;
                eth->length = fragment->max_length;
                if(access_interface) {
                    stream = bbl_stream_rx(eth, NULL);
                    if(stream) {
                        bbl_stream_rx_interface_set(stream, STREAM_FLAG_ACCESS, access_interface, timestamp);
                    }
                } else if(network_interface) {
                    stream = bbl_stream_rx(eth, network_interface->mac);
                    if(stream) {
                        bbl_stream_rx_interface_set(stream, STREAM_FLAG_NETWORK, network_interface, timestamp);
                    }
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

    g_ctx->ipv4_fragment_hash = calloc(BBL_FRAGMENT_HASH_SIZE, sizeof(bbl_fragment_s*));

    timer_add_periodic(&g_ctx->timer_root, &g_ctx->fragmentation_timer,
                       "FRAGMENT", 3, 0, NULL,
                       &bbl_fragment_cleanup_job);
}