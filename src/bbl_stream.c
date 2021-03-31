/*
 * BNG Blaster (BBL) - Streams
 *
 * Christian Giese, March 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#include "bbl.h"
#include "bbl_stream.h"
#include "bbl_stats.h"
#include "bbl_io_packet_mmap.h"
#include "bbl_io_raw.h"
#ifdef BNGBLASTER_NETMAP
    #include "bbl_io_netmap.h"
#endif


bool
bbl_stream_can_send(bbl_stream *stream) {
    bbl_session_s *session = stream->session;

    if(session->session_state == BBL_ESTABLISHED) {
        if(session->access_type == ACCESS_TYPE_PPPOE) {
            if(session->l2tp && session->l2tp_session == NULL) {
                goto Free;
            }
            switch (stream->config->type) {
                case STREAM_IPV4:
                    if(session->ipcp_state == BBL_PPP_OPENED) {
                        return true;
                    }
                    break;
                case STREAM_IPV6:
                    if(session->ip6cp_state == BBL_PPP_OPENED && session->icmpv6_ra_received) {
                        return true;
                    }
                    break;
                case STREAM_IPV6PD:
                    if(session->ip6cp_state == BBL_PPP_OPENED && session->dhcpv6_received) {
                        return true;
                    }
                    break;
                default:
                    break;
            }
        }
    }
Free:
    /* Free of packet if not ready to send */
    if(stream->buf) {
        free(stream->buf);
        stream->buf = NULL;
        stream->tx_len = 0;
    }
    return false;
}

bool
bbl_stream_build_access_pppoe_packet(bbl_stream *stream) {
    
    bbl_ctx_s *ctx = stream->interface->ctx;
    bbl_session_s *session = stream->session;
    bbl_stream_config *config = stream->config;

    uint16_t buf_len;

    bbl_ethernet_header_t eth = {0};
    bbl_pppoe_session_t pppoe = {0};
    bbl_ipv4_t ipv4 = {0};
    bbl_ipv6_t ipv6 = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_outer_priority = config->vlan_priority;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_inner_priority = config->vlan_priority;
    eth.vlan_three = session->access_third_vlan;
    eth.type = ETH_TYPE_PPPOE_SESSION;
    eth.next = &pppoe;
    pppoe.session_id = session->pppoe_session_id;   
    udp.src = BBL_UDP_PORT;
    udp.dst = BBL_UDP_PORT;
    udp.protocol = UDP_PROTOCOL_BBL;
    udp.next = &bbl;
    bbl.type = BBL_TYPE_UNICAST_SESSION;
    bbl.session_id = session->session_id;
    bbl.ifindex = session->interface->ifindex;
    bbl.outer_vlan_id = session->vlan_key.outer_vlan_id;
    bbl.inner_vlan_id = session->vlan_key.inner_vlan_id;
    bbl.flow_id = stream->flow_id;
    bbl.direction = BBL_DIRECTION_UP;

    switch (stream->config->type) {
        case STREAM_IPV4:
            pppoe.protocol = PROTOCOL_IPV4;
            pppoe.next = &ipv4;
            ipv4.dst = ctx->op.network_if->ip;
            ipv4.src = session->ip_address;
            ipv4.ttl = 64;
            ipv4.tos = config->priority;
            ipv4.protocol = PROTOCOL_IPV4_UDP;
            ipv4.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV4;
            if (config->length > 76) {
                bbl.padding = config->length - 76;
            }
            break;
        case STREAM_IPV6:
            pppoe.protocol = PROTOCOL_IPV6;
            pppoe.next = &ipv6;
            ipv6.dst = ctx->op.network_if->ip6.address;
            ipv6.src = session->ipv6_address;
            ipv6.ttl = 64;
            ipv4.tos = config->priority;
            ipv6.protocol = IPV6_NEXT_HEADER_UDP;
            ipv6.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV6;
            if (config->length > 96) {
                bbl.padding = config->length - 96;
            }
            break;
        case STREAM_IPV6PD:
            pppoe.protocol = PROTOCOL_IPV6;
            pppoe.next = &ipv6;
            ipv6.dst = ctx->op.network_if->ip6.address;
            ipv6.src = session->delegated_ipv6_address;
            ipv6.ttl = 64;
            ipv4.tos = config->priority;
            ipv6.protocol = IPV6_NEXT_HEADER_UDP;
            ipv6.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV6;
            if (config->length > 96) {
                bbl.padding = config->length - 96;
            }
            break;
        default:
            return false;
    }

    buf_len = config->length + 64;
    if(buf_len < 256) buf_len = 256;
    stream->buf = malloc(buf_len);
    if(encode_ethernet(stream->buf, &stream->tx_len, &eth) != PROTOCOL_SUCCESS) {
        free(stream->buf);
        stream->buf = NULL;
        stream->tx_len = 0;
        return false;
    }
    return true;
}

bool
bbl_stream_build_access_ipoe_packet(bbl_stream *stream) {
    
    bbl_ctx_s *ctx = stream->interface->ctx;
    bbl_session_s *session = stream->session;
    bbl_stream_config *config = stream->config;

    uint16_t buf_len;

    bbl_ethernet_header_t eth = {0};
    bbl_ipv4_t ipv4 = {0};
    bbl_ipv6_t ipv6 = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_outer_priority = config->vlan_priority;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_inner_priority = config->vlan_priority;
    eth.vlan_three = session->access_third_vlan;

    udp.src = BBL_UDP_PORT;
    udp.dst = BBL_UDP_PORT;
    udp.protocol = UDP_PROTOCOL_BBL;
    udp.next = &bbl;
    bbl.type = BBL_TYPE_UNICAST_SESSION;
    bbl.session_id = session->session_id;
    bbl.ifindex = session->interface->ifindex;
    bbl.outer_vlan_id = session->vlan_key.outer_vlan_id;
    bbl.inner_vlan_id = session->vlan_key.inner_vlan_id;
    bbl.flow_id = stream->flow_id;
    bbl.direction = BBL_DIRECTION_UP;

    switch (stream->config->type) {
        case STREAM_IPV4:
            eth.type = ETH_TYPE_IPV4;
            eth.next = &ipv4;
            ipv4.dst = ctx->op.network_if->ip;
            ipv4.src = session->ip_address;
            ipv4.ttl = 64;
            ipv4.tos = config->priority;
            ipv4.protocol = PROTOCOL_IPV4_UDP;
            ipv4.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV4;
            if (config->length > 76) {
                bbl.padding = config->length - 76;
            }
            break;
        case STREAM_IPV6:
            eth.type = ETH_TYPE_IPV6;
            eth.next = &ipv6;
            ipv6.dst = ctx->op.network_if->ip6.address;
            ipv6.src = session->ipv6_address;
            ipv6.ttl = 64;
            ipv6.tos = config->priority;
            ipv6.protocol = IPV6_NEXT_HEADER_UDP;
            ipv6.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV6;
            if (config->length > 96) {
                bbl.padding = config->length - 96;
            }
            break;
        case STREAM_IPV6PD:
            eth.type = ETH_TYPE_IPV6;
            eth.next = &ipv6;
            ipv6.dst = ctx->op.network_if->ip6.address;
            ipv6.src = session->delegated_ipv6_address;
            ipv6.ttl = 64;
            ipv6.tos = config->priority;
            ipv6.protocol = IPV6_NEXT_HEADER_UDP;
            ipv6.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV6;
            if (config->length > 96) {
                bbl.padding = config->length - 96;
            }
            break;
        default:
            return false;
    }

    buf_len = config->length + 64;
    if(buf_len < 256) buf_len = 256;
    stream->buf = malloc(buf_len);
    if(encode_ethernet(stream->buf, &stream->tx_len, &eth) != PROTOCOL_SUCCESS) {
        free(stream->buf);
        stream->buf = NULL;
        stream->tx_len = 0;
        return false;
    }
    return true;
}

bool
bbl_stream_build_network_packet(bbl_stream *stream) {

    bbl_ctx_s *ctx = stream->interface->ctx;
    bbl_session_s *session = stream->session;
    bbl_stream_config *config = stream->config;

    uint16_t buf_len;

    bbl_ethernet_header_t eth = {0};
    bbl_ipv4_t ipv4 = {0};
    bbl_ipv6_t ipv6 = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};

    eth.dst = ctx->op.network_if->gateway_mac;
    eth.src = ctx->op.network_if->mac;
    eth.vlan_outer = ctx->config.network_vlan;
    eth.vlan_outer_priority = config->vlan_priority;
    eth.vlan_inner = 0;
    
    udp.src = BBL_UDP_PORT;
    udp.dst = BBL_UDP_PORT;
    udp.protocol = UDP_PROTOCOL_BBL;
    udp.next = &bbl;
    bbl.type = BBL_TYPE_UNICAST_SESSION;
    bbl.session_id = session->session_id;
    bbl.ifindex = session->interface->ifindex;
    bbl.outer_vlan_id = session->vlan_key.outer_vlan_id;
    bbl.inner_vlan_id = session->vlan_key.inner_vlan_id;
    bbl.flow_id = stream->flow_id;
    bbl.direction = BBL_DIRECTION_DOWN;

    switch (stream->config->type) {
        case STREAM_IPV4:
            eth.type = ETH_TYPE_IPV4;
            eth.next = &ipv4;
            ipv4.dst = session->ip_address;
            if(stream->config->ipv4_source_address) {
                ipv4.src = stream->config->ipv4_source_address;
            } else {
                ipv4.src = ctx->op.network_if->ip;
            }
            ipv4.ttl = 64;
            ipv4.tos = config->priority;
            ipv4.protocol = PROTOCOL_IPV4_UDP;
            ipv4.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV4;
            if (config->length > 76) {
                bbl.padding = config->length - 76;
            }
            break;
        case STREAM_IPV6:
            eth.type = ETH_TYPE_IPV6;
            eth.next = &ipv6;
            ipv6.dst = session->ipv6_address;
            if(*(uint64_t*)stream->config->ipv6_source_address) {
                ipv6.src = stream->config->ipv6_source_address;
            } else {
                ipv6.src = ctx->op.network_if->ip6.address;
            }
            ipv6.ttl = 64;
            ipv6.tos = config->priority;
            ipv6.protocol = IPV6_NEXT_HEADER_UDP;
            ipv6.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV6;
            if (config->length > 96) {
                bbl.padding = config->length - 96;
            }
            break;
        case STREAM_IPV6PD:
            eth.type = ETH_TYPE_IPV6;
            eth.next = &ipv6;
            ipv6.dst = session->delegated_ipv6_address;
            if(*(uint64_t*)stream->config->ipv6_source_address) {
                ipv6.src = stream->config->ipv6_source_address;
            } else {
                ipv6.src = ctx->op.network_if->ip6.address;
            }
            ipv6.ttl = 64;
            ipv6.tos = config->priority;
            ipv6.protocol = IPV6_NEXT_HEADER_UDP;
            ipv6.next = &udp;
            bbl.sub_type = BBL_SUB_TYPE_IPV6;
            if (config->length > 96) {
                bbl.padding = config->length - 96;
            }
            break;
        default:
            return false;
    }

    buf_len = config->length + 64;
    if(buf_len < 256) buf_len = 256;
    stream->buf = malloc(buf_len);
    if(encode_ethernet(stream->buf, &stream->tx_len, &eth) != PROTOCOL_SUCCESS) {
        free(stream->buf);
        stream->buf = NULL;
        stream->tx_len = 0;
        return false;
    }
    return true;
}

bool
bbl_stream_build_l2tp_packet(bbl_stream *stream) {

    bbl_ctx_s *ctx = stream->interface->ctx;
    bbl_session_s *session = stream->session;
    bbl_stream_config *config = stream->config;

    bbl_l2tp_session_t *l2tp_session = stream->session->l2tp_session;
    bbl_l2tp_tunnel_t *l2tp_tunnel = l2tp_session->tunnel;

    uint16_t buf_len;

    bbl_ethernet_header_t eth = {0};
    bbl_ipv4_t l2tp_ipv4 = {0};
    bbl_udp_t l2tp_udp = {0};
    bbl_l2tp_t l2tp = {0};
    bbl_ipv4_t ipv4 = {0};
    bbl_udp_t udp = {0};
    bbl_bbl_t bbl = {0};

    eth.dst = ctx->op.network_if->gateway_mac;
    eth.src = ctx->op.network_if->mac;
    eth.vlan_outer = ctx->config.network_vlan;
    eth.vlan_inner = 0;
    eth.type = ETH_TYPE_IPV4;
    eth.next = &l2tp_ipv4;
    l2tp_ipv4.dst = l2tp_tunnel->peer_ip;
    l2tp_ipv4.src = l2tp_tunnel->server->ip;
    l2tp_ipv4.ttl = 64;
    l2tp_ipv4.tos = config->priority;
    l2tp_ipv4.protocol = PROTOCOL_IPV4_UDP;
    l2tp_ipv4.next = &l2tp_udp;
    l2tp_udp.src = L2TP_UDP_PORT;
    l2tp_udp.dst = L2TP_UDP_PORT;
    l2tp_udp.protocol = UDP_PROTOCOL_L2TP;
    l2tp_udp.next = &l2tp;
    l2tp.type = L2TP_MESSAGE_DATA;
    l2tp.tunnel_id = l2tp_tunnel->peer_tunnel_id;
    l2tp.session_id = l2tp_session->peer_session_id;
    l2tp.protocol = PROTOCOL_IPV4;
    l2tp.with_length = l2tp_tunnel->server->data_lenght;
    l2tp.with_offset = l2tp_tunnel->server->data_offset;
    l2tp.next = &ipv4;
    ipv4.dst = session->ip_address;
    ipv4.src = l2tp_tunnel->server->ip;
    ipv4.ttl = 64;
    ipv4.tos = config->priority;
    ipv4.protocol = PROTOCOL_IPV4_UDP;
    ipv4.next = &udp; 
    udp.src = BBL_UDP_PORT;
    udp.dst = BBL_UDP_PORT;
    udp.protocol = UDP_PROTOCOL_BBL;
    udp.next = &bbl;
    bbl.type = BBL_TYPE_UNICAST_SESSION;
    bbl.session_id = session->session_id;
    bbl.ifindex = session->interface->ifindex;
    bbl.outer_vlan_id = session->vlan_key.outer_vlan_id;
    bbl.inner_vlan_id = session->vlan_key.inner_vlan_id;
    bbl.flow_id = stream->flow_id;
    bbl.direction = BBL_DIRECTION_DOWN;
    bbl.sub_type = BBL_SUB_TYPE_IPV4;
    if (config->length > 76) {
        bbl.padding = config->length - 76;
    }

    buf_len = config->length + 128;
    if(buf_len < 256) buf_len = 256;
    stream->buf = malloc(buf_len);
    if(encode_ethernet(stream->buf, &stream->tx_len, &eth) != PROTOCOL_SUCCESS) {
        free(stream->buf);
        stream->buf = NULL;
        stream->tx_len = 0;
        return false;
    }
    return true;
}

bool
bbl_stream_build_packet(bbl_stream *stream) {

    if(stream->session->access_type == ACCESS_TYPE_PPPOE) {
        if(stream->session->l2tp_session) {
            if(stream->direction == STREAM_DIRECTION_UP) {
                return bbl_stream_build_access_pppoe_packet(stream);
            } else {
                return bbl_stream_build_l2tp_packet(stream);
            }
        } else {
            switch (stream->config->type) {
                case STREAM_IPV4:
                case STREAM_IPV6:
                case STREAM_IPV6PD:
                    if(stream->direction == STREAM_DIRECTION_UP) {
                        return bbl_stream_build_access_pppoe_packet(stream);
                    } else {
                        return bbl_stream_build_network_packet(stream);
                    }
                    break;                    
                default:
                    break;
            }
        }        
    } else if (stream->session->access_type == ACCESS_TYPE_IPOE) {
        if(stream->direction == STREAM_DIRECTION_UP) {
            return bbl_stream_build_access_ipoe_packet(stream);
        } else {
            return bbl_stream_build_network_packet(stream);
        }
    }
    return false;
}

void
bbl_stream_tx_job (timer_s *timer) {

    bbl_stream *stream = timer->data;
    bbl_session_s *session = stream->session;
    bbl_interface_s *interface = stream->interface;

    struct timespec send_windwow;
    struct timespec now;

    double d;
    uint64_t packets = 1;
    uint64_t packets_expected;

    if(!bbl_stream_can_send(stream)) {
        stream->send_window_packets = 0;
        return;
    }
    if(!stream->buf) {
        if(!bbl_stream_build_packet(stream)) {
            LOG(ERROR, "Failed to build packet for stream %s session-id %u\n", 
                stream->config->name, session->session_id);
            return;
        }
    }

    if(!session->stream_traffic) {
        /* Close send window */
        stream->send_window_packets = 0;
        return;
    }

    clock_gettime(CLOCK_MONOTONIC, &now);
    if(stream->send_window_packets == 0) {
        /* Open new send window */
        stream->send_window_start.tv_sec = now.tv_sec;
        stream->send_window_start.tv_nsec = now.tv_nsec;
    } else {
        timespec_sub(&send_windwow, &now, &stream->send_window_start);
        packets_expected = send_windwow.tv_sec * stream->config->pps;
        d = (send_windwow.tv_nsec / 1000000000.0);
        packets_expected += d * stream->config->pps;

        if(packets_expected > stream->send_window_packets) {
            packets = packets_expected - stream->send_window_packets;
        }
        if(packets > 32) {
            packets = 32;
        }
    }

    /* Update BBL header fields */
    clock_gettime(CLOCK_REALTIME, &interface->tx_timestamp);
    *(uint32_t*)(stream->buf + (stream->tx_len - 8)) = interface->tx_timestamp.tv_sec;
    *(uint32_t*)(stream->buf + (stream->tx_len - 4)) = interface->tx_timestamp.tv_nsec;
    while(packets) {
        *(uint64_t*)(stream->buf + (stream->tx_len - 16)) = stream->flow_seq;
        /* Send packet ... */
        switch (interface->io_mode) {
            case IO_MODE_PACKET_MMAP:
                if(!bbl_io_packet_mmap_send(interface, stream->buf, stream->tx_len)) {
                    return;
                }
                break;
            case IO_MODE_PACKET_MMAP_RAW:
                if(!bbl_io_packet_mmap_raw_send(interface, stream->buf, stream->tx_len)) {
                    return;
                }
                break;
            case IO_MODE_RAW:
                if(!bbl_io_raw_send(interface, stream->buf, stream->tx_len)) {
                    return;
                }
                break;
    #ifdef BNGBLASTER_NETMAP
            case IO_MODE_NETMAP:
                if(!bbl_io_netmap_send(interface, stream->buf, stream->tx_len)) {
                    return;
                }
                break;
    #endif
            default:
                return;
        }
        stream->send_window_packets++;
        stream->packets_tx++;
        stream->flow_seq++;
        packets--;
        if(stream->session && stream->direction == STREAM_DIRECTION_UP) {
            stream->session->stats.packets_tx++;
            stream->session->stats.bytes_tx += stream->tx_len;
        }
    }
}

void
bbl_stream_rate_job (timer_s *timer) {
    bbl_stream *stream = timer->data;
    bbl_compute_avg_rate(&stream->rate_packets_tx, stream->packets_tx);
    bbl_compute_avg_rate(&stream->rate_packets_rx, stream->packets_rx);
}

bool
bbl_stream_add(bbl_ctx_s *ctx, bbl_access_config_s *access_config, bbl_session_s *session) {

    bbl_stream_config *config;
    bbl_stream *stream;
    bbl_stream *session_stream;

    dict_insert_result result;

    time_t timer_sec = 0;
    long timer_nsec  = 0;

    config = ctx->config.stream_config;

    while(config) {
        if(config->stream_group_id == access_config->stream_group_id) {

            if(!ctx->op.network_if) {
                LOG(ERROR, "Failed to add stream because of missing network interface\n"); 
                return false;
            }

            if(config->pps == 1) {
                timer_sec = 1;
            } else {
                timer_nsec = 1000000000 / config->pps;
            }

            if(config->direction & STREAM_DIRECTION_UP) {
                stream = calloc(1, sizeof(bbl_stream));
                stream->flow_id = ctx->flow_id++;
                stream->flow_seq = 1;
                stream->config = config;
                stream->direction = STREAM_DIRECTION_UP;
                stream->interface = session->interface;
                stream->session = session;
                stream->tx_interval = timer_sec * 1e9 + timer_nsec;
                result = dict_insert(ctx->stream_flow_dict, &stream->flow_id);
                if (!result.inserted) {
                    LOG(ERROR, "Failed to insert stream %s\n", config->name); 
                    free(stream);
                    return false;
                }
                *result.datum_ptr = stream;
                if(session->stream) {
                    session_stream = session->stream;
                    while(session_stream->next) {
                        session_stream = session_stream->next;
                    }
                    session_stream->next = stream;
                } else {
                    session->stream = stream;
                }
                timer_add_periodic(&ctx->timer_root, &stream->timer, config->name, timer_sec, timer_nsec, stream, bbl_stream_tx_job);
                timer_add_periodic(&ctx->timer_root, &stream->timer_rate, "Rate Computation", 1, 0, stream, bbl_stream_rate_job);
                LOG(DEBUG, "Traffic stream %s added in upstream with timer %lu sec %lu nsec\n", config->name, timer_sec, timer_nsec); 
            }
            if(config->direction & STREAM_DIRECTION_DOWN) {
                stream = calloc(1, sizeof(bbl_stream));
                stream->flow_id = ctx->flow_id++;
                stream->flow_seq = 1;
                stream->config = config;
                stream->direction = STREAM_DIRECTION_DOWN;
                stream->interface = ctx->op.network_if;
                stream->session = session;
                stream->tx_interval = timer_sec * 1e9 + timer_nsec;
                result = dict_insert(ctx->stream_flow_dict, &stream->flow_id);
                if (!result.inserted) {
                    LOG(ERROR, "Failed to insert stream %s\n", config->name); 
                    free(stream);
                    return false;
                }
                *result.datum_ptr = stream;
                if(session->stream) {
                    session_stream = session->stream;
                    while(session_stream->next) {
                        session_stream = session_stream->next;
                    }
                    session_stream->next = stream;
                } else {
                    session->stream = stream;
                }
                timer_add_periodic(&ctx->timer_root, &stream->timer, config->name, timer_sec, timer_nsec, stream, bbl_stream_tx_job);
                timer_add_periodic(&ctx->timer_root, &stream->timer_rate, "Rate Computation", 1, 0, stream, bbl_stream_rate_job);
                LOG(DEBUG, "Traffic stream %s added in downstream with timer %lu sec %lu nsec\n", config->name, timer_sec, timer_nsec); 
            }
            timer_smear_bucket(&ctx->timer_root, timer_sec, timer_nsec);
        }
        config = config->next;
    }

    return true;
}
