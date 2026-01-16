/*
 * BNG Blaster (BBL) - Network Interface Functions
 *
 * Christian Giese, August 2022
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"
#include "bbl_protocols.h"
#include "bbl_session.h"
#include "bbl_stream.h"

void
bbl_network_interface_rate_job(timer_s *timer) {
    bbl_network_interface_s *interface = timer->data;
    bbl_compute_avg_rate(&interface->stats.rate_packets_tx, interface->stats.packets_tx);
    bbl_compute_avg_rate(&interface->stats.rate_packets_rx, interface->stats.packets_rx);
    bbl_compute_avg_rate(&interface->stats.rate_bytes_tx, interface->stats.bytes_tx);
    bbl_compute_avg_rate(&interface->stats.rate_bytes_rx, interface->stats.bytes_rx);
    bbl_compute_avg_rate(&interface->stats.rate_mc_tx, interface->stats.mc_tx);
    bbl_compute_avg_rate(&interface->stats.rate_li_rx, interface->stats.li_rx);
    bbl_compute_avg_rate(&interface->stats.rate_l2tp_data_rx, interface->stats.l2tp_data_rx);
    bbl_compute_avg_rate(&interface->stats.rate_l2tp_data_tx, interface->stats.l2tp_data_tx);
    bbl_compute_avg_rate(&interface->stats.rate_stream_tx, interface->stats.stream_tx);
    bbl_compute_avg_rate(&interface->stats.rate_stream_rx, interface->stats.stream_rx);
    bbl_compute_avg_rate(&interface->stats.rate_session_ipv4_tx, interface->stats.session_ipv4_tx);
    bbl_compute_avg_rate(&interface->stats.rate_session_ipv4_rx, interface->stats.session_ipv4_rx);
    bbl_compute_avg_rate(&interface->stats.rate_session_ipv6_tx, interface->stats.session_ipv6_tx);
    bbl_compute_avg_rate(&interface->stats.rate_session_ipv6_rx, interface->stats.session_ipv6_rx);
    bbl_compute_avg_rate(&interface->stats.rate_session_ipv6pd_tx, interface->stats.session_ipv6pd_tx);
    bbl_compute_avg_rate(&interface->stats.rate_session_ipv6pd_rx, interface->stats.session_ipv6pd_rx);
}

/**
 * bbl_network_interfaces_add
 */
bool
bbl_network_interfaces_add()
{
    bbl_network_config_s *network_config = g_ctx->config.network_config;
    bbl_network_interface_s *network_interface;
    bbl_a10nsp_interface_s *a10nsp;
    bbl_interface_s *interface;
    isis_instance_s *isis;
    ldp_instance_s *ldp;
    bool result;

    char ifname[SUB_STR_LEN];

    while(network_config) {
        /* Generate sub-interface name */
        if(network_config->vlan) {
            snprintf(ifname, sizeof(ifname), "%s:%u", 
                     network_config->interface, network_config->vlan);
        } else {
            snprintf(ifname, sizeof(ifname), "%s", 
                     network_config->interface);
        }

        interface = bbl_interface_get(network_config->interface);
        if(!interface) {
            LOG(ERROR, "Failed to add network interface %s (interface not found)\n", ifname);
            return false;
        }
        if(bbl_network_interface_get(ifname)) {
            LOG(ERROR, "Failed to add network interface %s (duplicate)\n", ifname);
            return false;
        }
        if(interface->access && network_config->vlan == 0) {
            LOG(ERROR, "Failed to add network interface %s (untagged not allowed on access interfaces)\n", ifname);
            return false;
        }

        network_interface = calloc(1, sizeof(bbl_network_interface_s));
        network_interface->next = interface->network;
        interface->network = network_interface;
        interface->network_vlan[network_config->vlan] = network_interface;
        network_config->network_interface = network_interface;

        CIRCLEQ_INSERT_TAIL(&g_ctx->network_interface_qhead, network_interface, network_interface_qnode);

        /* Init interface */
        network_interface->name = strdup(ifname);
        network_interface->interface = interface;
        network_interface->ifindex = interface->ifindex;
        network_interface->vlindex = interface->ifindex << 12;
        network_interface->vlindex |= network_config->vlan;

        /* Init TXQ */
        network_interface->txq = calloc(1, sizeof(bbl_txq_s));
        bbl_txq_init(network_interface->txq, BBL_TXQ_DEFAULT_SIZE);

        /* Init ethernet */
        network_interface->vlan = network_config->vlan;
        network_interface->mtu = network_config->mtu;

        if(*(uint32_t*)network_config->mac) {
            memcpy(network_interface->mac, network_config->mac, ETH_ADDR_LEN);
        } else {
            memcpy(network_interface->mac, interface->mac, ETH_ADDR_LEN);
        }        

        /* Copy gateway MAC from config (default 00:00:00:00:00:00) */
        memcpy(network_interface->gateway_mac, network_config->gateway_mac, ETH_ADDR_LEN);
        memcpy(network_interface->gateway6_mac, network_config->gateway_mac, ETH_ADDR_LEN);

        /* Init IPv4 */
        if(network_config->ip.address && network_config->gateway) {
            network_interface->ip.address = network_config->ip.address;
            network_interface->ip.len = network_config->ip.len;
            network_interface->gateway = network_config->gateway;
            network_interface->secondary_ip_addresses = network_config->secondary_ip_addresses;
            /* Send initial ARP request */
            network_interface->send_requests |= BBL_IF_SEND_ARP_REQUEST;
        }

        /* Init link-local IPv6 address */
        network_interface->ip6_ll[0]  = 0xfe;
        network_interface->ip6_ll[1]  = 0x80;
        network_interface->ip6_ll[8]  = network_interface->mac[0];
        network_interface->ip6_ll[9]  = network_interface->mac[1];
        network_interface->ip6_ll[10] = network_interface->mac[2];
        network_interface->ip6_ll[11] = 0xff;
        network_interface->ip6_ll[12] = 0xfe;
        network_interface->ip6_ll[13] = network_interface->mac[3];
        network_interface->ip6_ll[14] = network_interface->mac[4];
        network_interface->ip6_ll[15] = network_interface->mac[5];
        if(network_config->ipv6_ra) {
            network_interface->ipv6_ra = true;
            network_interface->send_requests |= BBL_IF_SEND_ICMPV6_RA;
        }

        /* Init IPv6 */
        if(ipv6_prefix_not_zero(&network_config->ip6) && 
           ipv6_addr_not_zero(&network_config->gateway6)) {
            /* Init global IPv6 address */
            memcpy(&network_interface->ip6, &network_config->ip6, sizeof(ipv6_prefix));
            memcpy(&network_interface->gateway6, &network_config->gateway6, sizeof(ipv6addr_t));
            memcpy(&network_interface->gateway6_solicited_node_multicast, &ipv6_solicited_node_multicast, sizeof(ipv6addr_t));
            memcpy(((uint8_t*)&network_interface->gateway6_solicited_node_multicast)+13,
                   ((uint8_t*)&network_interface->gateway6)+13, 3);

            network_interface->secondary_ip6_addresses = network_config->secondary_ip6_addresses;
            /* Send initial ICMPv6 NS */
            network_interface->send_requests |= BBL_IF_SEND_ICMPV6_NS;
        }

        network_interface->gateway_resolve_wait = network_config->gateway_resolve_wait;

        /* Init TCP */
        if(!bbl_tcp_network_interface_init(network_interface, network_config)) {
            LOG(ERROR, "Failed to init TCP for network interface %s\n", ifname);
            return false;
        }

        /* Init HTTP servers */
        if(!bbl_http_server_init(network_interface)) {
            LOG(ERROR, "Failed to init HTTP servers for network interface %s\n", ifname);
            return false;
        }

        /* Init ICMP clients */
        if(!bbl_icmp_client_network_interface_init(network_interface)) {
            LOG(ERROR, "Failed to init ICMP clients for network interface %s\n", ifname);
            return false;
        }

        /* Init routing protocols */ 
        if(network_config->isis_instance_id) {
            result = false;
            isis = g_ctx->isis_instances;
            while(isis) {
                if(isis->config->id == network_config->isis_instance_id) {
                    result = isis_adjacency_init(network_interface, network_config, isis);
                    if(!result) {
                        LOG(ERROR, "Failed to enable IS-IS for network interface %s (adjacency init failed)\n", ifname);
                        return false;
                    }
                    break;
                }
                isis = isis->next;
            }
            if(!result) {
                LOG(ERROR, "Failed to enable IS-IS for network interface %s (instance not found)\n", ifname);
                return false;
            }
        }
        if(network_config->ldp_instance_id) {
            result = false;
            ldp = g_ctx->ldp_instances;
            while(ldp) {
                if(ldp->config->id == network_config->ldp_instance_id) {
                    result = ldp_interface_init(network_interface, network_config, ldp);
                    if(!result) {
                        LOG(ERROR, "Failed to enable LDP for network interface %s (adjacency init failed)\n", ifname);
                        return false;
                    }
                    break;
                }
                ldp = ldp->next;
            }
            if(!result) {
                LOG(ERROR, "Failed to enable LDP for network interface %s (instance not found)\n", ifname);
                return false;
            }
        }

        if(!ospf_interface_init(network_interface, network_config, OSPF_VERSION_2)) {
            return false;
        }
        if(!ospf_interface_init(network_interface, network_config, OSPF_VERSION_3)) {
            return false;
        }

        /* Init CFM */
        if(network_config->cfm_cc) {
            network_interface->cfm = calloc(1, sizeof(bbl_cfm_session_s));
            network_interface->cfm->cfm_cc = true;
            if(network_config->cfm_seq) network_interface->cfm->cfm_seq = 1;
            network_interface->cfm->cfm_level = network_config->cfm_level;
            network_interface->cfm->cfm_interval = network_config->cfm_interval;
            network_interface->cfm->cfm_ma_id = network_config->cfm_ma_id;
            network_interface->cfm->cfm_md_name = network_config->cfm_md_name;
            network_interface->cfm->cfm_ma_name = network_config->cfm_ma_name;
            network_interface->cfm->vlan_priority = network_config->cfm_vlan_priority;
            network_interface->cfm->network_interface = network_interface;
            bbl_cfm_cc_start(network_interface->cfm);
        }

        /* Init A10NSP switch emulation */
        if(network_config->a10nsp) {
            a10nsp = calloc(1, sizeof(bbl_a10nsp_interface_s));
            network_interface->a10nsp = a10nsp;
            interface->a10nsp = a10nsp;

            a10nsp->network_interface = network_interface;
            a10nsp->name = network_interface->name;
            a10nsp->interface = network_interface->interface;
            a10nsp->ifindex = network_interface->ifindex;
            a10nsp->txq = network_interface->txq;
            a10nsp->tx_label = network_config->a10nsp_tx_label;
            memcpy(a10nsp->mac, network_interface->mac, ETH_ADDR_LEN);

            CIRCLEQ_INSERT_TAIL(&g_ctx->a10nsp_interface_qhead, a10nsp, a10nsp_interface_qnode);

            /* TX list init */
            CIRCLEQ_INIT(&a10nsp->session_tx_qhead);

            /* Timer to compute periodic rates */
            timer_add_periodic(&g_ctx->timer_root, &network_interface->a10nsp->rate_job, "Rate Computation", 1, 0, 
                               network_interface->a10nsp, &bbl_a10nsp_interface_rate_job);
            network_interface->a10nsp->rate_job->reset = false;

            LOG(DEBUG, "Added a10nsp switch to network network interface %s\n", ifname);
        }

        /* TX list init */
        CIRCLEQ_INIT(&network_interface->l2tp_tx_qhead);

        /* Timer to compute periodic rates */
        timer_add_periodic(&g_ctx->timer_root, &network_interface->rate_job, "Rate Computation", 1, 0, network_interface,
                           &bbl_network_interface_rate_job);
        network_interface->rate_job->reset = false;
        LOG(DEBUG, "Added network interface %s\n", ifname);
        network_config = network_config->next;
    }
    return true;
}

/**
 * bbl_network_interface_get
 *
 * @brief This function returns the network interface
 * with the given name and VLAN or the first network 
 * interface found if name is NULL.
 *
 * @param interface_name interface name
 * @return network interface
 */
bbl_network_interface_s*
bbl_network_interface_get(char *interface_name)
{
    struct bbl_interface_ *interface;
    bbl_network_interface_s *network_interface;

    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        network_interface = interface->network;
        while(network_interface) {
            if(!interface_name) {
                return network_interface;
            }
            if(strcmp(network_interface->name, interface_name) == 0) {
                return network_interface;
            }
            network_interface = network_interface->next;
        }
    }
    return NULL;
}

static void
bbl_network_update_eth(bbl_network_interface_s *interface,
                       bbl_ethernet_header_s *eth) {
    eth->dst = eth->src;
    eth->src = interface->mac;
    eth->vlan_outer = interface->vlan;
    eth->vlan_inner = 0;
    eth->vlan_three = 0;
    if(interface->tx_label.label) {
        eth->mpls = &interface->tx_label;
    } else {
        eth->mpls = NULL;
    }
}

static bbl_txq_result_t
bbl_network_arp_reply(bbl_network_interface_s *interface,
                      bbl_ethernet_header_s *eth,
                      bbl_arp_s *arp) {
    uint32_t target_ip = arp->target_ip;
    bbl_network_update_eth(interface, eth);
    arp->code = ARP_REPLY;
    arp->target = arp->sender;
    arp->target_ip = arp->sender_ip;
    arp->sender = interface->mac;
    arp->sender_ip = target_ip;
    return bbl_txq_to_buffer(interface->txq, eth);
}

static bbl_txq_result_t
bbl_network_icmp_reply(bbl_network_interface_s *interface,
                       bbl_ethernet_header_s *eth,
                       bbl_ipv4_s *ipv4,
                       bbl_icmp_s *icmp) {
    uint32_t dst = ipv4->dst;
    bbl_network_update_eth(interface, eth);
    ipv4->dst = ipv4->src;
    ipv4->src = dst;
    ipv4->ttl = 64;
    icmp->type = ICMP_TYPE_ECHO_REPLY;
    return bbl_txq_to_buffer(interface->txq, eth);
}

static bbl_txq_result_t
bbl_network_icmpv6_na(bbl_network_interface_s *interface,
                      bbl_ethernet_header_s *eth,
                      bbl_ipv6_s *ipv6,
                      bbl_icmpv6_s *icmpv6) {
    bbl_network_update_eth(interface, eth);
    ipv6->dst = ipv6->src;
    ipv6->src = icmpv6->prefix.address;
    ipv6->ttl = 255;
    icmpv6->type = IPV6_ICMPV6_NEIGHBOR_ADVERTISEMENT;
    icmpv6->mac = interface->mac;
    icmpv6->flags = 0;
    icmpv6->data = NULL;
    icmpv6->data_len = 0;
    icmpv6->dns1 = NULL;
    icmpv6->dns2 = NULL;
    return bbl_txq_to_buffer(interface->txq, eth);
}

static bbl_txq_result_t
bbl_network_icmpv6_echo_reply(bbl_network_interface_s *interface,
                              bbl_ethernet_header_s *eth,
                              bbl_ipv6_s *ipv6,
                              bbl_icmpv6_s *icmpv6) {
    uint8_t *dst = ipv6->dst;
    bbl_network_update_eth(interface, eth);
    ipv6->dst = ipv6->src;
    ipv6->src = dst;
    ipv6->ttl = 255;
    icmpv6->type = IPV6_ICMPV6_ECHO_REPLY;
    return bbl_txq_to_buffer(interface->txq, eth);
}

static void
bbl_network_rx_arp(bbl_network_interface_s *interface, bbl_ethernet_header_s *eth) {
    bbl_secondary_ip_s *secondary_ip;

    bbl_arp_s *arp = (bbl_arp_s*)eth->next;
    if(arp->sender_ip == interface->gateway) {
        interface->arp_resolved = true;
        if(memcmp(interface->gateway_mac, "\x00\x00\x00\x00\x00\x00", ETH_ADDR_LEN) == 0) {
            memcpy(interface->gateway_mac, arp->sender, ETH_ADDR_LEN);
            if(!ipv6_addr_not_zero(&interface->gateway6)) {
                memcpy(interface->gateway6_mac, interface->gateway_mac, ETH_ADDR_LEN);
            }
        }
    }
    if(arp->code == ARP_REQUEST) {
        if(arp->target_ip == interface->ip.address) {
            bbl_network_arp_reply(interface, eth, arp);
        } else {
            secondary_ip = interface->secondary_ip_addresses;
            while(secondary_ip) {
                if(arp->target_ip == secondary_ip->ip) {
                    bbl_network_arp_reply(interface, eth, arp);
                    return;
                }
                secondary_ip = secondary_ip->next;
            }
        }
    }
}

static void
bbl_network_rx_icmpv6(bbl_network_interface_s *interface, 
                      bbl_ethernet_header_s *eth) {
    uint8_t *gw_mac;
    bbl_ipv6_s *ipv6;
    bbl_icmpv6_s *icmpv6;
    bbl_secondary_ip6_s *secondary_ip6;

    ipv6 = (bbl_ipv6_s*)eth->next;
    icmpv6 = (bbl_icmpv6_s*)ipv6->next;


    if(icmpv6->type == IPV6_ICMPV6_NEIGHBOR_ADVERTISEMENT) {
        if(memcmp(icmpv6->prefix.address, interface->gateway6, IPV6_ADDR_LEN) == 0) {
            interface->icmpv6_nd_resolved = true;
            if(memcmp(interface->gateway6_mac, "\x00\x00\x00\x00\x00\x00", ETH_ADDR_LEN) == 0) {
                if(icmpv6->dst_mac == NULL) {
                    gw_mac = eth->src;
                } else {
                    gw_mac = icmpv6->dst_mac;
                }
                memcpy(interface->gateway6_mac, gw_mac, ETH_ADDR_LEN);
            }
        }
    } else if(icmpv6->type == IPV6_ICMPV6_NEIGHBOR_SOLICITATION) {
        if(memcmp(icmpv6->prefix.address, interface->ip6.address, IPV6_ADDR_LEN) == 0) {
            bbl_network_icmpv6_na(interface, eth, ipv6, icmpv6);
        } else if(memcmp(icmpv6->prefix.address, interface->ip6_ll, IPV6_ADDR_LEN) == 0) {
            bbl_network_icmpv6_na(interface, eth, ipv6, icmpv6);
        } else {
            secondary_ip6 = interface->secondary_ip6_addresses;
            while(secondary_ip6) {
                if(memcmp(icmpv6->prefix.address, secondary_ip6->ip, IPV6_ADDR_LEN) == 0) {
                    bbl_network_icmpv6_na(interface, eth, ipv6, icmpv6);
                    return;
                }
                secondary_ip6 = secondary_ip6->next;
            }
        }
    } else if(icmpv6->type == IPV6_ICMPV6_ROUTER_SOLICITATION && interface->ipv6_ra) {
        interface->send_requests |= BBL_IF_SEND_ICMPV6_RA;
    } else if(icmpv6->type == IPV6_ICMPV6_ECHO_REQUEST) {
        bbl_network_icmpv6_echo_reply(interface, eth, ipv6, icmpv6);
    }
}

static void
bbl_network_rx_icmp(bbl_network_interface_s *interface, 
                    bbl_ethernet_header_s *eth, bbl_ipv4_s *ipv4)
{
    bbl_icmp_s *icmp = (bbl_icmp_s*)ipv4->next;
    if(icmp->type == ICMP_TYPE_ECHO_REQUEST) {
        /* Send ICMP reply... */
        if(bbl_network_icmp_reply(interface, eth, ipv4, icmp) == BBL_TXQ_OK) {
            interface->stats.icmp_tx++;
        }
    }  else {
        bbl_icmp_client_rx(NULL, interface, eth, ipv4, icmp);
    }
    interface->stats.icmp_rx++;
}

/**
 * bbl_network_rx_handler
 *
 * This function handles all packets received on network interfaces.
 *
 * @param interface pointer to network interface on which packet was received
 * @param eth pointer to ethernet header structure of received packet
 */
void
bbl_network_rx_handler(bbl_network_interface_s *interface, 
                       bbl_ethernet_header_s *eth)
{
    bbl_ipv4_s *ipv4 = NULL;
    bbl_ipv6_s *ipv6 = NULL;
    bbl_udp_s *udp = NULL;

    interface->stats.packets_rx++;
    interface->stats.bytes_rx += eth->length;

    switch(eth->type) {
        case ETH_TYPE_ARP:
            bbl_network_rx_arp(interface, eth);
            return;
        case ETH_TYPE_IPV4:
            ipv4 = (bbl_ipv4_s*)eth->next;
            if(ipv4->protocol == PROTOCOL_IPV4_UDP) {
                udp = (bbl_udp_s*)ipv4->next;
                /* LDP hello is send to all routers multicast address and therefore 
                 * processed before check on local MAC address. */
                if(udp->protocol == UDP_PROTOCOL_LDP) {
                    ldp_hello_ipv4_rx(interface, eth, ipv4, (bbl_ldp_hello_s*)udp->next);
                    return;
                }
                if(memcmp(interface->mac, eth->dst, ETH_ADDR_LEN) != 0) {
                   /* Drop wrong MAC */
                    return;
                }
                if(udp->protocol == UDP_PROTOCOL_QMX_LI) {
                    bbl_qmx_li_handler_rx(interface, eth, (bbl_qmx_li_s*)udp->next);
                    return;
                } else if(udp->protocol == UDP_PROTOCOL_L2TP) {
                    bbl_l2tp_handler_rx(interface, eth, (bbl_l2tp_s*)udp->next);
                    return;
                } 
            } else if(ipv4->protocol == PROTOCOL_IPV4_ICMP) {
                if(memcmp(interface->mac, eth->dst, ETH_ADDR_LEN) != 0) {
                   /* Drop wrong MAC */
                    return;
                }
                bbl_network_rx_icmp(interface, eth, ipv4);
                return;
            } else if(ipv4->protocol == PROTOCOL_IPV4_TCP) {
                if(memcmp(interface->mac, eth->dst, ETH_ADDR_LEN) != 0) {
                   /* Drop wrong MAC */
                    return;
                }
                bbl_tcp_ipv4_rx(interface, eth, ipv4);
                return;
            } else if(ipv4->protocol == PROTOCOL_IPV4_OSPF && interface->ospfv2_interface) {
                ospf_handler_rx_ipv4(interface, eth, ipv4);
                return;
            } else if(ipv4->offset & ~IPV4_DF) {
                interface->stats.ipv4_fragmented_rx++;
                bbl_fragment_rx(NULL, interface, eth, ipv4);
            }
            break;
        case ETH_TYPE_IPV6:
            ipv6 = (bbl_ipv6_s*)eth->next;
            if(ipv6->protocol == IPV6_NEXT_HEADER_ICMPV6) {
                bbl_network_rx_icmpv6(interface, eth);
                return;
            } else if(ipv6->protocol == IPV6_NEXT_HEADER_UDP) {
                udp = (bbl_udp_s*)ipv6->next;
                /* LDP hello is send to all routers multicast address and therefore 
                 * processed before check on local MAC address. */
                if(udp->protocol == UDP_PROTOCOL_LDP) {
                    ldp_hello_ipv6_rx(interface, eth, ipv6, (bbl_ldp_hello_s*)udp->next);
                    return;
                }
            } else if(ipv6->protocol == IPV6_NEXT_HEADER_TCP) {
                if(memcmp(interface->mac, eth->dst, ETH_ADDR_LEN) != 0) {
                   /* Drop wrong MAC */
                    return;
                }
                bbl_tcp_ipv6_rx(interface, eth, ipv6);
                return;
            } else if(ipv6->protocol == IPV6_NEXT_HEADER_OSPF && interface->ospfv3_interface) {
                ospf_handler_rx_ipv6(interface, eth, ipv6);
                return;
            }
            break;
        case ISIS_PROTOCOL_IDENTIFIER:
            isis_handler_rx(interface, eth);
            return;
        default:
            break;
    }
    interface->stats.unknown++;
}

static json_t *
bbl_network_interface_json(bbl_network_interface_s *interface)
{
    return json_pack("{ss si ss sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI sI}",
                     "name", interface->name,
                     "ifindex", interface->ifindex,
                     "type", "Network",
                     "tx-packets", interface->stats.packets_tx,
                     "tx-bytes", interface->stats.bytes_tx, 
                     "tx-pps", interface->stats.rate_packets_tx.avg,
                     "tx-kbps", interface->stats.rate_bytes_tx.avg * 8 / 1000,
                     "rx-packets", interface->stats.packets_rx, 
                     "rx-bytes", interface->stats.bytes_rx,
                     "rx-pps", interface->stats.rate_packets_rx.avg,
                     "rx-kbps", interface->stats.rate_bytes_rx.avg * 8 / 1000,
                     "tx-packets-multicast", interface->stats.mc_tx,
                     "tx-pps-multicast", interface->stats.rate_mc_tx.avg,
                     "tx-packets-session-ipv4", interface->stats.session_ipv4_tx,
                     "tx-pps-session-ipv4", interface->stats.rate_session_ipv4_tx.avg,
                     "rx-packets-session-ipv4", interface->stats.session_ipv4_rx,
                     "rx-pps-session-ipv4", interface->stats.rate_session_ipv4_rx.avg,
                     "rx-loss-packets-session-ipv4", interface->stats.session_ipv4_loss,
                     "tx-packets-session-ipv6", interface->stats.session_ipv6_tx,
                     "tx-pps-session-ipv6", interface->stats.rate_session_ipv6_tx.avg,
                     "rx-packets-session-ipv6", interface->stats.session_ipv6_rx,
                     "rx-pps-session-ipv6", interface->stats.rate_session_ipv6_rx.avg,
                     "rx-loss-packets-session-ipv6", interface->stats.session_ipv6_loss,
                     "tx-packets-session-ipv6pd", interface->stats.session_ipv6pd_tx,
                     "tx-pps-session-ipv6pd", interface->stats.rate_session_ipv6pd_tx.avg,
                     "rx-packets-session-ipv6pd", interface->stats.session_ipv6pd_rx,
                     "rx-pps-session-ipv6pd", interface->stats.rate_session_ipv6pd_rx.avg,
                     "rx-loss-packets-session-ipv6pd", interface->stats.session_ipv6pd_loss,
                     "tx-packets-streams", interface->stats.stream_tx,
                     "tx-pps-streams", interface->stats.rate_stream_tx.avg,
                     "rx-packets-streams", interface->stats.stream_rx,
                     "rx-pps-streams", interface->stats.rate_stream_rx.avg,
                     "rx-loss-packets-streams", interface->stats.stream_loss
                    );
}

/* Control Socket Commands */

int
bbl_network_ctrl_interfaces(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    int result = 0;
    json_t *root, *interfaces;
    bbl_interface_s *interface;
    bbl_network_interface_s *network_interface;

    interfaces = json_array();
    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        network_interface = interface->network;
        while(network_interface) {
            json_array_append_new(interfaces, bbl_network_interface_json(network_interface));
            network_interface = network_interface->next;
        }
    }
    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "network-interfaces", interfaces);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(interfaces);
    }
    return result;
}
