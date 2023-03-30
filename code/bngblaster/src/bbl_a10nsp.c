/*
 * BNG Blaster (BBL) - A10NSP Functions
 *
 * Christian Giese, September 2021
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"
#include "bbl_stream.h"

static uint32_t
bbl_a10nsp_ipv4_address()
{
    static uint32_t index = 0;
    index++;
    if(index > 16000000) {
        index = 1;
    }
    return htobe32(MOCK_IP_LOCAL + index);
}

void
bbl_a10nsp_interface_rate_job(timer_s *timer)
{
    bbl_a10nsp_interface_s *interface = timer->data;
    bbl_compute_avg_rate(&interface->stats.rate_packets_tx, interface->stats.packets_tx);
    bbl_compute_avg_rate(&interface->stats.rate_packets_rx, interface->stats.packets_rx);
    bbl_compute_avg_rate(&interface->stats.rate_bytes_tx, interface->stats.bytes_tx);
    bbl_compute_avg_rate(&interface->stats.rate_bytes_rx, interface->stats.bytes_rx);
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
 * bbl_a10nsp_interfaces_add
 */
bool
bbl_a10nsp_interfaces_add()
{
    bbl_a10nsp_config_s *a10nsp_config = g_ctx->config.a10nsp_config;
    bbl_a10nsp_interface_s *a10nsp_interface;
    bbl_interface_s *interface;

    while(a10nsp_config) {
        interface = bbl_interface_get(a10nsp_config->interface);
        if(!interface) {
            LOG(ERROR, "Failed to add a10nsp interface %s (interface not found)\n", a10nsp_config->interface);
            return false;
        }
        if(interface->a10nsp) {
            LOG(ERROR, "Failed to add a10nsp interface %s (duplicate)\n", a10nsp_config->interface);
            return false;
        }
        if(interface->access || interface->network) {
            LOG(ERROR, "Failed to add a10nsp interface %s (used)\n", a10nsp_config->interface);
            return false;
        }

        a10nsp_interface = calloc(1, sizeof(bbl_a10nsp_interface_s));
        interface->a10nsp = a10nsp_interface;
        a10nsp_config->a10nsp_interface = a10nsp_interface;

        CIRCLEQ_INSERT_TAIL(&g_ctx->a10nsp_interface_qhead, a10nsp_interface, a10nsp_interface_qnode);

        /* Init interface */
        a10nsp_interface->name = a10nsp_config->interface;
        a10nsp_interface->interface = interface;

        /* Init TXQ */
        a10nsp_interface->txq = calloc(1, sizeof(bbl_txq_s));
        bbl_txq_init(a10nsp_interface->txq, BBL_TXQ_DEFAULT_SIZE);

        /* Init ethernet */
        a10nsp_interface->qinq = a10nsp_config->qinq;
        if(*(uint32_t*)a10nsp_config->mac) {
            memcpy(a10nsp_interface->mac, a10nsp_config->mac, ETH_ADDR_LEN);
        } else {
            memcpy(a10nsp_interface->mac, interface->mac, ETH_ADDR_LEN);
        }      

        /* TX list init */
        CIRCLEQ_INIT(&a10nsp_interface->session_tx_qhead);

        /* Timer to compute periodic rates */
        timer_add_periodic(&g_ctx->timer_root, &a10nsp_interface->rate_job, "Rate Computation", 1, 0, a10nsp_interface,
                           &bbl_a10nsp_interface_rate_job);

        LOG(DEBUG, "Added a10nsp interface %s\n", a10nsp_config->interface);
        a10nsp_config = a10nsp_config->next;
    }
    return true;
}

/**
 * bbl_a10nsp_interface_get
 *
 * @brief This function returns the A10NSP interface
 * with the given name or the first A10NSP 
 * interface found if name is NULL.
 *
 * @param interface_name interface name
 * @return a10nsp interface
 */
bbl_a10nsp_interface_s*
bbl_a10nsp_interface_get(char *interface_name)
{
    struct bbl_interface_ *interface;

    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        if(interface_name) {
            if(strcmp(interface->name, interface_name) == 0) {
                return interface->a10nsp;
            }
        } else if(interface->a10nsp) {
            return interface->a10nsp;
        }
    }
    return NULL;
}

void
bbl_a10nsp_session_free(bbl_session_s *session)
{
    if(session->a10nsp_session) {
        if(session->a10nsp_session->pppoe_aci) {
            free(session->a10nsp_session->pppoe_aci);
        }
        if(session->a10nsp_session->pppoe_ari) {
            free(session->a10nsp_session->pppoe_ari);
        }
        if(session->a10nsp_session->dhcp_aci) {
            free(session->a10nsp_session->dhcp_aci);
        }
        if(session->a10nsp_session->dhcp_ari) {
            free(session->a10nsp_session->dhcp_ari);
        }
        if(session->a10nsp_session->dhcpv6_aci) {
            free(session->a10nsp_session->dhcpv6_aci);
        }
        if(session->a10nsp_session->dhcpv6_ari) {
            free(session->a10nsp_session->dhcpv6_ari);
        }
        free(session->a10nsp_session);
        session->a10nsp_session = NULL;
    }
}

static void
bbl_a10nsp_pppoed_handler(bbl_a10nsp_interface_s *interface,
                          bbl_session_s *session,
                          bbl_ethernet_header_s *eth)
{
    bbl_a10nsp_session_s *a10nsp_session = session->a10nsp_session;
    bbl_pppoe_discovery_s *pppoed = (bbl_pppoe_discovery_s*)eth->next;
    uint8_t ac_cookie[16];
    uint8_t i;

    switch(pppoed->code) {
        case PPPOE_PADI:
            pppoed->code = PPPOE_PADO;
            /* Init random AC-Cookie */
            for(i = 0; i < sizeof(ac_cookie); i++) {
                ac_cookie[i] = rand();
            }
            pppoed->ac_cookie = ac_cookie;
            pppoed->ac_cookie_len = sizeof(ac_cookie);
            if(pppoed->access_line) {
                if(pppoed->access_line->aci) {
                    if(a10nsp_session->pppoe_aci) {
                        free(a10nsp_session->pppoe_aci);
                    }
                    a10nsp_session->pppoe_aci = strdup(pppoed->access_line->aci);
                }
                if(pppoed->access_line->ari) {
                    if(a10nsp_session->pppoe_ari) {
                        free(a10nsp_session->pppoe_ari);
                    }
                    a10nsp_session->pppoe_ari = strdup(pppoed->access_line->ari);
                }
            }
            break;
        case PPPOE_PADR:
            pppoed->code = PPPOE_PADS;
            pppoed->session_id = (uint16_t)session->session_id;
            break;
        default:
            return;
    }
    pppoed->access_line = NULL;
    pppoed->service_name = (uint8_t*)A10NSP_PPPOE_SERVICE_NAME;
    pppoed->service_name_len = sizeof(A10NSP_PPPOE_SERVICE_NAME)-1;
    pppoed->ac_name = (uint8_t*)A10NSP_PPPOE_AC_NAME;
    pppoed->ac_name_len = sizeof(A10NSP_PPPOE_AC_NAME)-1;
    if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
        a10nsp_session->stats.packets_tx++;
    }
    return;
}

static void
bbl_a10nsp_lcp_handler(bbl_a10nsp_interface_s *interface,
                       bbl_session_s *session,
                       bbl_ethernet_header_s *eth)
{
    bbl_a10nsp_session_s *a10nsp_session = session->a10nsp_session;
    bbl_pppoe_session_s *pppoes = (bbl_pppoe_session_s*)eth->next;
    bbl_lcp_s *lcp = (bbl_lcp_s*)pppoes->next;
    bbl_lcp_s lcp_request = {0};

    switch(lcp->code) {
        case PPP_CODE_CONF_REQUEST:
            lcp->code = PPP_CODE_CONF_ACK;
            if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
                a10nsp_session->stats.packets_tx++;
            }
            lcp_request.code = PPP_CODE_CONF_REQUEST;
            lcp_request.identifier = 1;
            lcp_request.auth = PROTOCOL_PAP;
            lcp_request.mru = PPPOE_DEFAULT_MRU;
            lcp_request.magic = lcp->magic+1;
            pppoes->next = &lcp_request;
            if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
                a10nsp_session->stats.packets_tx++;
            }
            break;
        case PPP_CODE_ECHO_REQUEST:
            lcp->code = PPP_CODE_ECHO_REPLY;
            if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
                a10nsp_session->stats.packets_tx++;
            }
            break;
        case PPP_CODE_TERM_REQUEST:
            lcp->code = PPP_CODE_TERM_ACK;
            if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
                a10nsp_session->stats.packets_tx++;
            }
            break;
        default:
            break;
    }
}

static void
bbl_a10nsp_pap_handler(bbl_a10nsp_interface_s *interface,
                       bbl_session_s *session,
                       bbl_ethernet_header_s *eth)
{
    bbl_a10nsp_session_s *a10nsp_session = session->a10nsp_session;
    bbl_pppoe_session_s *pppoes = (bbl_pppoe_session_s*)eth->next;
    bbl_pap_s *pap = (bbl_pap_s*)pppoes->next;
    bbl_pap_s pap_response = {0};

    pap_response.code = PAP_CODE_ACK;
    pap_response.identifier = pap->identifier;
    pap_response.reply_message = A10NSP_REPLY_MESSAGE;
    pap_response.reply_message_len = sizeof(A10NSP_REPLY_MESSAGE)-1;
    pppoes->next = &pap_response;
    if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
        a10nsp_session->stats.packets_tx++;
    }
}

static void
bbl_a10nsp_ipcp_handler(bbl_a10nsp_interface_s *interface,
                        bbl_session_s *session,
                        bbl_ethernet_header_s *eth)
{
    bbl_a10nsp_session_s *a10nsp_session = session->a10nsp_session;
    bbl_pppoe_session_s *pppoes = (bbl_pppoe_session_s*)eth->next;
    bbl_ipcp_s *ipcp = (bbl_ipcp_s*)pppoes->next;
    bbl_ipcp_s ipcp_request = {0};

    UNUSED(session);

    switch(ipcp->code) {
        case PPP_CODE_CONF_REQUEST:
            if(ipcp->address == a10nsp_session->ipv4_address) {
                ipcp->code = PPP_CODE_CONF_ACK;
            } else {
                ipcp->options = NULL;
                ipcp->options_len = 0;
                ipcp->code = PPP_CODE_CONF_NAK;
                ipcp->address = a10nsp_session->ipv4_address;
                ipcp->option_address = true;
                if(ipcp->option_dns1) {
                    ipcp->dns1 = MOCK_DNS1;
                }
                if(ipcp->option_dns2) {
                    ipcp->dns2 = MOCK_DNS2;
                }
            }
            if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
                a10nsp_session->stats.packets_tx++;
            }
            ipcp_request.code = PPP_CODE_CONF_REQUEST;
            ipcp_request.identifier = 1;
            ipcp_request.address = MOCK_IP_LOCAL;
            ipcp_request.option_address = true;
            pppoes->next = &ipcp_request;
            if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
                a10nsp_session->stats.packets_tx++;
            }
            break;
        case PPP_CODE_TERM_REQUEST:
            ipcp->code = PPP_CODE_TERM_ACK;
            if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
                a10nsp_session->stats.packets_tx++;
            }
            break;
        default:
            break;
    }
}

static void
bbl_a10nsp_ip6cp_handler(bbl_a10nsp_interface_s *interface,
                         bbl_session_s *session,
                         bbl_ethernet_header_s *eth)
{
    bbl_a10nsp_session_s *a10nsp_session = session->a10nsp_session;
    bbl_pppoe_session_s *pppoes = (bbl_pppoe_session_s*)eth->next;
    bbl_ip6cp_s *ip6cp = (bbl_ip6cp_s*)pppoes->next;
    bbl_ip6cp_s ip6cp_request = {0};

    UNUSED(session);

    switch(ip6cp->code) {
        case PPP_CODE_CONF_REQUEST:
            ip6cp->code = PPP_CODE_CONF_ACK;
            if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
                a10nsp_session->stats.packets_tx++;
            }
            ip6cp_request.code = PPP_CODE_CONF_REQUEST;
            ip6cp_request.identifier = 1;
            ip6cp_request.ipv6_identifier = 1;
            pppoes->next = &ip6cp_request;
            if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
                a10nsp_session->stats.packets_tx++;
            }
            break;
        case PPP_CODE_TERM_REQUEST:
            ip6cp->code = PPP_CODE_TERM_ACK;
            if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
                a10nsp_session->stats.packets_tx++;
            }
            break;
        default:
            break;
    }
}

static void
bbl_a10nsp_pppoes_handler(bbl_a10nsp_interface_s *interface,
                          bbl_session_s *session,
                          bbl_ethernet_header_s *eth)
{
    bbl_pppoe_session_s *pppoes = (bbl_pppoe_session_s*)eth->next;
    switch(pppoes->protocol) {
        case PROTOCOL_LCP:
            bbl_a10nsp_lcp_handler(interface, session, eth);
            break;
        case PROTOCOL_PAP:
            bbl_a10nsp_pap_handler(interface, session, eth);
            break;
        case PROTOCOL_IPCP:
            bbl_a10nsp_ipcp_handler(interface, session, eth);
            break;
        case PROTOCOL_IP6CP:
            bbl_a10nsp_ip6cp_handler(interface, session, eth);
            break;
        default:
            break;
    }
}

static void
bbl_a10nsp_arp_handler(bbl_a10nsp_interface_s *interface,
                       bbl_session_s *session,
                       bbl_ethernet_header_s *eth)
{
    bbl_arp_s *arp = (bbl_arp_s*)eth->next;
    uint32_t target_ip = arp->target_ip;

    if(arp->code == ARP_REQUEST) {
        arp->code = ARP_REPLY;
        arp->target = arp->sender;
        arp->target_ip = arp->sender_ip;
        arp->sender = interface->mac;
        arp->sender_ip = target_ip;
        if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
            session->a10nsp_session->stats.packets_tx++;
        }
    }
}

static void
bbl_a10nsp_dhcp_handler(bbl_a10nsp_interface_s *interface,
                        bbl_session_s *session,
                        bbl_ethernet_header_s *eth)
{
    bbl_a10nsp_session_s *a10nsp_session = session->a10nsp_session;
    bbl_ipv4_s *ipv4 = (bbl_ipv4_s*)eth->next;
    bbl_udp_s *udp = (bbl_udp_s*)ipv4->next;
    bbl_dhcp_s *dhcp = (bbl_dhcp_s*)udp->next;
    switch(dhcp->type) {
        case DHCP_MESSAGE_DISCOVER:
            dhcp->type = DHCP_MESSAGE_OFFER;
            if(dhcp->access_line) {
                if(dhcp->access_line->aci) {
                    if(a10nsp_session->dhcp_aci) {
                        free(a10nsp_session->dhcp_aci);
                    }
                    a10nsp_session->dhcp_aci = strdup(dhcp->access_line->aci);
                }
                if(dhcp->access_line->ari) {
                    if(a10nsp_session->dhcp_ari) {
                        free(a10nsp_session->dhcp_ari);
                    }
                    a10nsp_session->dhcp_ari = strdup(dhcp->access_line->ari);
                }
            }
            break;
        case DHCP_MESSAGE_REQUEST:
        case DHCP_MESSAGE_RELEASE:
            dhcp->type = DHCP_MESSAGE_ACK;
            break;
        default:
            return;
    }
    ipv4->src = MOCK_IP_LOCAL;
    ipv4->dst = IPV4_BROADCAST;
    udp->src = DHCP_UDP_SERVER;
    udp->dst = DHCP_UDP_CLIENT;
    dhcp->header->op = BOOTREPLY;
    dhcp->header->secs = 0;
    dhcp->header->hops = 0;
    dhcp->header->yiaddr = a10nsp_session->ipv4_address;
    dhcp->header->siaddr = MOCK_IP_LOCAL;
    dhcp->parameter_request_list = false;
    dhcp->client_identifier = NULL;
    dhcp->access_line = NULL;
    dhcp->option_server_identifier = true;
    dhcp->server_identifier = MOCK_IP_LOCAL;
    dhcp->option_address = true;
    dhcp->address = a10nsp_session->ipv4_address;
    dhcp->option_router = true;
    dhcp->router = MOCK_IP_LOCAL;
    dhcp->option_lease_time = true;
    dhcp->lease_time = 120;
    if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
        a10nsp_session->stats.packets_tx++;
    }
}

static void
bbl_a10nsp_dhcpv6_handler(bbl_a10nsp_interface_s *interface,
                        bbl_session_s *session,
                        bbl_ethernet_header_s *eth)
{
    bbl_a10nsp_session_s *a10nsp_session = session->a10nsp_session;
    bbl_ipv6_s *ipv6 = (bbl_ipv6_s*)eth->next;
    bbl_udp_s *udp = (bbl_udp_s*)ipv6->next;

    bbl_dhcpv6_s *dhcpv6 = (bbl_dhcpv6_s*)udp->next;
    bbl_dhcpv6_s *dhcpv6_outer = dhcpv6;

    if(dhcpv6->type == DHCPV6_MESSAGE_RELAY_FORW) {
        if(!dhcpv6->relay_message) {
            /* Invalid request. */
            return;
        }
        dhcpv6 = dhcpv6->relay_message;
        dhcpv6_outer->type = DHCPV6_MESSAGE_RELAY_REPL;
    }

    switch(dhcpv6->type) {
        case DHCPV6_MESSAGE_SOLICIT:
            if(dhcpv6->rapid) {
                dhcpv6->type = DHCPV6_MESSAGE_REPLY;
            } else {
                dhcpv6->type = DHCPV6_MESSAGE_ADVERTISE;
            }
            break;
        case DHCPV6_MESSAGE_REQUEST:
            dhcpv6->type = DHCPV6_MESSAGE_REPLY;
            break;
        case DHCPV6_MESSAGE_RELEASE:
            dhcpv6->type = DHCPV6_MESSAGE_REPLY;
            break;
        default:
            return;
    }

    if(dhcpv6_outer->access_line) {
        if(dhcpv6_outer->access_line->aci) {
            if(a10nsp_session->dhcpv6_aci) {
                free(a10nsp_session->dhcpv6_aci);
            }
            a10nsp_session->dhcp_aci = strdup(dhcpv6_outer->access_line->aci);
        }
        if(dhcpv6_outer->access_line->ari) {
            if(a10nsp_session->dhcpv6_ari) {
                free(a10nsp_session->dhcpv6_ari);
            }
            a10nsp_session->dhcpv6_ari = strdup(dhcpv6_outer->access_line->ari);
        }
        dhcpv6_outer->access_line = NULL;
    }

    ipv6->dst = ipv6->src;
    ipv6->src = (void*)ipv6_link_local_address;
    ipv6->ttl = 255;
    udp->src = DHCPV6_UDP_SERVER;
    udp->dst = DHCPV6_UDP_CLIENT;

    dhcpv6->server_duid = (void*)mock_dhcpv6_server_duid;
    dhcpv6->server_duid_len = sizeof(mock_dhcpv6_server_duid);
    dhcpv6->rapid = false;
    dhcpv6->oro = false;
    dhcpv6->dns1 = NULL;
    dhcpv6->dns2 = NULL;
    if(dhcpv6->ia_na_iaid) {
        dhcpv6->ia_na_option_len = 0;
        dhcpv6->ia_na_address = (void*)&mock_ipv6_ia_na;
        dhcpv6->ia_na_t1 = 300;
        dhcpv6->ia_na_t2 = 600;
        dhcpv6->ia_na_preferred_lifetime = 900;
        dhcpv6->ia_na_valid_lifetime = 1800;
    }
    if(dhcpv6->ia_pd_iaid) {
        dhcpv6->ia_pd_option_len = 0;
        dhcpv6->ia_pd_prefix = (void*)&mock_ipv6_ia_pd;
        dhcpv6->ia_pd_t1 = 300;
        dhcpv6->ia_pd_t2 = 600;
        dhcpv6->ia_pd_preferred_lifetime = 900;
        dhcpv6->ia_pd_valid_lifetime = 1800;
    }

    if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
        a10nsp_session->stats.packets_tx++;
    }
}

static void
bbl_a10nsp_icmpv6_handler(bbl_a10nsp_interface_s *interface,
                        bbl_session_s *session,
                        bbl_ethernet_header_s *eth)
{
    bbl_a10nsp_session_s *a10nsp_session = session->a10nsp_session;
    bbl_ipv6_s *ipv6 = (bbl_ipv6_s*)eth->next;
    bbl_icmpv6_s *icmpv6 = (bbl_icmpv6_s*)ipv6->next;

    switch(icmpv6->type) {
        case IPV6_ICMPV6_ROUTER_SOLICITATION:
            icmpv6->type = IPV6_ICMPV6_ROUTER_ADVERTISEMENT;
            icmpv6->mac = interface->mac;
            icmpv6->data_len = 0;
            break;
        default:
            return;
    }

    ipv6->src = (void*)ipv6_link_local_address;
    ipv6->dst = (void*)ipv6_multicast_all_nodes;
    ipv6->ttl = 255;
    if(bbl_txq_to_buffer(interface->txq, eth) == BBL_TXQ_OK) {
        a10nsp_session->stats.packets_tx++;
    }
}

static void
bbl_a10nsp_ipv4_handler(bbl_a10nsp_interface_s *interface,
                        bbl_session_s *session,
                        bbl_ethernet_header_s *eth)
{
    bbl_ipv4_s *ipv4 = (bbl_ipv4_s*)eth->next;
    bbl_udp_s *udp;

    switch(ipv4->protocol) {
        case PROTOCOL_IPV4_UDP:
            udp = (bbl_udp_s*)ipv4->next;
            if(udp->protocol == UDP_PROTOCOL_DHCP) {
                bbl_a10nsp_dhcp_handler(interface, session, eth);
            }
            break;
        default:
            break;
    }
}

static void
bbl_a10nsp_ipv6_handler(bbl_a10nsp_interface_s *interface,
                        bbl_session_s *session,
                        bbl_ethernet_header_s *eth)
{
    bbl_ipv6_s *ipv6 = (bbl_ipv6_s*)eth->next;
    bbl_udp_s *udp;

    switch(ipv6->protocol) {
        case IPV6_NEXT_HEADER_UDP:
            udp = (bbl_udp_s*)ipv6->next;
            if(udp->protocol == UDP_PROTOCOL_DHCPV6) {
                bbl_a10nsp_dhcpv6_handler(interface, session, eth);
            }
            break;
        case IPV6_NEXT_HEADER_ICMPV6:
            bbl_a10nsp_icmpv6_handler(interface, session, eth);
            break;
        default:
            break;
    }
}

/**
 * bbl_a10nsp_rx
 *
 * This function handles all received session
 * traffic on a10nsp interfaces.
 *
 * @param interface Receiving interface.
 * @param session Client session.
 * @param eth Received ethernet packet.
 */
static void
bbl_a10nsp_rx(bbl_a10nsp_interface_s *interface,
              bbl_session_s *session,
              bbl_ethernet_header_s *eth)
{
    /* Create A10NSP session if not already present */
    if(!session->a10nsp_session) {
        LOG(DEBUG, "A10NSP (ID: %u) Session created on interface %s with S-VLAN %d\n",
            session->session_id, interface->name, eth->vlan_outer);
        session->a10nsp_session = calloc(1, sizeof(bbl_a10nsp_session_s));
        session->a10nsp_session->session = session;
        session->a10nsp_session->ipv4_address = bbl_a10nsp_ipv4_address();
        session->a10nsp_session->a10nsp_interface = interface;
        session->a10nsp_session->s_vlan = eth->vlan_outer;
        session->a10nsp_session->qinq_received = eth->qinq;
        session->a10nsp_interface = interface;
    }
    session->a10nsp_session->stats.packets_rx++;

    /* Swap source/destination MAC addresses for response ... */
    eth->dst = eth->src;
    eth->src = interface->mac;
    eth->qinq = interface->qinq;
    switch(eth->type) {
        case ETH_TYPE_PPPOE_DISCOVERY:
            bbl_a10nsp_pppoed_handler(interface, session, eth);
            break;
        case ETH_TYPE_PPPOE_SESSION:
            bbl_a10nsp_pppoes_handler(interface, session, eth);
            break;
        case ETH_TYPE_ARP:
            bbl_a10nsp_arp_handler(interface, session, eth);
            break;
        case ETH_TYPE_IPV4:
            bbl_a10nsp_ipv4_handler(interface, session, eth);
            break;
        case ETH_TYPE_IPV6:
            bbl_a10nsp_ipv6_handler(interface, session, eth);
            break;
        default:
            break;
    }
    return;
}

/**
 * bbl_a10nsp_rx_handler
 *
 * This function handles all packets received on a10nsp interfaces.
 *
 * @param interface pointer to A10NSP interface on which packet was received
 * @param eth pointer to ethernet header structure of received packet
 */
void
bbl_a10nsp_rx_handler(bbl_a10nsp_interface_s *interface,
                      bbl_ethernet_header_s *eth)
{
    bbl_session_s *session;
    uint32_t session_id = 0;

    interface->stats.packets_rx++;
    interface->stats.bytes_rx += eth->length;

    /* The session-id is mapped into the last 3 bytes of
     * the client MAC address. The original approach using
     * VLAN identifiers was not working reliable as some NIC
     * drivers strip outer VLAN and it is also possible to have
     * multiple session per VLAN (N:1). */
    session_id |= eth->src[5];
    session_id |= eth->src[4] << 8;
    session_id |= eth->src[3] << 16;
    session = bbl_session_get(session_id);
    if(session) {
        bbl_a10nsp_rx(interface, session, eth);
    }
}

static json_t *
bbl_a10nsp_interface_json(bbl_a10nsp_interface_s *interface)
{
    return json_pack("{ss si ss si si si si si si si si si si si si si si si si si si si si si si si si si si si si}",
                     "name", interface->name,
                     "ifindex", interface->ifindex,
                     "type", "A10NSP",
                     "tx-packets", interface->stats.packets_tx,
                     "tx-bytes", interface->stats.bytes_tx, 
                     "tx-pps", interface->stats.rate_packets_tx.avg,
                     "tx-kbps", interface->stats.rate_bytes_tx.avg * 8 / 1000,
                     "rx-packets", interface->stats.packets_rx, 
                     "rx-bytes", interface->stats.bytes_rx,
                     "rx-pps", interface->stats.rate_packets_rx.avg,
                     "rx-kbps", interface->stats.rate_bytes_rx.avg * 8 / 1000,
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
bbl_a10nsp_ctrl_interfaces(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    int result = 0;
    json_t *root, *interfaces;
    bbl_interface_s *interface;

    interfaces = json_array();
    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        if(interface->a10nsp) {
            json_array_append(interfaces, bbl_a10nsp_interface_json(interface->a10nsp));
        }
    }
    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "a10nsp-interfaces", interfaces);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(interfaces);
    }
    return result;
}