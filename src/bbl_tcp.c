/*
 * BNG Blaster (BBL) - LwIP
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bbl.h"
#include "lwip/priv/tcp_priv.h"

void
bbl_tcp_ctx_free(bbl_tcp_t *tcp) {
    if(tcp) {
        if(tcp->pcb) {
            tcp_close(tcp->pcb);
        }
        free(tcp);
    }
}

static bbl_tcp_t *
bbl_tcp_new(bbl_interface_s *interface) {
    
    bbl_tcp_t *tcp;

    /* Init TCP context */
    tcp = calloc(1, sizeof(bbl_tcp_t));
    if(!tcp) {
        return NULL;
    }
    tcp->interface = interface;

    /* Init TCP PCB */
    tcp->pcb = tcp_new();
    if(!tcp->pcb) {
        free(tcp);
        return NULL;
    }

    /* Bind local network interface */
    tcp_bind_netif(tcp->pcb, &interface->netif);
    
    /* Add BBL TCP context as argument */
    tcp_arg(tcp->pcb, tcp);

    return tcp;
}

err_t 
bbl_tcp_sent_cb(void *arg, struct tcp_pcb *tpcb, u16_t len) {
    bbl_tcp_t *tcp = arg;
    size_t tx = tpcb->snd_buf;

    UNUSED(len);

    if(tcp->tx.offset < tcp->tx.len) {
        tcp->state = BBL_TCP_STATE_SEND;
        if((tcp->tx.offset + tx) > tcp->tx.len) {
            tx = tcp->tx.len - tcp->tx.offset;
        }
        if(tcp_write(tpcb, tcp->tx.buf + tcp->tx.offset, tx, 0) == ERR_OK) {
            tcp->tx.offset += tx;
        }
    }
    return ERR_OK;
}

err_t 
bbl_tcp_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    bbl_tcp_t *tcp = arg;
    struct pbuf *_p;

    UNUSED(err); /* TODO!!! */
    LOG(TCP, "TCP RX CB\n");
    if(p) {
        _p = p;
        while(_p) {
            if(tcp->receive_cb) {
                (tcp->receive_cb)(tcp->arg, p->payload, p->len);
            }
            _p = _p->next;
        }
        tcp->bytes_rx += p->tot_len;
        tcp_recved(tpcb, p->tot_len);
        pbuf_free(p);
    }
    return ERR_OK;
}

err_t 
bbl_tcp_connected(void *arg, struct tcp_pcb *tpcb, err_t err) {
    bbl_tcp_t *tcp = arg;

    UNUSED(err); /* TODO!!! */

    /* Add send/receive callback functions. */
    tcp_sent(tpcb, bbl_tcp_sent_cb);
    tcp_recv(tpcb, bbl_tcp_recv_cb);
    //tcp_err(tpcb, bbl_tcp_error_cb);
    //tcp_poll(tpcb, bbl_tcp_poll_cb, 0);

    LOG(TCP, "TCP session connected\n");

    tcp->state = BBL_TCP_STATE_IDLE;
    bbl_tcp_sent_cb(tcp, tpcb, 0);
    return ERR_OK;
}

/**
 * bbl_tcp_ipv4_connect 
 * 
 * @param interface interface
 * @param src source address
 * @param dst destination address
 * @param port destination port
 * @return bbl_tcp_t* 
 */
bbl_tcp_t *
bbl_tcp_ipv4_connect(bbl_interface_s *interface, ipv4addr_t *src, ipv4addr_t *dst, uint16_t port) {

    bbl_tcp_t *tcp;

    tcp = bbl_tcp_new(interface);
    if(!tcp) {
        return NULL;
    }

    /* Bind local IP address and port */
    tcp_bind(tcp->pcb, (const ip_addr_t*)src, 0);

    /* Connect session */
    if(tcp_connect(tcp->pcb, (const ip_addr_t*)dst, port, bbl_tcp_connected) != ERR_OK) {
        bbl_tcp_ctx_free(tcp);
        return NULL;
    }

    tcp->af = AF_INET;
    tcp->local.ipv4 = *src;
    tcp->local.port = tcp->pcb->local_port;
    tcp->remote.ipv4 = *dst;
    tcp->remote.port = port;
    
    /* TODO: This looks wrong but is required. 
     * Further investigations needed! */
    tcp->pcb->remote_ip.type = IPADDR_TYPE_V4;

    LOG(TCP, "TCP connect from %s (%u) %s:%u to %s:%u\n",
        interface->name,
        tcp->pcb->netif_idx,
        format_ipv4_address(&tcp->local.ipv4), tcp->local.port,
        format_ipv4_address(&tcp->remote.ipv4), tcp->remote.port);

    return tcp;
}

/**
 * bbl_tcp_ipv4_rx 
 * 
 * @param eth ethernet packet received
 * @param ipv4 ipv4 header received
 * @param interface receiving interface
 */
void
bbl_tcp_ipv4_rx(bbl_interface_s *interface, bbl_ethernet_header_t *eth, bbl_ipv4_t *ipv4) {
    struct pbuf *pbuf;
    UNUSED(eth);

    LOG(TCP, "TCP RX from %s %s to %s\n",
        interface->name,
        format_ipv4_address(&ipv4->src),
        format_ipv4_address(&ipv4->dst));

/* Alternative code...
    struct ip_hdr *iphdr = (struct ip_hdr*)ipv4->hdr;
    ip_addr_copy_from_ip4(*ip_current_dest_addr(), iphdr->dest);
    ip_addr_copy_from_ip4(*ip_current_src_addr(), iphdr->src);
    ip_current_netif() = &interface->netif;
    ip_current_input_netif() = &interface->netif;
*/

    ip_data.current_netif = &interface->netif;
    ip_data.current_input_netif = &interface->netif;
    ip_data.current_iphdr_dest.type = IPADDR_TYPE_V4;
    ip_data.current_iphdr_dest.u_addr.ip4.addr = ipv4->dst;
    ip_data.current_iphdr_src.type = IPADDR_TYPE_V4;
    ip_data.current_iphdr_src.u_addr.ip4.addr = ipv4->src;

    pbuf = pbuf_alloc_reference(ipv4->payload, ipv4->payload_len, PBUF_ROM);
    tcp_input(pbuf, &interface->netif);
}

/**
 * bbl_tcp_ipv6_rx 
 * 
 * @param eth ethernet packet received
 * @param ipv6 ipv6 header received
 * @param interface receiving interface
 */
void
bbl_tcp_ipv6_rx(bbl_interface_s *interface, bbl_ethernet_header_t *eth, bbl_ipv6_t *ipv6) {
    struct pbuf *pbuf;
    UNUSED(eth);
    pbuf = pbuf_alloc_reference(ipv6->hdr, ipv6->len, PBUF_ROM);
    interface->netif.input(pbuf, &interface->netif);
}

/**
 * bbl_tcp_send 
 * 
 * @param tcp 
 * @param buf 
 * @param len
 * @return ERR_OK if successfull
 */
err_t
bbl_tcp_send(bbl_tcp_t *tcp, uint8_t *buf, uint16_t len) {

    if(tcp->tx.offset < tcp->tx.len) {
        /* There is still data to send */
        return ERR_INPROGRESS;
    }

    tcp->tx.buf = buf;
    tcp->tx.len = len;
    tcp->tx.offset = 0;

    if(tcp->state == BBL_TCP_STATE_IDLE) {
        bbl_tcp_sent_cb(tcp, tcp->pcb, 0);
    }
    return ERR_OK;
}

/**
 * Function of type netif_output_fn
 */
err_t 
bbl_tcp_netif_output_ipv4(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
    bbl_interface_s *interface = netif->state;
    bbl_ethernet_header_t eth = {0};

    UNUSED(ipaddr);

    eth.dst = interface->gateway_mac;
    eth.src = interface->mac;
    eth.vlan_outer = interface->vlan;
    eth.type = ETH_TYPE_IPV4;
    while(p) {
        eth.next = p->payload;
        eth.next_len = p->len;
        if(bbl_send_to_buffer(interface, &eth) != BBL_SEND_OK) {
            return ERR_IF;
        }
        interface->stats.tcp_tx++;
        p = p->next;
    }
    return ERR_OK;
}

/**
 * Function of type netif_output_ip6_fn
 */
err_t 
bbl_tcp_netif_output_ipv6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr) {
    bbl_tcp_t *tcp = netif->state;
    bbl_interface_s *interface = tcp->interface;
    bbl_ethernet_header_t eth = {0};

    UNUSED(ipaddr);

    eth.dst = interface->gateway_mac;
    eth.src = interface->mac;
    eth.vlan_outer = interface->vlan;
    eth.type = ETH_TYPE_IPV6;
    while(p) {
        eth.next = p->payload;
        eth.next_len = p->len;
        if(bbl_send_to_buffer(interface, &eth) != BBL_SEND_OK) {
            return ERR_IF;
        }
        interface->stats.tcp_tx++;
        p = p->next;
    }
    return ERR_OK;
}

err_t 
bbl_tcp_netif_init(struct netif *netif) {
    //bbl_interface_s *interface = netif->state;
    netif->output = bbl_tcp_netif_output_ipv4;
    netif->output_ip6 = bbl_tcp_netif_output_ipv6;
    //netif_set_link_up(netif);
    netif_set_up(netif);
    return ERR_OK;
}

/**
 * bbl_tcp_interface_init
 * 
 * Init TCP (LwIP) network interface.  
 * 
 * @param interface interface
 * @return return true if successfully
 */
bool
bbl_tcp_interface_init(bbl_interface_s *interface, bbl_network_config_s *network_config) {
    UNUSED(network_config);
    if(!netif_add(&interface->netif, NULL, NULL, NULL, interface, bbl_tcp_netif_init, ip_input))  {
        return false;
    }
    interface->netif.state = interface;
    interface->netif.mtu = 1492;
    interface->netif.mtu6 = 1492;
    return true;
}

void
bbl_tcp_timer(timer_s *timer) {
    bbl_ctx_s *ctx = timer->data;

    UNUSED(ctx);
    sys_check_timeouts();
}

/**
 * bbl_tcp_init
 * 
 * Init TCP (LwIP) and start global TCP timer job. 
 * 
 * @param ctx global context
 */
void
bbl_tcp_init(bbl_ctx_s *ctx) {

    lwip_init();

    /* Start TCP timer */
    timer_add_periodic(&ctx->timer_root, &ctx->tcp_timer, "TCP",
                        0, BBL_TCP_INTERVAL, ctx, &bbl_tcp_timer);
}