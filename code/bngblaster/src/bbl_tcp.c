/*
 * BNG Blaster (BBL) - TCP (lwIP)
 * 
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl_tcp.h"
#ifndef BNGBLASTER_TCP_DEBUG
#define BNGBLASTER_TCP_DEBUG 0
#endif

const char *
tcp_err_string(err_t err) {
    switch(err) {
        case ERR_OK: return "ok";
        case ERR_MEM: return "out of memory error";
        case ERR_BUF: return "buffer error";
        case ERR_TIMEOUT: return "timeout";
        case ERR_RTE: return "routing problem";
        case ERR_INPROGRESS: return "operation in progress";
        case ERR_VAL: return "illegal value";
        case ERR_WOULDBLOCK: return "operation would block";
        case ERR_USE: return "address in use";
        case ERR_ALREADY: return "already connecting";
        case ERR_ISCONN: return "already connected";
        case ERR_CONN: return "not connected";
        case ERR_IF: return "low-level netif error";
        case ERR_ABRT: return "connection aborted";
        case ERR_RST: return "connection reset";
        case ERR_CLSD: return "connection closed";
        case ERR_ARG: return "illegal argument";
        default: return "unknown error";
    }
}

/**
 * bbl_tcp_close 
 * 
 * This function closes the TCP session.
 * 
 * @param tcpc TCP context
 */
void
bbl_tcp_close(bbl_tcp_ctx_s *tcpc) {
    if(tcpc) {
        if(tcpc->pcb) {
            tcp_arg(tcpc->pcb, NULL);
            tcp_sent(tcpc->pcb, NULL);
            tcp_recv(tcpc->pcb, NULL);
            tcp_err(tcpc->pcb, NULL);
            tcp_poll(tcpc->pcb, NULL, 0);
            tcp_close(tcpc->pcb);
        }
        tcpc->state = BBL_TCP_STATE_CLOSED;
        tcpc->pcb = NULL;
    }
}

/**
 * bbl_tcp_ctx_free 
 * 
 * This function closes the TCP session (if active)
 * and free the TCP context memory. 
 * 
 * @param tcpc TCP context
 */
void
bbl_tcp_ctx_free(bbl_tcp_ctx_s *tcpc) {
    if(tcpc) {
        bbl_tcp_close(tcpc);
        free(tcpc);
    }
}

static bbl_tcp_ctx_s *
bbl_tcp_ctx_new(bbl_network_interface_s *interface) {
    
    bbl_tcp_ctx_s *tcp;

    /* Init TCP context */
    tcp = calloc(1, sizeof(bbl_tcp_ctx_s));
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
    bbl_tcp_ctx_s *tcpc = arg;
    uint16_t tx = tcp_sndbuf(tpcb);
    err_t result = ERR_OK;

    UNUSED(len);

    if(tcpc->tx.offset < tcpc->tx.len) {
        if(tx) {
            if((tcpc->tx.offset + tx) > tcpc->tx.len) {
                tx = tcpc->tx.len - tcpc->tx.offset;
            }
            result = tcp_write(tpcb, tcpc->tx.buf + tcpc->tx.offset, tx, tcpc->tx.flags);
            if(result == ERR_OK) {
                tcpc->state = BBL_TCP_STATE_SENDING;
                tcpc->tx.offset += tx;
            }
        } else {
            result = ERR_MEM;
        }
    } else if(tcpc->pcb->unacked == NULL && tcpc->pcb->unsent == NULL) {
        /* Idle means that it is save to replace buffer. */
        tcpc->state = BBL_TCP_STATE_IDLE;
        if(tcpc->idle_cb) {
            (tcpc->idle_cb)(tcpc->arg);
        }
    }

    if (result == ERR_MEM) {
        tcp_output(tpcb);
    }
    return result;
}

err_t 
bbl_tcp_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    bbl_tcp_ctx_s *tcpc = arg;
    struct pbuf *_p;

    if(p) {
        if(err == ERR_OK) {
            if(tcpc->receive_cb) {
                _p = p;
                while(_p) {
                    (tcpc->receive_cb)(tcpc->arg, p->payload, p->len);
                    _p = _p->next;
                }
                /* Signal application that read is finished. */
                (tcpc->receive_cb)(tcpc->arg, NULL, 0);
            }
            tcpc->bytes_rx += p->tot_len;
            tcp_recved(tpcb, p->tot_len);
        }
        pbuf_free(p);
    }
    return err;
}

/** 
 * Called when the pcb receives a RST or is unexpectedly closed for any other reason.
 *
 * @note The corresponding pcb is already freed when this callback is called!
 *
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param err Error code to indicate why the pcb has been closed
 *            ERR_ABRT: aborted through tcp_abort or by a TCP timer
 *            ERR_RST: the connection was reset by the remote host
 */
void 
bbl_tcp_error_cb(void *arg, err_t err) {
    bbl_tcp_ctx_s *tcpc = arg;
    tcpc->state = BBL_TCP_STATE_CLOSED;
    tcpc->pcb = NULL;
    tcpc->err = err;

    if(tcpc->af == AF_INET) {
        LOG(TCP, "TCP (%s %s:%u - %s:%u) error %d (%s)\n",
            tcpc->interface->name,
            format_ipv4_address(&tcpc->local_ipv4), tcpc->local_port,
            format_ipv4_address(&tcpc->remote_ipv4), tcpc->remote_port,
            err, tcp_err_string(err));
    } else {
        LOG(TCP, "TCP (%s %s:%u - %s:%u) error %d (%s)\n",
            tcpc->interface->name,
            format_ipv6_address(&tcpc->local_ipv6), tcpc->local_port,
            format_ipv6_address(&tcpc->remote_ipv6), tcpc->remote_port,
            err, tcp_err_string(err));
    }

    if(tcpc->error_cb) {
        (tcpc->error_cb)(tcpc->arg, err);
    }
}

/** 
 * Called periodically.
 *
 * @param arg Additional argument to pass to the callback function (@see tcp_arg())
 * @param tpcb tcp pcb
 * @return ERR_OK: try to send some data by calling tcp_output
 *         Only return ERR_ABRT if you have called tcp_abort from within the
 *         callback function!
 */
err_t
bbl_tcp_poll_cb(void *arg, struct tcp_pcb *tpcb) {
    bbl_tcp_ctx_s *tcpc = arg;
    if(tcpc->poll_cb) {
        return (tcpc->poll_cb)(tcpc->arg, tpcb);
    }
    return ERR_OK;
}

err_t 
bbl_tcp_connected(void *arg, struct tcp_pcb *tpcb, err_t err) {
    bbl_tcp_ctx_s *tcpc = arg;

    UNUSED(err); /* TODO!!! */

    /* Add send/receive callback functions. */
    tcp_sent(tpcb, bbl_tcp_sent_cb);
    tcp_recv(tpcb, bbl_tcp_recv_cb);
    if(tcpc->poll_cb && tcpc->poll_interval) {
        tcp_poll(tpcb, bbl_tcp_poll_cb, tcpc->poll_interval);
    }

    if(tcpc->af == AF_INET) {
        LOG(TCP, "TCP (%s %s:%u - %s:%u) session connected\n",
            tcpc->interface->name,
            format_ipv4_address(&tcpc->local_ipv4), tcpc->local_port,
            format_ipv4_address(&tcpc->remote_ipv4), tcpc->remote_port);
    } else {
        LOG(TCP, "TCP (%s %s:%u - %s:%u) session connected\n",
            tcpc->interface->name,
            format_ipv6_address(&tcpc->local_ipv6), tcpc->local_port,
            format_ipv6_address(&tcpc->remote_ipv6), tcpc->remote_port);
    }

    tcpc->state = BBL_TCP_STATE_IDLE;

    /* Call application TCP connected callback function. */
    if(tcpc->connected_cb) {
        (tcpc->connected_cb)(tcpc->arg);
    }
    bbl_tcp_sent_cb(tcpc, tpcb, 0);
    return ERR_OK;
}

/**
 * bbl_tcp_ipv4_connect 
 * 
 * @param interface interface
 * @param src source address
 * @param dst destination address
 * @param port destination port
 * @return TCP context
 */
bbl_tcp_ctx_s *
bbl_tcp_ipv4_connect(bbl_network_interface_s *interface, ipv4addr_t *src, ipv4addr_t *dst, uint16_t port) {

    bbl_tcp_ctx_s *tcpc;

    if(!g_ctx->tcp) {
        /* TCP not enabled! */
        return NULL;
    }

    tcpc = bbl_tcp_ctx_new(interface);
    if(!tcpc) {
        return NULL;
    }

    /* Bind local IP address and port */
    tcp_bind(tcpc->pcb, (const ip_addr_t*)src, 0);

    /* Disable nagle algorithm */
    tcp_nagle_disable(tcpc->pcb);

    /* Connect session */
    if(tcp_connect(tcpc->pcb, (const ip_addr_t*)dst, port, bbl_tcp_connected) != ERR_OK) {
        bbl_tcp_ctx_free(tcpc);
        return NULL;
    }
    tcp_err(tcpc->pcb, bbl_tcp_error_cb);

    tcpc->af = AF_INET;
    tcpc->local_port = tcpc->pcb->local_port;
    tcpc->remote_port = port;
    tcpc->local_ipv4 = *src;
    tcpc->remote_ipv4 = *dst;
    tcpc->pcb->local_ip.type = IPADDR_TYPE_V4;
    tcpc->pcb->remote_ip.type = IPADDR_TYPE_V4;
    tcpc->state = BBL_TCP_STATE_CONNECTING;
    LOG(TCP, "TCP (%s %s:%u - %s:%u) connect\n",
        interface->name,
        format_ipv4_address(&tcpc->local_ipv4), tcpc->local_port,
        format_ipv4_address(&tcpc->remote_ipv4), tcpc->remote_port);

    return tcpc;
}

/**
 * bbl_tcp_ipv4_rx 
 * 
 * @param eth ethernet packet received
 * @param ipv4 ipv4 header received
 * @param interface receiving interface
 */
void
bbl_tcp_ipv4_rx(bbl_network_interface_s *interface, bbl_ethernet_header_t *eth, bbl_ipv4_t *ipv4) {
    struct pbuf *pbuf;
    UNUSED(eth);

    if(!g_ctx->tcp) {
        /* TCP not enabled! */
        return;
    }

#if BNGBLASTER_TCP_DEBUG
    bbl_tcp_t *tcp = (bbl_tcp_t*)ipv4->next;
    LOG(DEBUG, "TCP (%s %s:%u - %s:%u) packet received\n",
        interface->name,
        format_ipv4_address(&ipv4->dst), tcp->dst,
        format_ipv4_address(&ipv4->src), tcp->src);
#endif

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
 * bbl_tcp_ipv6_connect 
 * 
 * @param interface interface
 * @param src source address
 * @param dst destination address
 * @param port destination port
 * @return TCP context
 */
bbl_tcp_ctx_s *
bbl_tcp_ipv6_connect(bbl_network_interface_s *interface, ipv6addr_t *src, ipv6addr_t *dst, uint16_t port) {

    if(!g_ctx->tcp) {
        /* TCP not enabled! */
        return NULL;
    }

    UNUSED(interface);
    UNUSED(src);
    UNUSED(dst);
    UNUSED(port);
    return NULL;
}

/**
 * bbl_tcp_ipv6_rx 
 * 
 * @param eth ethernet packet received
 * @param ipv6 ipv6 header received
 * @param interface receiving interface
 */
void
bbl_tcp_ipv6_rx(bbl_network_interface_s *interface, bbl_ethernet_header_t *eth, bbl_ipv6_t *ipv6) {
    struct pbuf *pbuf;
    UNUSED(eth);

    if(!g_ctx->tcp) {
        /* TCP not enabled! */
        return;
    }

#if BNGBLASTER_TCP_DEBUG
    bbl_tcp_t *tcp = (bbl_tcp_t*)ipv6->next;
    LOG(DEBUG, "TCP (%s %s:%u - %s:%u) packet received\n",
        interface->name,
        format_ipv6_address((ipv6addr_t*)ipv6->dst), tcp->dst,
        format_ipv6_address((ipv6addr_t*)ipv6->src), tcp->src);
#endif

    pbuf = pbuf_alloc_reference(ipv6->hdr, ipv6->len, PBUF_ROM);
    interface->netif.input(pbuf, &interface->netif);
}

/**
 * bbl_tcp_send 
 * 
 * @param tcp 
 * @param buf 
 * @param len
 * @return true if successful
 */
bool
bbl_tcp_send(bbl_tcp_ctx_s *tcpc, uint8_t *buf, uint32_t len) {

    if(tcpc->state == BBL_TCP_STATE_SENDING) {
        return false;
    }

    tcpc->tx.buf = buf;
    tcpc->tx.len = len;
    tcpc->tx.offset = 0;

    if(tcpc->state == BBL_TCP_STATE_IDLE) {
        bbl_tcp_sent_cb(tcpc, tcpc->pcb, 0);
    }
    return true;
}

/**
 * Function of type netif_output_fn
 */
err_t 
bbl_tcp_netif_output_ipv4(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr) {
    bbl_network_interface_s *interface = netif->state;
    bbl_ethernet_header_t eth = {0};
    UNUSED(ipaddr);

    eth.dst = interface->gateway_mac;
    eth.src = interface->mac;
    eth.vlan_outer = interface->vlan;
    eth.type = ETH_TYPE_IPV4;
    eth.lwip = true;
    eth.next = p;
    if(bbl_txq_to_buffer(interface->txq, &eth) != BBL_TXQ_OK) {
        return ERR_IF;
    }
    interface->stats.tcp_tx++;
    return ERR_OK;
}

/**
 * Function of type netif_output_ip6_fn
 */
err_t 
bbl_tcp_netif_output_ipv6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr) {
    bbl_tcp_ctx_s *tcpc = netif->state;
    bbl_network_interface_s *interface = tcpc->interface;
    bbl_ethernet_header_t eth = {0};
    UNUSED(ipaddr);

    eth.dst = interface->gateway_mac;
    eth.src = interface->mac;
    eth.vlan_outer = interface->vlan;
    eth.type = ETH_TYPE_IPV6;
    eth.lwip = true;
    eth.next = p;
    if(bbl_txq_to_buffer(interface->txq, &eth) != BBL_TXQ_OK) {
        return ERR_IF;
    }
    interface->stats.tcp_tx++;
    return ERR_OK;
}

err_t 
bbl_tcp_netif_init(struct netif *netif) {
    netif->output = bbl_tcp_netif_output_ipv4;
    netif->output_ip6 = bbl_tcp_netif_output_ipv6;
    netif_set_up(netif);
    return ERR_OK;
}

/**
 * bbl_tcp_network_interface_init
 * 
 * Init TCP (LwIP) network interface.  
 * 
 * @param interface network interface
 * @param config network interface configuration
 * @return return true if successfully
 */
bool
bbl_tcp_network_interface_init(bbl_network_interface_s *interface, bbl_network_config_s *config) {
    if(!g_ctx->tcp) {
        /* TCP not enabled! */
        return true;
    }
    if(!netif_add(&interface->netif, NULL, NULL, NULL, interface, bbl_tcp_netif_init, ip_input))  {
        return false;
    }
    interface->netif.state = interface;
    interface->netif.mtu = config->mtu;
    interface->netif.mtu6 = config->mtu;
    return true;
}

void
bbl_tcp_timer(timer_s *timer) {
    UNUSED(timer);
    sys_check_timeouts();
}

/**
 * bbl_tcp_init
 * 
 * Init TCP (LwIP) and start global TCP timer job. 
 */
void
bbl_tcp_init() {
    if(!g_ctx->tcp) {
        /* TCP not enabled! */
        return;
    }

    lwip_init();

    /* Start TCP timer */
    timer_add_periodic(&g_ctx->timer_root, &g_ctx->tcp_timer, "TCP",
                       0, BBL_TCP_INTERVAL, g_ctx, &bbl_tcp_timer);
}