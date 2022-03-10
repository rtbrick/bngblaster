/*
 * BNG Blaster (BBL) - LwIP
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl_tcp.h"

static void
bbl_tcp_ctx_free(bbl_tcp_ctx_t *tcp) {
    if(tcp) {
        if(tcp->pcb) {
            tcp_close(tcp->pcb);
        }
        free(tcp);
    }
}

static bbl_tcp_ctx_t *
bbl_tcp_ctx_new(bbl_interface_s *interface) {
    
    bbl_tcp_ctx_t *tcp;

    /* Init TCP context */
    tcp = calloc(1, sizeof(bbl_tcp_ctx_t));
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
    bbl_tcp_ctx_t *tcpc = arg;
    uint16_t tx = tpcb->snd_buf;
    uint8_t flags = 0; /* no-copy (alternative TCP_WRITE_FLAG_COPY) */

    UNUSED(len);

    if(tcpc->tx.offset < tcpc->tx.len) {
        tcpc->state = BBL_TCP_STATE_SEND;
        if((tcpc->tx.offset + tx) > tcpc->tx.len) {
            tx = tcpc->tx.len - tcpc->tx.offset;
        }
/* Enable the following code to suppress PSH flag 
 * if buffer was not dequeued completely. 
 *
 * if((tcpc->tx.offset + tx) < tcpc->tx.len) {
 *     flags |= TCP_WRITE_FLAG_MORE;
 * }
 */
        if(tcp_write(tpcb, tcpc->tx.buf + tcpc->tx.offset, tx, flags) == ERR_OK) {
            tcpc->tx.offset += tx;
            if(tcpc->af == AF_INET) {
                LOG(TCP_DETAIL, "TCP %u bytes send (%s %s:%u - %s:%u)\n",
                    tx, tcpc->interface->name,
                    format_ipv4_address(&tcpc->local_ipv4), tcpc->key.local_port,
                    format_ipv4_address(&tcpc->remote_ipv4), tcpc->key.remote_port);
            }
        }
    }
    return ERR_OK;
}

err_t 
bbl_tcp_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    bbl_tcp_ctx_t *tcpc = arg;
    struct pbuf *_p;

    UNUSED(err); /* TODO!!! */

    if(p) {
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
        pbuf_free(p);
        if(tcpc->af == AF_INET) {
            LOG(TCP_DETAIL, "TCP %u bytes received (%s %s:%u - %s:%u)\n",
                p->tot_len, tcpc->interface->name,
                format_ipv4_address(&tcpc->local_ipv4), tcpc->key.local_port,
                format_ipv4_address(&tcpc->remote_ipv4), tcpc->key.remote_port);
        }
    }
    return ERR_OK;
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
    bbl_tcp_ctx_t *tcpc = arg;

    if(tcpc->af == AF_INET) {
        LOG(TCP, "TCP error %u (%s %s:%u - %s:%u)\n",
            err, tcpc->interface->name,
            format_ipv4_address(&tcpc->local_ipv4), tcpc->key.local_port,
            format_ipv4_address(&tcpc->remote_ipv4), tcpc->key.remote_port);
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
    bbl_tcp_ctx_t *tcpc = arg;
    if(tcpc->poll_cb) {
        return (tcpc->poll_cb)(tcpc->arg, tpcb);
    }
    return ERR_OK;
}

err_t 
bbl_tcp_connected(void *arg, struct tcp_pcb *tpcb, err_t err) {
    bbl_tcp_ctx_t *tcpc = arg;

    UNUSED(err); /* TODO!!! */

    /* Add send/receive callback functions. */
    tcp_sent(tpcb, bbl_tcp_sent_cb);
    tcp_recv(tpcb, bbl_tcp_recv_cb);
    tcp_err(tpcb, bbl_tcp_error_cb);
    if(tcpc->poll_cb && tcpc->poll_interval) {
        tcp_poll(tpcb, bbl_tcp_poll_cb, tcpc->poll_interval);
    }

    if(tcpc->af == AF_INET) {
        LOG(TCP_DETAIL, "TCP session connected (%s %s:%u - %s:%u)\n",
            tcpc->interface->name,
            format_ipv4_address(&tcpc->local_ipv4), tcpc->key.local_port,
            format_ipv4_address(&tcpc->remote_ipv4), tcpc->key.remote_port);
    }

    tcpc->state = BBL_TCP_STATE_IDLE;
    if(tcpc->connected_cb) {
        (tcpc->connected_cb)(tcpc->arg);
    }
    bbl_tcp_sent_cb(tcpc, tpcb, 0);
    return ERR_OK;
}

void
bbl_tcp_close(bbl_tcp_ctx_t *tcpc) {
    dict_remove(tcpc->interface->tcp_connections, &tcpc->key);
    bbl_tcp_ctx_free(tcpc);
}

/**
 * bbl_tcp_ipv4_connect 
 * 
 * @param interface interface
 * @param src source address
 * @param dst destination address
 * @param port destination port
 * @return bbl_tcp_ctx_t * 
 */
bbl_tcp_ctx_t *
bbl_tcp_ipv4_connect(bbl_interface_s *interface, ipv4addr_t *src, ipv4addr_t *dst, uint16_t port) {

    bbl_tcp_ctx_t *tcpc;
    dict_insert_result result;

    if(!interface->ctx->tcp) {
        /* TCP not enabled! */
        return NULL;
    }

    tcpc = bbl_tcp_ctx_new(interface);
    if(!tcpc) {
        return NULL;
    }

    /* Bind local IP address and port */
    tcp_bind(tcpc->pcb, (const ip_addr_t*)src, 0);

    /* Connect session */
    if(tcp_connect(tcpc->pcb, (const ip_addr_t*)dst, port, bbl_tcp_connected) != ERR_OK) {
        bbl_tcp_ctx_free(tcpc);
        return NULL;
    }

    tcpc->af = AF_INET;
    tcpc->key.local_port = tcpc->pcb->local_port;
    tcpc->key.remote_port = port;
    tcpc->local_ipv4 = *src;
    tcpc->remote_ipv4 = *dst;

    /* Add BBL TCP context to interface */
    result = dict_insert(interface->tcp_connections, &tcpc->key);
    if (!result.inserted) {
        bbl_tcp_ctx_free(tcpc);
        return NULL;
    }

    /* TODO: This looks wrong but is required. 
     * Further investigations needed! */
    tcpc->pcb->local_ip.type = IPADDR_TYPE_V4;
    tcpc->pcb->remote_ip.type = IPADDR_TYPE_V4;

    LOG(TCP, "TCP connect (%s %s:%u - %s:%u)\n",
        interface->name,
        format_ipv4_address(&tcpc->local_ipv4), tcpc->key.local_port,
        format_ipv4_address(&tcpc->remote_ipv4), tcpc->key.remote_port);

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
bbl_tcp_ipv4_rx(bbl_interface_s *interface, bbl_ethernet_header_t *eth, bbl_ipv4_t *ipv4) {
    struct pbuf *pbuf;
    bbl_tcp_t *tcp = (bbl_tcp_t*)ipv4->next;

    UNUSED(eth);

    if(!interface->ctx->tcp) {
        /* TCP not enabled! */
        return;
    }

    LOG(TCP_DETAIL, "TCP packet received (%s %s:%u - %s:%u)\n",
        interface->name,
        format_ipv4_address(&ipv4->dst), tcp->dst,
        format_ipv4_address(&ipv4->src), tcp->src);

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
 * @return bbl_tcp_ctx_t * 
 */
bbl_tcp_ctx_t *
bbl_tcp_ipv6_connect(bbl_interface_s *interface, ipv6addr_t *src, ipv6addr_t *dst, uint16_t port) {

    if(!interface->ctx->tcp) {
        /* TCP not enabled! */
        return NULL;
    }

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
bbl_tcp_ipv6_rx(bbl_interface_s *interface, bbl_ethernet_header_t *eth, bbl_ipv6_t *ipv6) {
    struct pbuf *pbuf;
    bbl_tcp_t *tcp = (bbl_tcp_t*)ipv6->next;

    UNUSED(eth);

    if(!interface->ctx->tcp) {
        /* TCP not enabled! */
        return;
    }

    LOG(TCP_DETAIL, "TCP packet received (%s %s:%u - %s:%u)\n",
        interface->name,
        format_ipv6_address((ipv6addr_t*)ipv6->dst), tcp->dst,
        format_ipv6_address((ipv6addr_t*)ipv6->src), tcp->src);

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
bbl_tcp_send(bbl_tcp_ctx_t *tcpc, uint8_t *buf, uint32_t len) {

    if(tcpc->tx.offset < tcpc->tx.len) {
        /* There is still data to send */
        return ERR_INPROGRESS;
    }

    tcpc->tx.buf = buf;
    tcpc->tx.len = len;
    tcpc->tx.offset = 0;

    if(tcpc->state == BBL_TCP_STATE_IDLE) {
        bbl_tcp_sent_cb(tcpc, tcpc->pcb, 0);
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
    eth.lwip = true;
    eth.next = p;
    if(bbl_send_to_buffer(interface, &eth) != BBL_SEND_OK) {
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
    bbl_tcp_ctx_t *tcpc = netif->state;
    bbl_interface_s *interface = tcpc->interface;
    bbl_ethernet_header_t eth = {0};
    UNUSED(ipaddr);

    eth.dst = interface->gateway_mac;
    eth.src = interface->mac;
    eth.vlan_outer = interface->vlan;
    eth.type = ETH_TYPE_IPV6;
    eth.lwip = true;
    eth.next = p;
    if(bbl_send_to_buffer(interface, &eth) != BBL_SEND_OK) {
        return ERR_IF;
    }
    interface->stats.tcp_tx++;
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

    if(!interface->ctx->tcp) return true;

    if(!netif_add(&interface->netif, NULL, NULL, NULL, interface, bbl_tcp_netif_init, ip_input))  {
        return false;
    }
    interface->netif.state = interface;
    interface->netif.mtu = network_config->mtu;
    interface->netif.mtu6 = network_config->mtu;
    interface->tcp_connections = hashtable_dict_new((dict_compare_func)bbl_compare_key32, bbl_key32_hash, BBL_TCP_HASHTABLE_SIZE);

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

    if(!ctx->tcp) {
        /* TCP not enabled! */
        return;
    }

    lwip_init();

    /* Start TCP timer */
    timer_add_periodic(&ctx->timer_root, &ctx->tcp_timer, "TCP",
                       0, BBL_TCP_INTERVAL, ctx, &bbl_tcp_timer);
}