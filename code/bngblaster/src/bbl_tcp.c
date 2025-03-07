/*
 * BNG Blaster (BBL) - TCP (lwIP)
 * 
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl_tcp.h"
#ifndef BNGBLASTER_TCP_DEBUG
#define BNGBLASTER_TCP_DEBUG 0
#endif

size_t g_netif_count = 0;

const char *
tcp_err_string(err_t err)
{
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
bbl_tcp_close(bbl_tcp_ctx_s *tcpc)
{
    if(tcpc) {
        if(tcpc->pcb) {
            if(!tcpc->listen) {
                tcp_arg(tcpc->pcb, NULL);
                tcp_sent(tcpc->pcb, NULL);
                tcp_recv(tcpc->pcb, NULL);
                tcp_err(tcpc->pcb, NULL);
                tcp_poll(tcpc->pcb, NULL, 0);
            }
            tcp_close(tcpc->pcb);
        }
        if(tcpc->sp) {
            free(tcpc->sp);
            tcpc->sp = NULL;
            tcpc->sp_len = 0;
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
        if(tcpc->ifname) {
            free(tcpc->ifname);
            tcpc->ifname = NULL;
        }
        bbl_tcp_close(tcpc);
        free(tcpc);
    }
}

static bbl_tcp_ctx_s *
bbl_tcp_ctx_new(bbl_network_interface_s *interface)
{
    bbl_tcp_ctx_s *tcpc;

    /* Init TCP context */
    tcpc = calloc(1, sizeof(bbl_tcp_ctx_s));
    if(!tcpc) {
        return NULL;
    }
    tcpc->interface = interface;

    /* Init TCP PCB */
    tcpc->pcb = tcp_new();
    if(!tcpc->pcb) {
        free(tcpc);
        return NULL;
    }

    /* Bind local network interface */
    tcp_bind_netif(tcpc->pcb, &interface->netif);
    
    /* Add BBL TCP context as argument */
    tcp_arg(tcpc->pcb, tcpc);

    tcpc->ifname = strdup(interface->name);
    return tcpc;
}

static bbl_tcp_ctx_s *
bbl_tcp_ctx_new_session(bbl_session_s *session)
{
    bbl_tcp_ctx_s *tcpc;
    static char s[sizeof("ID: 999999999")] = {0};

    /* Init TCP context */
    tcpc = calloc(1, sizeof(bbl_tcp_ctx_s));
    if(!tcpc) {
        return NULL;
    }
    tcpc->session = session;

    /* Init TCP PCB */
    tcpc->pcb = tcp_new();
    if(!tcpc->pcb) {
        free(tcpc);
        return NULL;
    }

    /* Bind local network interface */
    tcp_bind_netif(tcpc->pcb, &session->netif);
    
    /* Add BBL TCP context as argument */
    tcp_arg(tcpc->pcb, tcpc);

    sprintf(s, "ID: %u", session->session_id);
    tcpc->ifname = strdup(s);
    return tcpc;
}

err_t 
bbl_tcp_sent_cb(void *arg, struct tcp_pcb *tpcb, u16_t len)
{
    bbl_tcp_ctx_s *tcpc = arg;
    uint16_t tx;
    err_t result = ERR_OK;

    UNUSED(len);

    if(tcpc->tx.offset < tcpc->tx.len) {
        tx = tcp_sndbuf(tpcb);
        if(tx) {
            if(tx > 4096) tx = 4096;
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

    if(result == ERR_MEM) {
        tcp_output(tpcb);
    }
    return result;
}

err_t 
bbl_tcp_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
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
bbl_tcp_error_cb(void *arg, err_t err)
{
    bbl_tcp_ctx_s *tcpc = arg;
    tcpc->state = BBL_TCP_STATE_CLOSED;
    tcpc->pcb = NULL;
    tcpc->err = err;

    if(tcpc->af == AF_INET) {
        LOG(TCP, "TCP (%s %s:%u - %s:%u) error %d (%s)\n",
            tcpc->ifname,
            format_ipv4_address(&tcpc->local_addr.u_addr.ip4.addr), tcpc->local_port,
            format_ipv4_address(&tcpc->remote_addr.u_addr.ip4.addr), tcpc->remote_port,
            err, tcp_err_string(err));
    } else {
        LOG(TCP, "TCP (%s [%s]:%u - [%s]:%u) error %d (%s)\n",
            tcpc->ifname,
            format_ipv6_address((ipv6addr_t*)&tcpc->local_addr.u_addr.ip6.addr), tcpc->local_port,
            format_ipv6_address((ipv6addr_t*)&tcpc->local_addr.u_addr.ip6.addr), tcpc->remote_port,
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
bbl_tcp_poll_cb(void *arg, struct tcp_pcb *tpcb)
{
    bbl_tcp_ctx_s *tcpc = arg;
    if(tcpc->poll_cb) {
        return (tcpc->poll_cb)(tcpc->arg, tpcb);
    }
    return ERR_OK;
}

err_t 
bbl_tcp_connected(void *arg, struct tcp_pcb *tpcb, err_t err)
{
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
            tcpc->ifname,
            format_ipv4_address(&tcpc->local_addr.u_addr.ip4.addr), tcpc->local_port,
            format_ipv4_address(&tcpc->remote_addr.u_addr.ip4.addr), tcpc->remote_port);
    } else {
        LOG(TCP, "TCP (%s [%s]:%u - [%s]:%u) session connected\n",
            tcpc->ifname,
            format_ipv6_address((ipv6addr_t*)&tcpc->local_addr.u_addr.ip6.addr), tcpc->local_port,
            format_ipv6_address((ipv6addr_t*)&tcpc->remote_addr.u_addr.ip6.addr), tcpc->remote_port);
    }

    tcpc->state = BBL_TCP_STATE_IDLE;

    /* Call application TCP connected callback function. */
    if(tcpc->connected_cb) {
        (tcpc->connected_cb)(tcpc->arg);
    }
    bbl_tcp_sent_cb(tcpc, tpcb, 0);
    return ERR_OK;
}

err_t
bbl_tcp_listen_accepted(void *arg, struct tcp_pcb *tpcb, err_t err)
{
    bbl_tcp_ctx_s *listen = arg;
    bbl_tcp_ctx_s *tcpc;

    if(tpcb == NULL || err != ERR_OK) {
        if(listen->af == AF_INET) {
            LOG(TCP, "TCP (%s %s:%u) listen accepted failed with error %d (%s)\n",
                listen->ifname,
                format_ipv4_address(&listen->local_addr.u_addr.ip4.addr), 
                listen->local_port,
                err, tcp_err_string(err));

        } else {
            LOG(TCP, "TCP (%s %s:%u) listen accepted failed with error %d (%s)\n",
                listen->ifname,
                format_ipv6_address((ipv6addr_t*)&listen->local_addr.u_addr.ip6.addr),
                listen->local_port,
                err, tcp_err_string(err));
        }
        return ERR_RST;
    }

    tcpc = calloc(1, sizeof(bbl_tcp_ctx_s));
    if(!tcpc) {
        return ERR_MEM;
    }
    tcpc->ifname = strdup(listen->ifname);
    tcpc->interface = listen->interface;
    tcpc->af = listen->af;
    tcpc->local_port = listen->local_port;
    tcpc->remote_port = tpcb->remote_port;

    tcpc->accepted_cb = listen->accepted_cb;
    tcpc->connected_cb = listen->connected_cb;
    tcpc->idle_cb = listen->idle_cb;
    tcpc->receive_cb = listen->receive_cb;
    tcpc->error_cb = listen->error_cb;
    tcpc->poll_cb = listen->poll_cb;
    tcpc->poll_interval = listen->poll_interval;
    tcpc->arg = listen->arg;

    /* Copy TTL and TOS from listen socket. */
    if(listen->pcb) {
        if(listen->pcb->ttl) {
            tpcb->ttl = listen->pcb->ttl;
        }
        tpcb->tos = listen->pcb->tos;
    }

    tcpc->pcb = tpcb;
    tcp_arg(tpcb, tcpc);

    /* Add send/receive callback functions. */
    tcp_sent(tpcb, bbl_tcp_sent_cb);
    tcp_recv(tpcb, bbl_tcp_recv_cb);
    if(tcpc->poll_cb && tcpc->poll_interval) {
        tcp_poll(tpcb, bbl_tcp_poll_cb, tcpc->poll_interval);
    }
    tcp_err(tpcb, bbl_tcp_error_cb);

    if(tcpc->af == AF_INET) {
        tcpc->local_addr.u_addr.ip4.addr = tpcb->local_ip.u_addr.ip4.addr;
        tcpc->remote_addr.u_addr.ip4.addr = tpcb->remote_ip.u_addr.ip4.addr;
        LOG(TCP, "TCP (%s %s:%u - %s:%u) session accepted\n",
            tcpc->ifname,
            format_ipv4_address(&tcpc->local_addr.u_addr.ip4.addr), tcpc->local_port,
            format_ipv4_address(&tcpc->remote_addr.u_addr.ip4.addr), tcpc->remote_port);
    } else {
        memcpy(&tcpc->local_addr.u_addr.ip6.addr, &tpcb->local_ip.u_addr.ip6.addr, IPV6_ADDR_LEN);
        memcpy(&tcpc->remote_addr.u_addr.ip6.addr, &tpcb->remote_ip.u_addr.ip6.addr, IPV6_ADDR_LEN);
        LOG(TCP, "TCP (%s [%s]:%u - [%s]:%u) session accepted\n",
            tcpc->ifname,
            format_ipv6_address((ipv6addr_t*)&tcpc->local_addr.u_addr.ip6.addr), tcpc->local_port,
            format_ipv6_address((ipv6addr_t*)&tcpc->remote_addr.u_addr.ip6.addr), tcpc->remote_port);
    }

    /* Call application TCP accepted callback function. */
    if(listen->accepted_cb) {
        if((listen->accepted_cb)(tcpc, listen->arg) != ERR_OK) {
            tcp_abort(tpcb);
            return ERR_ABRT;
        };
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
 * bbl_tcp_ipv4_listen 
 * 
 * @param interface interface
 * @param address local address
 * @param port local port
 * @param ttl TTL
 * @param tos TOS
 * @return TCP context
 */
bbl_tcp_ctx_s *
bbl_tcp_ipv4_listen(bbl_network_interface_s *interface, ipv4addr_t *address,
                     uint16_t port, uint8_t ttl, uint8_t tos)
{
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
    tcpc->local_addr.u_addr.ip4.addr = *address;
    if(tcp_bind(tcpc->pcb, &tcpc->local_addr, port) != ERR_OK) {
        bbl_tcp_ctx_free(tcpc);
        return NULL;
    }

    tcpc->pcb = tcp_listen(tcpc->pcb);
    if(!tcpc->pcb) {
        bbl_tcp_ctx_free(tcpc);
        return NULL;
    }

    tcp_accept(tcpc->pcb, bbl_tcp_listen_accepted);

    tcpc->listen = true;
    tcpc->af = AF_INET;
    tcpc->local_port = port;
    tcpc->pcb->local_ip.type = IPADDR_TYPE_V4;
    tcpc->pcb->remote_ip.type = IPADDR_TYPE_V4;
    if(ttl) {
        tcpc->pcb->ttl = ttl;
    }
    tcpc->pcb->tos = tos;
    tcpc->state = BBL_TCP_STATE_LISTEN;
    LOG(TCP, "TCP (%s %s:%u) listen\n",
        tcpc->ifname,
        format_ipv4_address(&tcpc->local_addr.u_addr.ip4.addr), 
        tcpc->local_port);

    return tcpc;
}

/**
 * bbl_tcp_ipv6_listen 
 * 
 * @param interface interface
 * @param address local address
 * @param port local port
 * @param ttl TTL
 * @param tos TOS
 * @return TCP context
 */
bbl_tcp_ctx_s *
bbl_tcp_ipv6_listen(bbl_network_interface_s *interface, ipv6addr_t *address,
                     uint16_t port, uint8_t ttl, uint8_t tos)
{
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
    memcpy(&tcpc->local_addr.u_addr.ip6.addr, address, sizeof(ip6_addr_t));
    tcpc->local_addr.type = IPADDR_TYPE_V6;
    if(tcp_bind(tcpc->pcb, &tcpc->local_addr, port) != ERR_OK) {
        bbl_tcp_ctx_free(tcpc);
        return NULL;
    }

    tcpc->pcb = tcp_listen(tcpc->pcb);
    if(!tcpc->pcb) {
        bbl_tcp_ctx_free(tcpc);
        return NULL;
    }

    tcp_accept(tcpc->pcb, bbl_tcp_listen_accepted);

    tcpc->listen = true;
    tcpc->af = AF_INET6;
    tcpc->local_port = port;
    tcpc->remote_addr.type = IPADDR_TYPE_V6;
    tcpc->pcb->local_ip.type = IPADDR_TYPE_V6;
    tcpc->pcb->remote_ip.type = IPADDR_TYPE_V6;
    if(ttl) {
        tcpc->pcb->ttl = ttl;
    }
    tcpc->pcb->tos = tos;
    tcpc->state = BBL_TCP_STATE_LISTEN;
    LOG(TCP, "TCP (%s %s:%u) listen\n",
        tcpc->ifname,
        format_ipv6_address((ipv6addr_t*)&tcpc->local_addr.u_addr.ip6.addr), 
        tcpc->local_port);

    return tcpc;
}

/**
 * bbl_tcp_ipv4_connect 
 * 
 * @param interface interface
 * @param src source address
 * @param dst destination address
 * @param port destination port
 * @param ttl TTL
 * @param tos TOS
 * @return TCP context
 */
bbl_tcp_ctx_s *
bbl_tcp_ipv4_connect(bbl_network_interface_s *interface, ipv4addr_t *src, ipv4addr_t *dst, 
                     uint16_t port, uint8_t ttl, uint8_t tos)
{
    bbl_tcp_ctx_s *tcpc;
    err_t err = ERR_OK;

    if(!g_ctx->tcp) {
        /* TCP not enabled! */
        return NULL;
    }

    tcpc = bbl_tcp_ctx_new(interface);
    if(!tcpc) {
        return NULL;
    }

    /* Bind local IP address and port */
    tcpc->local_addr.u_addr.ip4.addr = *src;
    tcp_bind(tcpc->pcb, &tcpc->local_addr, 0);

    /* Disable nagle algorithm */
    tcp_nagle_disable(tcpc->pcb);

    /* Set TTL and TOS */
    if(ttl) {
        tcpc->pcb->ttl = ttl;
    }
    tcpc->pcb->tos = tos;

    /* Connect session */
    tcpc->remote_addr.u_addr.ip4.addr = *dst;
    err = tcp_connect(tcpc->pcb, &tcpc->remote_addr, port, bbl_tcp_connected);
    if(err != ERR_OK) {
        LOG(TCP, "TCP (%s %s:%u - %s:%u) connect error %d (%s)\n",
            tcpc->ifname,
            format_ipv4_address(&tcpc->local_addr.u_addr.ip4.addr), 
            tcpc->local_port,
            format_ipv4_address(&tcpc->remote_addr.u_addr.ip4.addr),
            port,
            err, tcp_err_string(err));

        bbl_tcp_ctx_free(tcpc);
        return NULL;
    }
    tcp_err(tcpc->pcb, bbl_tcp_error_cb);

    tcpc->af = AF_INET;
    tcpc->local_port = tcpc->pcb->local_port;
    tcpc->remote_port = port;
    tcpc->pcb->local_ip.type = IPADDR_TYPE_V4;
    tcpc->pcb->remote_ip.type = IPADDR_TYPE_V4;
    tcpc->state = BBL_TCP_STATE_CONNECTING;
    LOG(TCP, "TCP (%s %s:%u - %s:%u) connect\n",
        tcpc->ifname,
        format_ipv4_address(&tcpc->local_addr.u_addr.ip4.addr), 
        tcpc->local_port,
        format_ipv4_address(&tcpc->remote_addr.u_addr.ip4.addr),
        tcpc->remote_port);

    return tcpc;
}

/**
 * bbl_tcp_ipv4_connect_session 
 * 
 * @param session session
 * @param src source address
 * @param dst destination address
 * @param port destination port
 * @return TCP context
 */
bbl_tcp_ctx_s *
bbl_tcp_ipv4_connect_session(bbl_session_s *session, ipv4addr_t *src, ipv4addr_t *dst, 
                             uint16_t port)
{
    bbl_tcp_ctx_s *tcpc;
    err_t err = ERR_OK;

    if(!g_ctx->tcp) {
        /* TCP not enabled! */
        return NULL;
    }

    tcpc = bbl_tcp_ctx_new_session(session);
    if(!tcpc) {
        return NULL;
    }

    if(!src) {
        src = &session->ip_address;
    }

    /* Bind local IP address and port */
    tcpc->local_addr.u_addr.ip4.addr = *src;
    tcp_bind(tcpc->pcb, &tcpc->local_addr, 0);

    /* Disable nagle algorithm */
    tcp_nagle_disable(tcpc->pcb);

    /* Connect session */
    tcpc->remote_addr.u_addr.ip4.addr = *dst;
    err = tcp_connect(tcpc->pcb, &tcpc->remote_addr, port, bbl_tcp_connected);
    if(err != ERR_OK) {
        LOG(TCP, "TCP (%s %s:%u - %s:%u) connect error %d (%s)\n",
            tcpc->ifname,
            format_ipv4_address(&tcpc->local_addr.u_addr.ip4.addr), 
            tcpc->local_port,
            format_ipv4_address(&tcpc->remote_addr.u_addr.ip4.addr),
            port,
            err, tcp_err_string(err));

        bbl_tcp_ctx_free(tcpc);
        return NULL;
    }
    tcp_err(tcpc->pcb, bbl_tcp_error_cb);

    tcpc->af = AF_INET;
    tcpc->local_port = tcpc->pcb->local_port;
    tcpc->remote_port = port;
    tcpc->pcb->local_ip.type = IPADDR_TYPE_V4;
    tcpc->pcb->remote_ip.type = IPADDR_TYPE_V4;
    tcpc->state = BBL_TCP_STATE_CONNECTING;
    LOG(TCP, "TCP (%s %s:%u - %s:%u) connect\n",
        tcpc->ifname,
        format_ipv4_address(&tcpc->local_addr.u_addr.ip4.addr), 
        tcpc->local_port,
        format_ipv4_address(&tcpc->remote_addr.u_addr.ip4.addr),
        tcpc->remote_port);

    return tcpc;
}

/**
 * bbl_tcp_ipv6_connect 
 * 
 * @param interface interface
 * @param src source address
 * @param dst destination address
 * @param port destination port
 * @param ttl TTL
 * @param tos TOS
 * @return TCP context
 */
bbl_tcp_ctx_s *
bbl_tcp_ipv6_connect(bbl_network_interface_s *interface, ipv6addr_t *src, ipv6addr_t *dst,
                     uint16_t port, uint8_t ttl, uint8_t tos)
{
    bbl_tcp_ctx_s *tcpc;
    err_t err = ERR_OK;

    if(!g_ctx->tcp) {
        /* TCP not enabled! */
        return NULL;
    }

    tcpc = bbl_tcp_ctx_new(interface);
    if(!tcpc) {
        return NULL;
    }

    /* Bind local IP address and port */
    memcpy(&tcpc->local_addr.u_addr.ip6.addr, src, sizeof(ip6_addr_t));
    tcpc->local_addr.type = IPADDR_TYPE_V6;
    tcp_bind(tcpc->pcb, &tcpc->local_addr, 0);

    /* Disable nagle algorithm */
    tcp_nagle_disable(tcpc->pcb);

    /* Set TTL and TOS */
    if(ttl) {
        tcpc->pcb->ttl = ttl;
    }
    tcpc->pcb->tos = tos;

    /* Connect session */
    memcpy(&tcpc->remote_addr.u_addr.ip6.addr, dst, sizeof(ip6_addr_t));
    tcpc->remote_addr.type = IPADDR_TYPE_V6;
    err = tcp_connect(tcpc->pcb, &tcpc->remote_addr, port, bbl_tcp_connected);
    if(err != ERR_OK) {
        LOG(TCP, "TCP (%s [%s]:%u - [%s]:%u) connect error %d (%s)\n",
            tcpc->ifname,
            format_ipv6_address((ipv6addr_t*)&tcpc->local_addr.u_addr.ip6.addr), 
            tcpc->local_port,
            format_ipv6_address((ipv6addr_t*)&tcpc->remote_addr.u_addr.ip6.addr),
            port,
            err, tcp_err_string(err));

        bbl_tcp_ctx_free(tcpc);
        return NULL;
    }
    tcp_err(tcpc->pcb, bbl_tcp_error_cb);

    tcpc->af = AF_INET6;
    tcpc->local_port = tcpc->pcb->local_port;
    tcpc->remote_port = port;
    tcpc->pcb->local_ip.type = IPADDR_TYPE_V6;
    tcpc->pcb->remote_ip.type = IPADDR_TYPE_V6;
    tcpc->state = BBL_TCP_STATE_CONNECTING;
    LOG(TCP, "TCP (%s [%s]:%u - [%s]:%u) connect\n",
        tcpc->ifname,
        format_ipv6_address((ipv6addr_t*)&tcpc->local_addr.u_addr.ip6.addr), 
        tcpc->local_port,
        format_ipv6_address((ipv6addr_t*)&tcpc->remote_addr.u_addr.ip6.addr),
        tcpc->remote_port);

    return tcpc;
}

/**
 * bbl_tcp_ipv6_connect_session 
 * 
 * @param session session
 * @param src source address
 * @param dst destination address
 * @param port destination port
 * @return TCP context
 */
bbl_tcp_ctx_s *
bbl_tcp_ipv6_connect_session(bbl_session_s *session, ipv6addr_t *src, ipv6addr_t *dst, 
                             uint16_t port)
{
    bbl_tcp_ctx_s *tcpc;
    err_t err = ERR_OK;

    if(!g_ctx->tcp) {
        /* TCP not enabled! */
        return NULL;
    }

    tcpc = bbl_tcp_ctx_new_session(session);
    if(!tcpc) {
        return NULL;
    }

    if(!src) {
        src = &session->ipv6_address;
    }

    /* Bind local IP address and port */
    memcpy(&tcpc->local_addr.u_addr.ip6.addr, src, sizeof(ip6_addr_t));
    tcpc->local_addr.type = IPADDR_TYPE_V6;
    tcp_bind(tcpc->pcb, &tcpc->local_addr, 0);

    /* Disable nagle algorithm */
    tcp_nagle_disable(tcpc->pcb);

    /* Connect session */
    memcpy(&tcpc->remote_addr.u_addr.ip6.addr, dst, sizeof(ip6_addr_t));
    tcpc->remote_addr.type = IPADDR_TYPE_V6;
    err = tcp_connect(tcpc->pcb, &tcpc->remote_addr, port, bbl_tcp_connected);
    if(err != ERR_OK) {
        LOG(TCP, "TCP (%s [%s]:%u - [%s]:%u) connect error %d (%s)\n",
            tcpc->ifname,
            format_ipv6_address((ipv6addr_t*)&tcpc->local_addr.u_addr.ip6.addr), 
            tcpc->local_port,
            format_ipv6_address((ipv6addr_t*)&tcpc->remote_addr.u_addr.ip6.addr),
            port,
            err, tcp_err_string(err));

        bbl_tcp_ctx_free(tcpc);
        return NULL;
    }
    tcp_err(tcpc->pcb, bbl_tcp_error_cb);

    tcpc->af = AF_INET6;
    tcpc->local_port = tcpc->pcb->local_port;
    tcpc->remote_port = port;
    tcpc->pcb->local_ip.type = IPADDR_TYPE_V6;
    tcpc->pcb->remote_ip.type = IPADDR_TYPE_V6;
    tcpc->state = BBL_TCP_STATE_CONNECTING;
    LOG(TCP, "TCP (%s [%s]:%u - [%s]:%u) connect\n",
        tcpc->ifname,
        format_ipv6_address((ipv6addr_t*)&tcpc->local_addr.u_addr.ip6.addr), 
        tcpc->local_port,
        format_ipv6_address((ipv6addr_t*)&tcpc->remote_addr.u_addr.ip6.addr),
        tcpc->remote_port);

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
bbl_tcp_ipv4_rx(bbl_network_interface_s *interface, bbl_ethernet_header_s *eth, bbl_ipv4_s *ipv4) {
    struct pbuf *pbuf;
    UNUSED(eth);

    if(!g_ctx->tcp) {
        /* TCP not enabled! */
        return;
    }
    interface->stats.tcp_rx++;

#if BNGBLASTER_TCP_DEBUG
    bbl_tcp_s *tcp = (bbl_tcp_s*)ipv4->next;
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
 * bbl_tcp_ipv4_rx_session 
 * 
 * @param eth ethernet packet received
 * @param ipv4 ipv4 header received
 * @param session receiving session
 */
void
bbl_tcp_ipv4_rx_session(bbl_session_s *session, bbl_ethernet_header_s *eth, bbl_ipv4_s *ipv4)
{
    struct pbuf *pbuf;
    UNUSED(eth);

    if(!(g_ctx->tcp && session->netif.state)) {
        /* TCP not enabled! */
        return;
    }

#if BNGBLASTER_TCP_DEBUG
    bbl_tcp_s *tcp = (bbl_tcp_s*)ipv4->next;
    LOG(DEBUG, "TCP (ID: %u %s:%u - %s:%u) packet received\n",
        session->session_id,
        format_ipv4_address(&ipv4->dst), tcp->dst,
        format_ipv4_address(&ipv4->src), tcp->src);
#endif

    ip_data.current_netif = &session->netif;
    ip_data.current_input_netif = &session->netif;
    ip_data.current_iphdr_dest.type = IPADDR_TYPE_V4;
    ip_data.current_iphdr_dest.u_addr.ip4.addr = ipv4->dst;
    ip_data.current_iphdr_src.type = IPADDR_TYPE_V4;
    ip_data.current_iphdr_src.u_addr.ip4.addr = ipv4->src;

    pbuf = pbuf_alloc_reference(ipv4->payload, ipv4->payload_len, PBUF_ROM);
    tcp_input(pbuf, &session->netif);
}

/**
 * bbl_tcp_ipv6_rx 
 * 
 * @param eth ethernet packet received
 * @param ipv6 ipv6 header received
 * @param interface receiving interface
 */
void
bbl_tcp_ipv6_rx(bbl_network_interface_s *interface, bbl_ethernet_header_s *eth, bbl_ipv6_s *ipv6)
{
    struct pbuf *pbuf;
    UNUSED(eth);

    if(!g_ctx->tcp) {
        /* TCP not enabled! */
        return;
    }
    interface->stats.tcp_rx++;

#if BNGBLASTER_TCP_DEBUG
    bbl_tcp_s *tcp = (bbl_tcp_s*)ipv6->next;
    LOG(DEBUG, "TCP (%s [%s]:%u - [%s]:%u) packet received\n",
        interface->name,
        format_ipv6_address((ipv6addr_t*)ipv6->dst), tcp->dst,
        format_ipv6_address((ipv6addr_t*)ipv6->src), tcp->src);
#endif

    pbuf = pbuf_alloc_reference(ipv6->hdr, ipv6->len, PBUF_ROM);
    interface->netif.input(pbuf, &interface->netif);

    ip_data.current_netif = &interface->netif;
    ip_data.current_input_netif = &interface->netif;
    memcpy(&ip_data.current_iphdr_dest.u_addr.ip6.addr, ipv6->dst, sizeof(ip6_addr_t));
    ip_data.current_iphdr_dest.type = IPADDR_TYPE_V6;
    memcpy(&ip_data.current_iphdr_src.u_addr.ip6.addr, ipv6->src, sizeof(ip6_addr_t));
    ip_data.current_iphdr_src.type = IPADDR_TYPE_V6;

    pbuf = pbuf_alloc_reference(ipv6->payload, ipv6->payload_len, PBUF_ROM);
    tcp_input(pbuf, &interface->netif);
}

/**
 * bbl_tcp_ipv6_rx_session 
 * 
 * @param eth ethernet packet received
 * @param ipv6 ipv6 header received
 * @param session receiving session
 */
void
bbl_tcp_ipv6_rx_session(bbl_session_s *session, bbl_ethernet_header_s *eth, bbl_ipv6_s *ipv6)
{
    struct pbuf *pbuf;
    UNUSED(eth);

    if(!(g_ctx->tcp && session->netif.state)) {
        /* TCP not enabled! */
        return;
    }

#if BNGBLASTER_TCP_DEBUG
    bbl_tcp_s *tcp = (bbl_tcp_s*)ipv6->next;
    LOG(DEBUG, "TCP (ID: %u [%s]:%u - [%s]:%u) packet received\n",
        session->session_id,
        format_ipv6_address((ipv6addr_t*)ipv6->dst), tcp->dst,
        format_ipv6_address((ipv6addr_t*)ipv6->src), tcp->src);
#endif

    pbuf = pbuf_alloc_reference(ipv6->hdr, ipv6->len, PBUF_ROM);
    session->netif.input(pbuf, &session->netif);

    ip_data.current_netif = &session->netif;
    ip_data.current_input_netif = &session->netif;
    memcpy(&ip_data.current_iphdr_dest.u_addr.ip6.addr, ipv6->dst, sizeof(ip6_addr_t));
    ip_data.current_iphdr_dest.type = IPADDR_TYPE_V6;
    memcpy(&ip_data.current_iphdr_src.u_addr.ip6.addr, ipv6->src, sizeof(ip6_addr_t));
    ip_data.current_iphdr_src.type = IPADDR_TYPE_V6;

    pbuf = pbuf_alloc_reference(ipv6->payload, ipv6->payload_len, PBUF_ROM);
    tcp_input(pbuf, &session->netif);
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
bbl_tcp_send(bbl_tcp_ctx_s *tcpc, uint8_t *buf, uint32_t len)
{
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
bbl_tcp_netif_output_ipv4(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    bbl_network_interface_s *interface = netif->state;
    bbl_ethernet_header_s eth = {0};
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
 * Function of type netif_output_fn
 */
err_t 
bbl_tcp_netif_output_ipv4_session(struct netif *netif, struct pbuf *p, const ip4_addr_t *ipaddr)
{
    bbl_session_s *session = netif->state;

    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_session_s pppoe = {0};

    UNUSED(ipaddr);

    if(session->session_state != BBL_ESTABLISHED) {
        return ERR_IF;
    }

    eth.src = session->client_mac;
    eth.dst = session->server_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = g_ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    if(session->access_type == ACCESS_TYPE_PPPOE) {
        eth.type = ETH_TYPE_PPPOE_SESSION;
        eth.next = &pppoe;
        pppoe.session_id = session->pppoe_session_id;
        pppoe.protocol = PROTOCOL_IPV4;
        pppoe.lwip = true;
        pppoe.next = p;
    } else {
        /* IPoE */
        eth.type = ETH_TYPE_IPV4;
        eth.lwip = true;
        eth.next = p;
    }

    if(bbl_txq_to_buffer(session->access_interface->txq, &eth) != BBL_TXQ_OK) {
        return ERR_IF;
    }
    return ERR_OK;
}

/**
 * Function of type netif_output_ip6_fn
 */
err_t 
bbl_tcp_netif_output_ipv6(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr)
{
    bbl_network_interface_s *interface = netif->state;
    bbl_ethernet_header_s eth = {0};
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

/**
 * Function of type netif_output_ip6_fn
 */
err_t 
bbl_tcp_netif_output_ipv6_session(struct netif *netif, struct pbuf *p, const ip6_addr_t *ipaddr)
{
    bbl_session_s *session = netif->state;

    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_session_s pppoe = {0};

    UNUSED(ipaddr);

    if(session->session_state != BBL_ESTABLISHED) {
        return ERR_IF;
    }

    eth.src = session->client_mac;
    eth.dst = session->server_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.vlan_outer_priority = g_ctx->config.pppoe_vlan_priority;
    eth.vlan_inner_priority = eth.vlan_outer_priority;
    if(session->access_type == ACCESS_TYPE_PPPOE) {
        eth.type = ETH_TYPE_PPPOE_SESSION;
        eth.next = &pppoe;
        pppoe.session_id = session->pppoe_session_id;
        pppoe.protocol = PROTOCOL_IPV6;
        pppoe.lwip = true;
        pppoe.next = p;
    } else {
        /* IPoE */
        eth.type = ETH_TYPE_IPV6;
        eth.lwip = true;
        eth.next = p;
    }

    if(bbl_txq_to_buffer(session->access_interface->txq, &eth) != BBL_TXQ_OK) {
        return ERR_IF;
    }
    return ERR_OK;
}

err_t 
bbl_tcp_netif_init(struct netif *netif)
{
    netif->output = bbl_tcp_netif_output_ipv4;
    netif->output_ip6 = bbl_tcp_netif_output_ipv6;
    netif_set_up(netif);
    return ERR_OK;
}

err_t 
bbl_tcp_netif_init_session(struct netif *netif)
{
    netif->output = bbl_tcp_netif_output_ipv4_session;
    netif->output_ip6 = bbl_tcp_netif_output_ipv6_session;
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
bbl_tcp_network_interface_init(bbl_network_interface_s *interface, bbl_network_config_s *config)
{
    if(!g_ctx->tcp) {
        /* TCP not enabled! */
        return true;
    }

    if(interface->netif.state) {
        /* Already initialised! */
        return true;
    }

    if(!(g_netif_count < BBL_TCP_NETIF_MAX)) {
        LOG(ERROR, "Failed to init TCP for network interface %s (max 255 TCP interfaces supported)\n", interface->name);
        return false;
    }
    if(!netif_add(&interface->netif, NULL, NULL, NULL, interface, bbl_tcp_netif_init, ip_input))  {
        return false;
    }
    g_netif_count++;

    interface->netif.state = interface;
    interface->netif.mtu = config->mtu;
    interface->netif.mtu6 = config->mtu;

    return true;
}

/**
 * bbl_tcp_session_init
 * 
 * Init TCP (LwIP) session.  
 * 
 * @param session session
 * @return return true if successfully
 */
bool
bbl_tcp_session_init(bbl_session_s *session)
{
    if(!(g_ctx->tcp && session->access_config->tcp)) {
        /* TCP not enabled! */
        return true;
    }

    if(session->netif.state) {
        /* Already initialised! */
        return true;
    }

    if(!(g_netif_count < BBL_TCP_NETIF_MAX)) {
        LOG(ERROR, "Failed to init TCP for session %u (max 255 TCP interfaces supported)\n", session->session_id);
        return false;
    }
    if(!netif_add(&session->netif, NULL, NULL, NULL, session, bbl_tcp_netif_init_session, ip_input))  {
        return false;
    }
    g_netif_count++;

    session->netif.state = session;
    session->netif.mtu = 1280;
    session->netif.mtu6 = 1280;
    return true;
}

void
bbl_tcp_timer(timer_s *timer)
{
    UNUSED(timer);
    sys_check_timeouts();
}

/**
 * bbl_tcp_init
 * 
 * Init TCP (LwIP) and start global TCP timer job. 
 */
void
bbl_tcp_init()
{
    if(!g_ctx->tcp) {
        /* TCP not enabled! */
        return;
    }

    lwip_init();

    /* Start TCP timer */
    timer_add_periodic(&g_ctx->timer_root, &g_ctx->tcp_timer, "TCP",
                       0, BBL_TCP_INTERVAL, g_ctx, &bbl_tcp_timer);
}