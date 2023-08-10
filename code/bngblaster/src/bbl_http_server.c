/*
 * BNG Blaster (BBL) - HTTP Server
 *
 * Christian Giese, June 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

/**
 * TCP callback function (receive)
 */
void 
bbl_http_server_receive_cb(void *arg, uint8_t *buf, uint16_t len)
{
    bbl_http_server_connection_s *connection = (bbl_http_server_connection_s*)arg;

    UNUSED(buf);
    UNUSED(len);

    bbl_tcp_send(connection->tcpc, (uint8_t*)HTTP_SERVER_RESPONSE_STRING, sizeof(HTTP_SERVER_RESPONSE_STRING));
}

/**
 * TCP callback function (accepted)
 */
err_t 
bbl_http_server_accepted_cb(bbl_tcp_ctx_s *tcpc, void *arg)
{
    bbl_http_server_s *server = (bbl_http_server_s*)arg;
    bbl_http_server_connection_s *connection = calloc(1, sizeof(bbl_http_server_connection_s));
    connection->next = server->connections;
    server->connections = connection;
    connection->tcpc = tcpc;
    tcpc->arg = connection;
    tcpc->receive_cb = bbl_http_server_receive_cb;

    if(tcpc->af == AF_INET) {
        LOG(HTTP, "HTTP-Server (Name: %s) new connection from %s\n",
            server->config->name, 
            format_ipv4_address(&tcpc->remote_addr.u_addr.ip4.addr));
    } else {
        LOG(HTTP, "HTTP-Server (Name: %s) new connection from %s\n",
            server->config->name, 
            format_ipv6_address((ipv6addr_t*)&tcpc->local_addr.u_addr.ip6.addr));
    }
    return ERR_OK;
}

void
bbl_http_server_job(timer_s *timer)
{
    bbl_http_server_s *server = timer->data;
    bbl_http_server_connection_s *connection = server->connections;
    bbl_http_server_connection_s *connection_prev = NULL;
    bbl_http_server_connection_s *connection_next = connection;
    bbl_tcp_ctx_s *tcpc;

    while(connection_next) {
        connection = connection_next;
        connection_next = connection->next;

        tcpc = connection->tcpc;
        if(tcpc->pcb->state == CLOSE_WAIT || tcpc->pcb->state == CLOSED) {
            if(connection->tcpc->af == AF_INET) {
                LOG(HTTP, "HTTP-Server (Name: %s) delete connection from %s\n",
                    server->config->name, 
                    format_ipv4_address(&connection->tcpc->remote_addr.u_addr.ip4.addr));
            } else {
                LOG(HTTP, "HTTP-Server (Name: %s) delete connection from %s\n",
                    server->config->name, 
                    format_ipv6_address((ipv6addr_t*)&connection->tcpc->local_addr.u_addr.ip6.addr));
            }
            bbl_tcp_ctx_free(connection->tcpc);
            connection->tcpc = NULL;
            free(connection);
            connection = NULL;
            if(connection_prev) {
                connection_prev->next = connection_next;
            } else {
                server->connections = connection_next;
            }
        } else {
            connection_prev = connection;
        }
    }
}

static bool
bbl_http_server_start(bbl_network_interface_s *network_interface, 
                      bbl_http_server_config_s *config)
{
    bbl_http_server_s *server = calloc(1, sizeof(bbl_http_server_s));
    server->config = config;
    server->next = network_interface->http_server;
    
    if(config->ipv4_address) {
        server->listen_tcpc = bbl_tcp_ipv4_listen(
            network_interface,
            &config->ipv4_address,
            config->port, 0, 0);
    } else {
        server->listen_tcpc = bbl_tcp_ipv6_listen(
            network_interface,
            &config->ipv6_address,
            config->port, 0, 0);
    }
    if(!server->listen_tcpc) {
        free(server);
        return false;
    }

    server->listen_tcpc->arg = server;
    server->listen_tcpc->accepted_cb = bbl_http_server_accepted_cb;

    timer_add_periodic(&g_ctx->timer_root, &server->gc_timer, 
                       "HTTP", 5, 0, server, 
                       &bbl_http_server_job);

    network_interface->http_server = server;
    return true;
}

bool
bbl_http_server_init(bbl_network_interface_s *network_interface)
{

    bbl_http_server_config_s *config = g_ctx->config.http_server_config;
    while(config) {
        if(strcmp(config->network_interface, network_interface->name) == 0) {
            if(!bbl_http_server_start(network_interface, config)) {
                return false;
            }
        }
        config = config->next;
    }
    return true;
}