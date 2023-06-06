/*
 * BNG Blaster (BBL) - HTTP
 *
 * Christian Giese, June 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

const char *
bbl_http_client_state_string(http_client_state_t state)
{
    switch(state) {
        case HTTP_CLIENT_IDLE: return "idle";
        case HTTP_CLIENT_CONNECTING: return "connecting";
        case HTTP_CLIENT_CONNECTED: return "connected";
        case HTTP_CLIENT_REQUEST_SEND: return "request-send";
        case HTTP_CLIENT_RESPONSE_RECEIVED: return "response-received";
        case HTTP_CLIENT_CLOSED: return "closed";
        default: return "unknown";
    }
}

void 
bbl_http_client_connected_cb(void *arg)
{
    bbl_http_client_s *client = (bbl_http_client_s*)arg;
    LOG(HTTP, "HTTP (ID: %u) CONNECTED\n", client->session->session_id); /* DEBUG */
    client->state = HTTP_CLIENT_CONNECTED;
    client->timeout = 60;
    if(bbl_tcp_send(client->tcpc, (uint8_t*)client->request, strlen(client->request))) {
        client->state = HTTP_CLIENT_REQUEST_SEND;
    }

}

void 
bbl_http_client_receive_cb(void *arg, uint8_t *buf, uint16_t len)
{
    bbl_http_client_s *client = (bbl_http_client_s*)arg;
    
    if(buf) {
        if(client->state == HTTP_CLIENT_REQUEST_SEND) {
            client->state = HTTP_CLIENT_RESPONSE_RECEIVED;
        }
        if(client->response_idx+len > HTTP_RESPONSE_LIMIT) {
            len = HTTP_RESPONSE_LIMIT-client->response_idx;
        }
        memcpy(client->response+client->response_idx, buf, len);
        client->response_idx+=len;

        LOG(HTTP, "HTTP (ID: %u) RESPONSE: %s\n", 
            client->session->session_id, 
            client->response);
    }
}

void 
bbl_http_client_error_cb(void *arg, err_t err) {
    bbl_http_client_s *client = (bbl_http_client_s*)arg;
    client->state = HTTP_CLIENT_CLOSED;
    client->error_string = tcp_err_string(err);
}

static void
bbl_http_client_connect(bbl_http_client_s *client)
{
    bbl_http_client_config_s *config = client->config;
    bbl_session_s *session = client->session;

    /* Connect TCP session */
    if(config->ipv4_destination_address) {
        client->tcpc = bbl_tcp_ipv4_connect_session(session, NULL,
            &config->ipv4_destination_address, config->dst_port);
    } else {
        client->tcpc = bbl_tcp_ipv6_connect_session(session, NULL, 
            &config->ipv6_destination_address, config->dst_port);
    }

    if(client->tcpc) {
        client->tcpc->arg = client;
        client->tcpc->connected_cb = bbl_http_client_connected_cb;
        client->tcpc->receive_cb = bbl_http_client_receive_cb;
        client->tcpc->error_cb = bbl_http_client_error_cb;

        LOG(HTTP, "HTTP (ID: %u) CONNECTING\n", client->session->session_id); /* DEBUG */
        client->state = HTTP_CLIENT_CONNECTING;
        client->timeout = 30; 
    }
}

static void
bbl_http_client_close(bbl_http_client_s *client)
{
    bbl_tcp_ctx_free(client->tcpc);
    client->tcpc = NULL;
}

void
bbl_http_client_job(timer_s *timer)
{
    bbl_http_client_s *client = timer->data;
    bbl_session_s *session = client->session;

    if(session->session_state != BBL_ESTABLISHED) {
        if(client->tcpc) {
            bbl_tcp_ctx_free(client->tcpc);
            client->tcpc = NULL;
        }
        client->state = HTTP_CLIENT_IDLE;
        return;
    }

    switch(client->state) {
        case HTTP_CLIENT_IDLE:
            bbl_http_client_connect(client);
            break;
        case HTTP_CLIENT_CONNECTING:
            if(--client->timeout == 0) {
                bbl_http_client_close(client);
                client->state = HTTP_CLIENT_IDLE;
            }
            break;
        case HTTP_CLIENT_CONNECTED:
        case HTTP_CLIENT_REQUEST_SEND:
        case HTTP_CLIENT_RESPONSE_RECEIVED:
            if(--client->timeout == 0) {
                bbl_http_client_close(client);
                client->state = HTTP_CLIENT_CLOSED;
            }
        default:
            break;
    }
}

static bool
bbl_http_client_add(bbl_http_client_config_s *config, bbl_session_s *session)
{
    bbl_http_client_s *client = calloc(1, sizeof(bbl_http_client_s));
    client->session = session;
    client->config = config;

    client->request = calloc(1, strlen(client->config->url)+sizeof(HTTP_REQUEST_STRING));
    sprintf(client->request, HTTP_REQUEST_STRING, client->config->url);
    
    client->response = calloc(1, HTTP_RESPONSE_LIMIT);

    client->next = session->http_client;
    session->http_client = client;

    timer_add_periodic(&g_ctx->timer_root, &client->state_timer, 
                       "HTTP", 1, 0, client,
                       &bbl_http_client_job);

    return true;
}

bool
bbl_http_client_session_init(bbl_session_s *session)
{
    bbl_http_client_config_s *config;
    uint16_t http_client_group_id = session->access_config->http_client_group_id;

    if(!bbl_tcp_session_init(session)) {
        return false;
    }

    /** Add clients of corresponding http-client-group-id */
    if(http_client_group_id) {
        config = g_ctx->config.http_client_config;
        while(config) {
            if(config->http_client_group_id == http_client_group_id) {
                if(!bbl_http_client_add(config, session)) {
                    return false;
                }
            }
            config = config->next;
        }
    }
    return true;
}