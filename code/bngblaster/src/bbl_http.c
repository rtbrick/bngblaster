/*
 * BNG Blaster (BBL) - HTTP
 *
 * Christian Giese, June 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

extern volatile bool g_teardown;

const char *
bbl_http_client_state_string(http_client_state_t state)
{
    switch(state) {
        case HTTP_CLIENT_IDLE: return "idle";
        case HTTP_CLIENT_CONNECTING: return "connecting";
        case HTTP_CLIENT_CONNECTED: return "connected";
        case HTTP_CLIENT_CLOSING: return "closing";
        case HTTP_CLIENT_CLOSED: return "closed";
        case HTTP_CLIENT_SESSION_DOWN: return "session-down";
        default: return "unknown";
    }
}

static void
bbl_http_client_close(bbl_http_client_s *client)
{
    if(client->state > HTTP_CLIENT_IDLE && client->state < HTTP_CLIENT_CLOSING) {
        client->state = HTTP_CLIENT_CLOSING;
    }
}

static void
bbl_http_client_start(bbl_http_client_s *client)
{
    if(client->state == HTTP_CLIENT_CLOSED) {
        client->state = HTTP_CLIENT_IDLE;
        client->error_string = NULL;
    }
}

/**
 * TCP callback function (connected)
 */
void 
bbl_http_client_connected_cb(void *arg)
{
    bbl_http_client_s *client = (bbl_http_client_s*)arg;
    client->state = HTTP_CLIENT_CONNECTED;
    client->timeout = HTTP_RESPONSE_TIMEOUT;
    if(client->request) {
        bbl_tcp_send(client->tcpc, (uint8_t*)client->request, strlen(client->request));
        LOG(HTTP, "HTTP (ID: %u Name: %s) request send\n", 
            client->session->session_id, client->config->name);

        LOG(DEBUG, "HTTP (ID: %u Name: %s) request: %s\n", 
            client->session->session_id, client->config->name, client->request);
    }
}

static bool
bbl_http_client_parse_response(bbl_http_client_s *client)
{
    client->http.num_headers = sizeof(client->http.headers) / sizeof(client->http.headers[0]);
    if(phr_parse_response(client->response, client->response_idx, 
        &client->http.minor_version, &client->http.status, 
        &client->http.msg, &client->http.msg_len, 
        client->http.headers, &client->http.num_headers, 0)) {

        LOG(HTTP, "HTTP (ID: %u Name: %s) response received with code %d\n", 
            client->session->session_id, client->config->name, 
            client->http.status);

        LOG(DEBUG, "HTTP (ID: %u Name: %s) response: %s\n", 
            client->session->session_id, client->config->name, client->response);

        return true;
    } else {
        return false;
    }
}

/**
 * TCP callback function (receive)
 */
void 
bbl_http_client_receive_cb(void *arg, uint8_t *buf, uint16_t len)
{
    bbl_http_client_s *client = (bbl_http_client_s*)arg;
    bool close = false;

    if(buf) {
        if(client->response_idx+len > HTTP_RESPONSE_LIMIT) {
            len = HTTP_RESPONSE_LIMIT - client->response_idx;
            /* Close TCP session after response buffer is full. */
            close = true;
        }
        if(len) {
            memcpy(client->response+client->response_idx, buf, len);
            client->response_idx+=len;
        }
        if(bbl_http_client_parse_response(client)) {
            /* Close TCP session after response has received completely. */
            close = true;
        }
        if(close) {
            bbl_http_client_close(client);
        }
    }
}

/**
 * TCP callback function (error)
 */
void 
bbl_http_client_error_cb(void *arg, err_t err) {
    bbl_http_client_s *client = (bbl_http_client_s*)arg;
    if(client->state > HTTP_CLIENT_IDLE && client->state < HTTP_CLIENT_CLOSING) {
        client->error_string = tcp_err_string(err);
    }
    bbl_http_client_close(client);
}

static void
bbl_http_client_connect(bbl_http_client_s *client)
{
    bbl_http_client_config_s *config = client->config;
    bbl_session_s *session = client->session;

    /* Connect TCP session */
    if(config->ipv4_destination_address) {
        LOG(HTTP, "HTTP (ID: %u Name: %s) connect to %s (%s:%u)\n", 
            client->session->session_id, config->name, config->url,
            format_ipv4_address(&config->ipv4_destination_address),
            config->dst_port);

        client->tcpc = bbl_tcp_ipv4_connect_session(session, NULL,
            &config->ipv4_destination_address, config->dst_port);
    } else {
        LOG(HTTP, "HTTP (ID: %u Name: %s) connect to %s (%s:%u)\n", 
            client->session->session_id, config->name, config->url,
            format_ipv6_address(&config->ipv6_destination_address),
            config->dst_port);

        client->tcpc = bbl_tcp_ipv6_connect_session(session, NULL, 
            &config->ipv6_destination_address, config->dst_port);
    }

    if(client->tcpc) {
        client->tcpc->arg = client;
        client->tcpc->connected_cb = bbl_http_client_connected_cb;
        client->tcpc->receive_cb = bbl_http_client_receive_cb;
        client->tcpc->error_cb = bbl_http_client_error_cb;

        client->state = HTTP_CLIENT_CONNECTING;
        client->timeout = HTTP_CONNECT_TIMEOUT; /* connect timeout */
    } else {
        LOG(HTTP, "HTTP (ID: %u Name: %s) connect failed\n", 
            client->session->session_id, config->name);

        client->state = HTTP_CLIENT_IDLE;
    }
}

static void
bbl_http_client_disconnect(bbl_http_client_s *client)
{
    bbl_session_s *session = client->session;

    /* Close TCP session */
    bbl_tcp_ctx_free(client->tcpc);
    client->tcpc = NULL;

    /* Update client state */
    if(session->session_state == BBL_ESTABLISHED) {
        client->state = HTTP_CLIENT_CLOSED;
    } else {
        client->state = HTTP_CLIENT_SESSION_DOWN;
    }
}

void
bbl_http_client_job(timer_s *timer)
{
    bbl_http_client_s *client = timer->data;
    bbl_http_client_config_s *config = client->config;

    bbl_session_s *session = client->session;

    if(session->session_state == BBL_ESTABLISHED) {
        if(client->state == HTTP_CLIENT_SESSION_DOWN) {
            if(config->autostart) {
                client->state = HTTP_CLIENT_IDLE;
            } else {
                client->state = HTTP_CLIENT_CLOSED;
            }
        }
    } else if(client->state == HTTP_CLIENT_SESSION_DOWN) {
        return;
    } else {
        if(client->state == HTTP_CLIENT_IDLE || 
           client->state == HTTP_CLIENT_CLOSED) {
            client->state = HTTP_CLIENT_SESSION_DOWN;
            return;
        } else {
            bbl_http_client_close(client);
        }
    }

    if(g_teardown) {
        if(client->state == HTTP_CLIENT_IDLE) {
            client->state = HTTP_CLIENT_CLOSED;
        } else {
            bbl_http_client_close(client);
        }   
    }

    switch(client->state) {
        case HTTP_CLIENT_IDLE:
            bbl_http_client_connect(client);
            break;
        case HTTP_CLIENT_CONNECTING:
            if(client->timeout) client->timeout--;
            if(client->timeout == 0) {
                LOG(HTTP, "HTTP (ID: %u Name: %s) connect timeout\n", 
                    client->session->session_id, config->name);
                bbl_http_client_disconnect(client);
                client->state = HTTP_CLIENT_IDLE;
            }
            break;
        case HTTP_CLIENT_CONNECTED:
            if(client->timeout) client->timeout--;
            if(client->timeout == 0) {
                LOG(HTTP, "HTTP (ID: %u Name: %s) response timeout\n", 
                    client->session->session_id, config->name);
                bbl_http_client_disconnect(client);
            }
            break;
        case HTTP_CLIENT_CLOSING:
            bbl_http_client_disconnect(client);
            break;
        default:
            break;
    }
}

static bool
bbl_http_client_add(bbl_http_client_config_s *config, bbl_session_s *session)
{
    bbl_http_client_s *client = calloc(1, sizeof(bbl_http_client_s));
    client->state = HTTP_CLIENT_SESSION_DOWN;
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

static json_t *
bbl_http_client_json(bbl_http_client_s *client)
{
    json_t *root = NULL;
    json_t *headers = NULL;

    bbl_http_client_config_s *config;
    char *destination;

    char header_name[256];
    char header_value[256];

    if(!client) {
        return NULL;
    }
    config = client->config;

    if(config->ipv4_destination_address) {
        destination = format_ipv4_address(&config->ipv4_destination_address);
    } else {
        destination = format_ipv6_address(&config->ipv6_destination_address);
    }

    headers = json_array();
    for(size_t i=0; i < client->http.num_headers; i++) {
        if(!client->http.headers[i].name_len) break;
        if(!client->http.headers[i].value_len) break;

        memset(header_name, 0x0, sizeof(header_name));
        if(client->http.headers[i].name_len < sizeof(header_name)) {
            strncpy(header_name, client->http.headers[i].name, client->http.headers[i].name_len);
        } else {
            strncpy(header_name, client->http.headers[i].name, sizeof(header_name)-1);
        }

        memset(header_value, 0x0, sizeof(header_value));
        if(client->http.headers[i].value_len < sizeof(header_value)) {
            strncpy(header_value, client->http.headers[i].value, client->http.headers[i].value_len);
        } else {
            strncpy(header_value, client->http.headers[i].value, sizeof(header_value)-1);
        }

        json_array_append(headers, json_pack("{ss* ss*}",
            "name", header_name,
            "value", header_value));
    }

    root = json_pack("{sI sI ss* ss* ss* sI ss* ss* s{sI, sI, ss* so*}}",
        "session-id", client->session->session_id,
        "http-client-group-id", config->http_client_group_id,
        "name", config->name,
        "url", config->url,
        "destination-address", destination,
        "destination-port", config->dst_port,
        "state", bbl_http_client_state_string(client->state),
        "tcp-error", client->error_string,
        "response",
        "minor-version", client->http.minor_version,
        "status", client->http.status,
        "msg", client->http.msg,
        "headers", headers);

    return root;
}

int
bbl_http_client_ctrl(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)))
{
    int result = 0;
    json_t *root;
    json_t *json_clients = NULL;
    json_t *json_client = NULL;
    uint32_t i;

    bbl_session_s *session;
    bbl_http_client_s *client;

    json_clients = json_array();

    if(session_id) {
        session = bbl_session_get(session_id);
        if(session) {
            client = session->http_client;
            while(client) {
                json_client = bbl_http_client_json(client);
                json_array_append(json_clients, json_client);
                client = client->next;
            }
        }
    } else {
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            client = session->http_client;
            while(client) {
                json_client = bbl_http_client_json(client);
                json_array_append(json_clients, json_client);
                client = client->next;
            }
        }
    }

    root = json_pack("{ss si so*}",
                     "status", "ok",
                     "code", 200,
                     "http-clients", json_clients);

    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(json_clients);
    }
    return result;
}

static int
bbl_http_client_ctrl_start_stop(int fd, uint32_t session_id, bool start)
{
    bbl_session_s *session;
    bbl_http_client_s *client;
    uint32_t i;

    if(session_id) {
        session = bbl_session_get(session_id);
        if(session) {
            client = session->http_client;
            while(client) {
                if(start) {
                    bbl_http_client_start(client);
                } else {
                    bbl_http_client_close(client);
                }
                client = client->next;
            }
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            client = session->http_client;
            while(client) {
                if(start) {
                    bbl_http_client_start(client);
                } else {
                    bbl_http_client_close(client);
                }
                client = client->next;
            }
        }
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_http_client_ctrl_start(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)))
{
    return bbl_http_client_ctrl_start_stop(fd, session_id, true);
}

int
bbl_http_client_ctrl_stop(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)))
{
    return bbl_http_client_ctrl_start_stop(fd, session_id, false);
}