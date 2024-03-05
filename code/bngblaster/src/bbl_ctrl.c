/*
 * BNG Blaster (BBL) - Control Socket
 *
 * Christian Giese, January 2021
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <sys/stat.h>

#include "bbl.h"
#include "bbl_ctrl.h"
#include "bbl_session.h"
#include "bbl_stream.h"
#include "bbl_dhcp.h"
#include "bbl_dhcpv6.h"

#define BACKLOG 4

extern volatile bool g_monkey;
extern volatile bool g_teardown;
extern volatile bool g_teardown_request;
extern volatile uint8_t g_teardown_request_count;

const char *schema_no_args[] = { NULL };
const char *schema_all_args[] = {
    "interface", "outer-vlan", "inner-vlan",
    "session-id", "session-group-id", "direction", "reconnect-delay", 
    "flow-id", "id", "name", "file", "reset", "timer",
    "group", "group-iter", "group-count", "source1", "source2", "source3",
    "local-ipv4-address", "peer-ipv4-address",
    "instance", "level", "pdu", "lsa",
    "tunnel-id", "sessions", 
    "result-code", "error-code", "error-message",
    "disconnect-code", "disconnect-protocol", 
    "disconnect-direction", "disconnect-message",
    "ldp-instance-id", "tcp-flags", "debug",
    NULL
};

static bool
bbl_ctrl_schema(json_t *arguments, const char *const schema[])
{
    size_t i;
    bool valid;
    const char *key;
    json_t *value = NULL;
    json_object_foreach(arguments, key, value) {
        valid = false; i = 0;
        while(schema[i]) {
            if (!strcmp(key, schema[i])) {
                valid = true;
                break;
            }
            i++;
        }
        if(valid) {
            continue;
        }
        return false;
    }
    return true;
}

int
bbl_ctrl_terminate(int fd, uint32_t session_id, json_t *arguments)
{
    bbl_session_s *session;
    int reconnect_delay = 0;

    if(session_id) {
        /* DEPRECATED! 
         * Terminate single matching session.
         * The option to reconnect session via "terminate" command
         * remains for backward compatibility only. The new commands
         * "session-start/stop/restart" should be used instead. */
        session = bbl_session_get(session_id);
        if(session) {
            json_unpack(arguments, "{s:i}", "reconnect-delay", &reconnect_delay);
            if(reconnect_delay > 0) {
                session->reconnect_delay = reconnect_delay;
            }
            bbl_session_clear(session);
            return bbl_ctrl_status(fd, "ok", 200, "terminate session");
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Terminate all sessions and teardown test ... */
        g_teardown = true;
        g_teardown_request = true;
        g_teardown_request_count++;
        LOG_NOARG(INFO, "Teardown request\n");
        return bbl_ctrl_status(fd, "ok", 200, "teardown requested");
    }
}

int
bbl_ctrl_status(int fd, const char *status, uint32_t code, const char *message)
{
    int result = 0;
    json_t *root = json_pack("{sssiss*}", "status", status, "code", code, "message", message);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    }
    return result;
}

int
bbl_ctrl_test_stop(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    g_teardown = true;
    g_teardown_request = true;
    g_teardown_request_count++;
    LOG_NOARG(INFO, "Teardown request\n");
    return bbl_ctrl_status(fd, "ok", 200, "teardown requested");
}

int
bbl_ctrl_test_info(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    int result = 0;
    json_t *root;
    root = json_pack("{ss si s{ss si}}",
                     "status", "ok",
                     "code", 200,
                     "test-info",
                     "state", test_state(),
                     "duration", test_duration());
    if(root) {
        result = json_dumpfd(root, fd, 0);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
    }
    return result;
}

int
bbl_ctrl_multicast_traffic_start(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    g_ctx->multicast_endpoint = ENDPOINT_ACTIVE;
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_ctrl_multicast_traffic_stop(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    g_ctx->multicast_endpoint = ENDPOINT_ENABLED;
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_ctrl_traffic_start(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    global_traffic_enable(true);
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_ctrl_traffic_stop(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    global_traffic_enable(false);
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_ctrl_monkey_start(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    if(!g_monkey) {
        LOG_NOARG(INFO, "Start monkey\n");
    }
    g_monkey = true;
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_ctrl_monkey_stop(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    if(g_monkey) {
        LOG_NOARG(INFO, "Stop monkey\n");
    }
    g_monkey = false;
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

typedef int callback_function(int fd, uint32_t session_id, json_t *arguments);

struct action {
    char *name;
    callback_function *fn;
    void *schema;
    bool thread_safe;
};

struct action actions[] = {
    {"test-info", bbl_ctrl_test_info, schema_no_args, true},
    {"test-stop", bbl_ctrl_test_stop, schema_no_args, true},
    {"terminate", bbl_ctrl_terminate, schema_all_args, false},
    {"traffic-start", bbl_ctrl_traffic_start, schema_all_args, false},
    {"traffic-stop", bbl_ctrl_traffic_stop, schema_all_args, false},
    {"stream-start", bbl_stream_ctrl_start, schema_all_args, true},
    {"stream-stop", bbl_stream_ctrl_stop, schema_all_args, true},
    {"stream-stop-verified", bbl_stream_ctrl_stop_verified, schema_all_args, true},
    {"stream-update", bbl_stream_ctrl_update, schema_all_args, true},
    {"session-traffic-start", bbl_session_ctrl_traffic_start, schema_all_args, true},
    {"session-traffic-stop", bbl_session_ctrl_traffic_stop, schema_all_args, true},
    {"multicast-traffic-start", bbl_ctrl_multicast_traffic_start, schema_all_args, false},
    {"multicast-traffic-stop", bbl_ctrl_multicast_traffic_stop, schema_all_args, false},
    {"stream-info", bbl_stream_ctrl_info, schema_all_args, true},
    {"stream-stats", bbl_stream_ctrl_stats, schema_all_args, true},
    {"stream-reset", bbl_stream_ctrl_reset, schema_all_args, false},
    {"stream-summary", bbl_stream_ctrl_summary, schema_all_args, true},
    {"streams-pending", bbl_stream_ctrl_pending, schema_no_args, true},
    {"session-traffic", bbl_session_ctrl_traffic_stats, schema_all_args, true},
    {"session-traffic-reset", bbl_session_ctrl_traffic_reset, schema_all_args, false},
    {"interfaces", bbl_interface_ctrl, schema_no_args, true},
    {"access-interfaces", bbl_access_ctrl_interfaces, schema_no_args, true},
    {"network-interfaces", bbl_network_ctrl_interfaces, schema_no_args, true},
    {"a10nsp-interfaces", bbl_a10nsp_ctrl_interfaces, schema_no_args, true},
    {"interface-enable", bbl_interface_ctrl_enable, schema_all_args, false},
    {"interface-disable", bbl_interface_ctrl_disable, schema_all_args, false},
    {"sessions-pending", bbl_session_ctrl_pending, schema_no_args, true},
    {"session-info", bbl_session_ctrl_info, schema_all_args, true},
    {"session-counters", bbl_session_ctrl_counters, schema_no_args, true},
    {"session-start", bbl_session_ctrl_start, schema_all_args, true},
    {"session-stop", bbl_session_ctrl_stop, schema_all_args, true},
    {"session-restart", bbl_session_ctrl_restart, schema_all_args, true},
    {"session-streams", bbl_stream_ctrl_session, schema_all_args, true},
    {"igmp-join", bbl_igmp_ctrl_join, schema_all_args, false},
    {"igmp-join-iter", bbl_igmp_ctrl_join_iter, schema_all_args, false},
    {"igmp-leave", bbl_igmp_ctrl_leave, schema_all_args, false},
    {"igmp-leave-all", bbl_igmp_ctrl_leave_all, schema_all_args, false},
    {"igmp-info", bbl_igmp_ctrl_info, schema_all_args, true},
    {"zapping-start", bbl_igmp_ctrl_zapping_start, schema_all_args, true},
    {"zapping-stop", bbl_igmp_ctrl_zapping_stop, schema_all_args, false},
    {"zapping-stats", bbl_igmp_ctrl_zapping_stats, schema_all_args, true},
    {"li-flows", bbl_li_ctrl_flows, schema_all_args, true},
    {"l2tp-tunnels", bbl_l2tp_ctrl_tunnels, schema_all_args, true},
    {"l2tp-sessions", bbl_l2tp_ctrl_sessions, schema_all_args, true},
    {"l2tp-csurq", bbl_l2tp_ctrl_csurq, schema_all_args, false},
    {"l2tp-tunnel-terminate", bbl_l2tp_ctrl_tunnel_terminate, schema_all_args, false},
    {"l2tp-session-terminate", bbl_l2tp_ctrl_session_terminate, schema_all_args, false},
    {"ipcp-open", bbl_session_ctrl_ipcp_open, schema_all_args, false},
    {"ipcp-close", bbl_session_ctrl_ipcp_close, schema_all_args, false},
    {"ip6cp-open", bbl_session_ctrl_ip6cp_open, schema_all_args, false},
    {"ip6cp-close", bbl_session_ctrl_ip6cp_close, schema_all_args, false},
    {"isis-adjacencies", isis_ctrl_adjacencies, schema_all_args, true},
    {"isis-database", isis_ctrl_database, schema_all_args, true},
    {"isis-load-mrt", isis_ctrl_load_mrt, schema_all_args, false},
    {"isis-lsp-update", isis_ctrl_lsp_update, schema_all_args, false},
    {"isis-lsp-purge", isis_ctrl_lsp_purge, schema_all_args, false},
    {"isis-lsp-flap", isis_ctrl_lsp_flap, schema_all_args, false},
    {"isis-teardown", isis_ctrl_teardown, schema_all_args, false},
    {"ospf-interfaces", ospf_ctrl_interfaces, schema_all_args, true},
    {"ospf-neighbors", ospf_ctrl_neighbors, schema_all_args, true},
    {"ospf-database", ospf_ctrl_database, schema_all_args, true},
    {"ospf-load-mrt", ospf_ctrl_load_mrt, schema_all_args, false},
    {"ospf-lsa-update", ospf_ctrl_lsa_update, schema_all_args, false},
    {"ospf-pdu-update", ospf_ctrl_pdu_update, schema_all_args, false},
    {"ospf-teardown", ospf_ctrl_teardown, schema_all_args, false},
    {"bgp-sessions", bgp_ctrl_sessions, schema_all_args, true},
    {"bgp-disconnect", bgp_ctrl_disconnect, schema_all_args, false},
    {"bgp-teardown", bgp_ctrl_teardown, schema_all_args, true},
    {"bgp-raw-update-list", bgp_ctrl_raw_update_list, schema_all_args, true},
    {"bgp-raw-update", bgp_ctrl_raw_update, schema_all_args, false},
    {"ldp-adjacencies", ldp_ctrl_adjacencies, schema_all_args, true},
    {"ldp-sessions", ldp_ctrl_sessions, schema_all_args, true},
    {"ldp-database", ldb_ctrl_database, schema_all_args, true},
    {"ldp-disconnect", ldp_ctrl_disconnect, schema_all_args, false},
    {"ldp-teardown", ldp_ctrl_teardown, schema_all_args, true},
    {"ldp-raw-update-list", ldp_ctrl_raw_update_list, schema_all_args, true},
    {"ldp-raw-update", ldp_ctrl_raw_update, schema_all_args, false},
    {"monkey-start", bbl_ctrl_monkey_start, schema_all_args, false},
    {"monkey-stop", bbl_ctrl_monkey_stop, schema_all_args, false},
    {"lag-info", bbl_lag_ctrl_info, schema_all_args, true},
    {"http-clients", bbl_http_client_ctrl, schema_all_args, true},
    {"http-clients-start", bbl_http_client_ctrl_start, schema_all_args, false},
    {"http-clients-stop", bbl_http_client_ctrl_stop, schema_all_args, false},
    {"cfm-cc-start", bbl_cfm_ctrl_cc_start, schema_all_args, false},
    {"cfm-cc-stop", bbl_cfm_ctrl_cc_stop, schema_all_args, false},
    {"cfm-cc-rdi-on", bbl_cfm_ctrl_cc_rdi_on, schema_all_args, false},
    {"cfm-cc-rdi-off", bbl_cfm_ctrl_cc_rdi_off, schema_all_args, false},
    /* DEPRECATED */
    {"session-traffic-enabled", bbl_session_ctrl_traffic_start, schema_all_args, true},
    {"session-traffic-disabled", bbl_session_ctrl_traffic_stop, schema_all_args, true},
    {"stream-traffic-enabled", bbl_stream_ctrl_start, schema_all_args, true},
    {"stream-traffic-start", bbl_stream_ctrl_start, schema_all_args, true},
    {"stream-traffic-disabled", bbl_stream_ctrl_stop, schema_all_args, true},
    {"stream-traffic-stop", bbl_stream_ctrl_stop, schema_all_args, true},
    /* END */
    {NULL, NULL, NULL, false},
};

static void
bbl_ctrl_socket_main(bbl_ctrl_thread_s *ctrl)
{
    if(ctrl->main.fd) {
        pthread_mutex_lock(&ctrl->mutex);
        actions[ctrl->main.action].fn(ctrl->main.fd, ctrl->main.session_id, (json_t*)ctrl->main.arguments);
        ctrl->main.action = 0;
        ctrl->main.fd = 0;
        ctrl->main.session_id = 0;
        ctrl->main.arguments = NULL;
        pthread_cond_signal(&ctrl->cond);
        pthread_mutex_unlock(&ctrl->mutex);
    }
}

void
bbl_ctrl_socket_main_job(timer_s *timer)
{
    bbl_ctrl_socket_main(timer->data);
}

void *
bbl_ctrl_socket_thread(void *thread_data)
{
    bbl_ctrl_thread_s *ctrl = thread_data;

    size_t i;
    size_t flags = JSON_DISABLE_EOF_CHECK;
    json_error_t error;
    json_t *root = NULL;
    json_t* arguments = NULL;
    json_t* value = NULL;
    const char *command = NULL;
    uint32_t session_id = 0;

    fd_set read_fds;

    bbl_access_interface_s *access_interface;

    vlan_session_key_t key = {0};
    bbl_session_s *session;
    void **search;

    /* ToDo: Add connection manager!
     * This is just a temporary workaround! Finally we need
     * to create a connection manager. */
    static int fd = 0;

    // Set timeout for 1s
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    struct timespec sleep, rem;
    sleep.tv_sec = 0;
    sleep.tv_nsec = 10 * MSEC;

    ctrl->active = true;
    while(ctrl->active) {
        fd = accept(ctrl->socket, 0, 0);
        if(fd > 0) {
            /* New connection. */
            FD_ZERO(&read_fds);
            FD_SET(fd, &read_fds);
            root = json_loadfd(fd, flags, &error);
            if(!root) {
                LOG(ERROR, "Invalid json via ctrl socket: line %d: %s\n", error.line, error.text);
                bbl_ctrl_status(fd, "error", 400, "invalid json");
            } else {
                    /* Each command request should be formatted as shown in the example below
                    * with a mandatory command element and optional arguments.
                    * {
                    *    "command": "session-info",
                    *    "arguments": {
                    *        "outer-vlan": 1,
                    *        "inner-vlan": 2
                    *    }
                    * }
                    */
                command = NULL;
                arguments = NULL;
                session_id = 0;
                key.ifindex = 0;
                key.inner_vlan_id = 0;
                key.outer_vlan_id = 0;
                if(json_unpack(root, "{s:s, s?o}", "command", &command, "arguments", &arguments) != 0) {
                    LOG_NOARG(ERROR, "Invalid command via ctrl socket\n");
                    bbl_ctrl_status(fd, "error", 400, "invalid request");
                } else {
                    if(arguments) {
                        value = json_object_get(arguments, "session-id");
                        if(value) {
                            if(json_is_number(value)) {
                                session_id = json_number_value(value);
                            } else {
                                bbl_ctrl_status(fd, "error", 400, "invalid session-id");
                                goto CLOSE;
                            }
                        } else {
                            /* Deprecated!
                             * For backward compatibility with version 0.4.X, we still
                             * support per session commands using VLAN index instead of
                             * new session-id. */
                            value = json_object_get(arguments, "ifindex");
                            if(value) {
                                if(json_is_number(value)) {
                                    key.ifindex = json_number_value(value);
                                } else {
                                    bbl_ctrl_status(fd, "error", 400, "invalid ifindex");
                                    goto CLOSE;
                                }
                            } else {
                                value = json_object_get(arguments, "interface");
                                if(value && json_is_string(value)) {
                                    access_interface = bbl_access_interface_get((char*)json_string_value(value));
                                } else {
                                    /* Use first interface as default. */
                                    access_interface = bbl_access_interface_get(NULL);
                                }
                                if(access_interface) {
                                    key.ifindex = access_interface->ifindex;
                                }
                            }
                            value = json_object_get(arguments, "outer-vlan");
                            if(value) {
                                if(json_is_number(value)) {
                                    key.outer_vlan_id = json_number_value(value);
                                } else {
                                    bbl_ctrl_status(fd, "error", 400, "invalid outer-vlan");
                                    goto CLOSE;
                                }
                            }
                            value = json_object_get(arguments, "inner-vlan");
                            if(value) {
                                if(json_is_number(value)) {
                                    key.inner_vlan_id = json_number_value(value);
                                } else {
                                    bbl_ctrl_status(fd, "error", 400, "invalid inner-vlan");
                                    goto CLOSE;
                                }
                            }
                            if(key.outer_vlan_id) {
                                search = dict_search(g_ctx->vlan_session_dict, &key);
                                if(search) {
                                    session = *search;
                                    session_id = session->session_id;
                                } else {
                                    bbl_ctrl_status(fd, "warning", 404, "session not found");
                                    goto CLOSE;
                                }
                            }
                        }
                    }
                    for(i = 0; true; i++) {
                        if(actions[i].name == NULL) {
                            bbl_ctrl_status(fd, "error", 400, "unknown command");
                            break;
                        } else if(strcmp(actions[i].name, command) == 0) {
                            if(actions[i].schema && !bbl_ctrl_schema(arguments, actions[i].schema)) {
                                bbl_ctrl_status(fd, "error", 400, "invalid argument");
                                break;
                            }
                            if(actions[i].thread_safe) {
                                actions[i].fn(fd, session_id, arguments);
                            } else {
                                pthread_mutex_lock(&ctrl->mutex);
                                ctrl->main.fd = fd;
                                ctrl->main.action = i;
                                ctrl->main.session_id = session_id;
                                ctrl->main.arguments = (void*)arguments;
                                pthread_cond_wait(&ctrl->cond, &ctrl->mutex);
                                pthread_mutex_unlock(&ctrl->mutex);
                            }
                            break;
                        }
                    }
                }
CLOSE:
                json_decref(root);
                root = NULL;
            }
            shutdown(fd, SHUT_WR);
            select(fd + 1, &read_fds, NULL, NULL, &timeout);
            close(fd);
        } else {
            nanosleep(&sleep, &rem);
        }
    }
    return NULL;
}

bool
bbl_ctrl_socket_init()
{
    bbl_ctrl_thread_s *ctrl;
    struct sockaddr_un addr = {0};

    if(!g_ctx->ctrl_socket_path) {
        return true;
    }

    ctrl = calloc(1, sizeof(bbl_ctrl_thread_s));
    if(!ctrl) {
        fprintf(stderr, "Error: Failed to init ctrl socket memory\n");
        return false;
    }
    g_ctx->ctrl_thread = ctrl;

    ctrl->socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if(ctrl->socket < 0) {
        fprintf(stderr, "Error: Failed to create ctrl socket\n");
        return false;
    }
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, g_ctx->ctrl_socket_path, sizeof(addr.sun_path)-1);
    unlink(g_ctx->ctrl_socket_path);
    if(bind(ctrl->socket, (struct sockaddr *)&addr, SUN_LEN(&addr)) != 0) {
        fprintf(stderr, "Error: Failed to bind ctrl socket %s (error %d)\n", g_ctx->ctrl_socket_path, errno);
        return false;
    }
    if(listen(ctrl->socket, BACKLOG) != 0) {
        fprintf(stderr, "Error: Failed to listen on ctrl socket %s (error %d)\n", g_ctx->ctrl_socket_path, errno);
        return false;
    }

    /* Change socket to non-blocking */
    fcntl(ctrl->socket, F_SETFL, O_NONBLOCK);

    /* Create ctrl thread */
    if(pthread_mutex_init(&ctrl->mutex, NULL) != 0) {
        LOG_NOARG(ERROR, "Failed to init ctrl mutex\n");
        return false;
    }
    if(pthread_cond_init(&ctrl->cond, NULL) != 0) {
        LOG_NOARG(ERROR, "Failed to init ctrl condition\n");
        return false;
    }
    if(pthread_create(&ctrl->thread, NULL, bbl_ctrl_socket_thread, (void *)ctrl) != 0) {
        LOG_NOARG(ERROR, "Failed to create ctrl thread\n");
        return false;
    }

    /* Start ctrl main job */
    timer_add_periodic(&g_ctx->timer_root, &ctrl->main.timer, "CTRL Socket Main Timer", 0, 1000 * MSEC, ctrl, &bbl_ctrl_socket_main_job);

    LOG(INFO, "Opened control socket %s\n", g_ctx->ctrl_socket_path);

    /* Ignore SIGPIPE */
    signal(SIGPIPE, SIG_IGN);
    return true;
}

bool
bbl_ctrl_socket_close()
{
    bbl_ctrl_thread_s *ctrl;
    if(g_ctx->ctrl_thread) {
        ctrl = g_ctx->ctrl_thread;
        if(ctrl->active) {
            ctrl->active = false;
            bbl_ctrl_socket_main(ctrl);
            pthread_join(ctrl->thread, NULL);
            pthread_mutex_destroy(&ctrl->mutex);
            pthread_cond_destroy(&ctrl->cond);
        }
        if(ctrl->socket) {
            close(ctrl->socket);
        }
        unlink(g_ctx->ctrl_socket_path);
        free(g_ctx->ctrl_thread);
        g_ctx->ctrl_thread = NULL;
    }
    return true;
}