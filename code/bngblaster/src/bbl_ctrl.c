/*
 * BNG Blaster (BBL) - Control Socket
 *
 * Christian Giese, January 2021
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
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

const char *schema_no_args[] = { NULL };
const char *schema_file[] = {
    "file", NULL
};
const char *schema_interface[] = {
    "interface", NULL
};
const char *schema_session_id[] = {
    "session-id", NULL
};
const char *schema_session_group_id[] = {
    "session-id", "session-group-id", NULL
};
const char *schema_session_terminate[] = {
    "session-id", "session-group-id", "reconnect-delay", NULL
};
const char *schema_session_direction[] = {
    "session-id", "session-group-id", "direction", NULL
};
const char *schema_session_update[] = {
    "session-id", "username", "password", 
    "agent-remote-id", "agent-circuit-id", "ipv6-link-local",
    NULL
};
const char *schema_session_summary[] = {
    "session-id", "sessions", "session-id-min", "session-id-max",
    NULL
};
const char *schema_stream_info[] = {
    "flow-id", "debug", NULL
};
const char *schema_stream_summary[] = {
    "session-group-id",
    "flows", "flow-id-min", "flow-id-max",
    "name", "interface", "direction",
    NULL
};
const char *schema_stream_start_stop[] = {
    "flow-id", "session-id", "session-group-id",
    "flows", "flow-id-min", "flow-id-max",
    "name", "interface", "direction",
    "verified-only", "bidirectional-verified-only",
    NULL
};
const char *schema_stream_update[] = {
    "flow-id", "tcp-flags", "pps", NULL
};
const char *schema_bgp[] = {
    "local-ipv4-address", "peer-ipv4-address",
    "local-ipv6-address", "peer-ipv6-address",  "ipv6-link-local",
    "file",
    NULL
};
const char *schema_isis[] = {
    "instance", "level", "file", "interface", 
    "priority", "timer", "id", "pdu",
    NULL
};
const char *schema_ospf[] = {
    "instance", "level", "file", "lsa", "pdu",
    NULL
};
const char *schema_ldp[] = {
    "ldp-instance-id",
    "local-ipv4-address", "peer-ipv4-address",
    "local-ipv6-address", "peer-ipv6-address",
    "file",
    NULL
};
const char *schema_l2tp[] = {
    "tunnel-id", "session-id", "sessions",
    "result-code", "error-code", "error-message",
    "disconnect-code", "disconnect-protocol", 
    "disconnect-direction", "disconnect-message",
    NULL
};
const char *schema_icmp[] = {
    "session-id", "detail", NULL
};
const char *schema_dhcp[] = {
    "session-id", "session-group-id", "keep-address", NULL
};
const char *schema_cfm[] = {
    "session-id", "network-interface", NULL
};
const char *schema_igmp[] = {
    "session-id", "group", "group-iter", "group-count", 
    "source1", "source2", "source3", "reset", 
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
        teardown_request();
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
    teardown_request();
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

static int bbl_ctrl_commands(int fd, uint32_t session_id, json_t *arguments);

static const struct action actions[] = {
    {"test-info", bbl_ctrl_test_info, schema_no_args, true},
    {"test-stop", bbl_ctrl_test_stop, schema_no_args, true},
    {"terminate", bbl_ctrl_terminate, schema_session_terminate, false},
    {"traffic-start", bbl_ctrl_traffic_start, schema_no_args, false},
    {"traffic-stop", bbl_ctrl_traffic_stop, schema_no_args, false},
    {"stream-start", bbl_stream_ctrl_start, schema_stream_start_stop, true},
    {"stream-stop", bbl_stream_ctrl_stop, schema_stream_start_stop, true},
    {"stream-stop-verified", bbl_stream_ctrl_stop_verified, schema_stream_start_stop, true},
    {"stream-update", bbl_stream_ctrl_update, schema_stream_update, true},
    {"session-traffic-start", bbl_session_ctrl_traffic_start, schema_session_direction, true},
    {"session-traffic-stop", bbl_session_ctrl_traffic_stop, schema_session_direction, true},
    {"multicast-traffic-start", bbl_ctrl_multicast_traffic_start, schema_no_args, false},
    {"multicast-traffic-stop", bbl_ctrl_multicast_traffic_stop, schema_no_args, false},
    {"stream-info", bbl_stream_ctrl_info, schema_stream_info, true},
    {"stream-stats", bbl_stream_ctrl_stats, schema_no_args, true},
    {"stream-reset", bbl_stream_ctrl_reset, schema_no_args, false},
    {"stream-summary", bbl_stream_ctrl_summary, schema_stream_summary, true},
    {"streams-pending", bbl_stream_ctrl_pending, schema_no_args, true},
    {"session-traffic", bbl_session_ctrl_traffic_stats, schema_no_args, true},
    {"session-traffic-reset", bbl_session_ctrl_traffic_reset, schema_session_group_id, false},
    {"interfaces", bbl_interface_ctrl, schema_no_args, true},
    {"access-interfaces", bbl_access_ctrl_interfaces, schema_no_args, true},
    {"network-interfaces", bbl_network_ctrl_interfaces, schema_no_args, true},
    {"a10nsp-interfaces", bbl_a10nsp_ctrl_interfaces, schema_no_args, true},
    {"interface-enable", bbl_interface_ctrl_enable, schema_interface, false},
    {"interface-disable", bbl_interface_ctrl_disable, schema_interface, false},
    {"sessions-pending", bbl_session_ctrl_pending, schema_no_args, true},
    {"session-info", bbl_session_ctrl_info, schema_session_id, true},
    {"session-counters", bbl_session_ctrl_counters, schema_no_args, true},
    {"session-start", bbl_session_ctrl_start, schema_session_group_id, false},
    {"session-stop", bbl_session_ctrl_stop, schema_session_group_id, false},
    {"session-restart", bbl_session_ctrl_restart, schema_session_terminate, false},
    {"session-streams", bbl_stream_ctrl_session, schema_session_id, true},
    {"session-summary", bbl_session_ctrl_summary, schema_session_summary, true},
    {"igmp-join", bbl_igmp_ctrl_join, schema_igmp, false},
    {"igmp-join-iter", bbl_igmp_ctrl_join_iter, schema_igmp, false},
    {"igmp-leave", bbl_igmp_ctrl_leave, schema_igmp, false},
    {"igmp-leave-all", bbl_igmp_ctrl_leave_all, schema_igmp, false},
    {"igmp-info", bbl_igmp_ctrl_info, schema_igmp, true},
    {"zapping-start", bbl_igmp_ctrl_zapping_start, schema_igmp, true},
    {"zapping-stop", bbl_igmp_ctrl_zapping_stop, schema_igmp, false},
    {"zapping-stats", bbl_igmp_ctrl_zapping_stats, schema_igmp, true},
    {"li-flows", bbl_li_ctrl_flows, schema_no_args, true},
    {"l2tp-tunnels", bbl_l2tp_ctrl_tunnels, schema_l2tp, true},
    {"l2tp-sessions", bbl_l2tp_ctrl_sessions, schema_l2tp, true},
    {"l2tp-csurq", bbl_l2tp_ctrl_csurq, schema_l2tp, false},
    {"l2tp-tunnel-terminate", bbl_l2tp_ctrl_tunnel_terminate, schema_l2tp, false},
    {"l2tp-session-terminate", bbl_l2tp_ctrl_session_terminate, schema_l2tp, false},
    {"ipcp-open", bbl_session_ctrl_ipcp_open, schema_session_group_id, false},
    {"ipcp-close", bbl_session_ctrl_ipcp_close, schema_session_group_id, false},
    {"ip6cp-open", bbl_session_ctrl_ip6cp_open, schema_session_group_id, false},
    {"ip6cp-close", bbl_session_ctrl_ip6cp_close, schema_session_group_id, false},
    {"isis-adjacencies", isis_ctrl_adjacencies, schema_isis, true},
    {"isis-database", isis_ctrl_database, schema_isis, true},
    {"isis-load-mrt", isis_ctrl_load_mrt, schema_isis, false},
    {"isis-lsp-update", isis_ctrl_lsp_update, schema_isis, false},
    {"isis-lsp-purge", isis_ctrl_lsp_purge, schema_isis, false},
    {"isis-lsp-flap", isis_ctrl_lsp_flap, schema_isis, false},
    {"isis-teardown", isis_ctrl_teardown, schema_isis, false},
    {"isis-update-priority", isis_ctrl_update_priority, schema_isis, false},
    {"ospf-interfaces", ospf_ctrl_interfaces, schema_ospf, true},
    {"ospf-neighbors", ospf_ctrl_neighbors, schema_ospf, true},
    {"ospf-database", ospf_ctrl_database, schema_ospf, true},
    {"ospf-load-mrt", ospf_ctrl_load_mrt, schema_ospf, false},
    {"ospf-lsa-update", ospf_ctrl_lsa_update, schema_ospf, false},
    {"ospf-pdu-update", ospf_ctrl_pdu_update, schema_ospf, false},
    {"ospf-teardown", ospf_ctrl_teardown, schema_ospf, false},
    {"bgp-sessions", bgp_ctrl_sessions, schema_bgp, true},
    {"bgp-disconnect", bgp_ctrl_disconnect, schema_bgp, false},
    {"bgp-teardown", bgp_ctrl_teardown, schema_bgp, true},
    {"bgp-raw-update-list", bgp_ctrl_raw_update_list, schema_bgp, true},
    {"bgp-raw-update", bgp_ctrl_raw_update, schema_bgp, false},
    {"ldp-adjacencies", ldp_ctrl_adjacencies, schema_ldp, true},
    {"ldp-sessions", ldp_ctrl_sessions, schema_ldp, true},
    {"ldp-database", ldb_ctrl_database, schema_ldp, true},
    {"ldp-disconnect", ldp_ctrl_disconnect, schema_ldp, false},
    {"ldp-teardown", ldp_ctrl_teardown, schema_ldp, true},
    {"ldp-raw-update-list", ldp_ctrl_raw_update_list, schema_ldp, true},
    {"ldp-raw-update", ldp_ctrl_raw_update, schema_ldp, false},
    {"monkey-start", bbl_ctrl_monkey_start, schema_no_args, false},
    {"monkey-stop", bbl_ctrl_monkey_stop, schema_no_args, false},
    {"lag-info", bbl_lag_ctrl_info, schema_interface, true},
    {"icmp-clients", bbl_icmp_client_ctrl, schema_icmp, true},
    {"icmp-clients-start", bbl_icmp_client_ctrl_start, schema_icmp, false},
    {"icmp-clients-stop", bbl_icmp_client_ctrl_stop, schema_icmp, false},
    {"http-clients", bbl_http_client_ctrl, schema_session_id, true},
    {"http-clients-start", bbl_http_client_ctrl_start, schema_session_id, false},
    {"http-clients-stop", bbl_http_client_ctrl_stop, schema_session_id, false},
    {"arp-clients", bbl_arp_client_ctrl, schema_session_id, true},
    {"arp-clients-reset", bbl_arp_client_ctrl_reset, schema_session_id, false},
    {"cfm-cc-start", bbl_cfm_ctrl_cc_start, schema_cfm, false},
    {"cfm-cc-stop", bbl_cfm_ctrl_cc_stop, schema_cfm, false},
    {"cfm-cc-rdi-on", bbl_cfm_ctrl_cc_rdi_on, schema_cfm, false},
    {"cfm-cc-rdi-off", bbl_cfm_ctrl_cc_rdi_off, schema_cfm, false},
    {"lcp-echo-request-ignore", bbl_session_ctrl_lcp_echo_request_ignore, schema_session_group_id, true},
    {"lcp-echo-request-accept", bbl_session_ctrl_lcp_echo_request_accept, schema_session_group_id, true},
    {"session-update", bbl_session_ctrl_update, schema_session_update, false},
    {"pcap-start", pcapng_ctrl_start, schema_file, false},
    {"pcap-stop", pcapng_ctrl_stop, schema_no_args, false},
    {"dhcp-start", bbl_dhcp_ctrl_start, schema_dhcp, false},
    {"dhcp-stop", bbl_dhcp_ctrl_stop, schema_dhcp, false},
    {"dhcp-release", bbl_dhcp_ctrl_release, schema_dhcp, false},
    /* DEPRECATED/HIDDERN COMMANDS */
    {"commands", bbl_ctrl_commands, schema_no_args, true},
    {"session-traffic-enabled", bbl_session_ctrl_traffic_start, schema_session_direction, true},
    {"session-traffic-disabled", bbl_session_ctrl_traffic_stop, schema_session_direction, true},
    {"stream-traffic-enabled", bbl_stream_ctrl_start, schema_stream_start_stop, true},
    {"stream-traffic-start", bbl_stream_ctrl_start, schema_stream_start_stop, true},
    {"stream-traffic-disabled", bbl_stream_ctrl_stop, schema_stream_start_stop, true},
    {"stream-traffic-stop", bbl_stream_ctrl_stop, schema_stream_start_stop, true},
    /* END */
    {NULL, NULL, NULL, false},
};

int
bbl_ctrl_commands(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    int result = 0;
    json_t *jobj;
    json_t *jobj_c_array = json_array();
    json_t *jobj_a_array = json_array();
    const char **schema;

    int i = 0;
    int i2;
    while(actions[i].name != NULL && strcmp(actions[i].name, "commands") != 0) {
        schema = actions[i].schema;
        jobj_a_array = json_array();
        i2 = 0;
        while(schema[i2] != NULL) {
            json_array_append_new(jobj_a_array, json_string(schema[i2++]));
        }
        jobj = json_pack("{ss* so*}", 
            "command", actions[i].name,
            "arguments", jobj_a_array
        );
        if(jobj) {
            json_array_append_new(jobj_c_array, jobj);
        }
        i++;
    }
    json_t *root = json_pack("{ss si so*}",
        "status", "ok",
        "code", 200,
        "commands", jobj_c_array);

    if(root) {
        result = json_dumpfd(root, fd, 0);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
    }
    return result;
}

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
                                if(search && *search) {
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