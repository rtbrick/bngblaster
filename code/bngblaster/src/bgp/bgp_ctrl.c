/*
 * BNG Blaster (BBL) - BGP CTRL (Control Commands)
 *
 * Christian Giese, March 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"
#include "../bbl_ctrl.h"

static const char *
raw_update_state(bgp_session_s *session) 
{
    if(session->raw_update) {
        if(session->update_start_timestamp.tv_sec) {
            if(session->raw_update_sending) {
                return "sending";
            }
            if(session->update_stop_timestamp.tv_sec) {
                return "done";
            }
        } else {
            return "wait";
        }
    }
    return NULL;
}

static json_t *
bgp_ctrl_session_json(bgp_session_s *session)
{
    json_t *root = NULL;
    json_t *stats = NULL;
    uint32_t peer_id_be;

    const char *raw_update_file = NULL;

    if(!session) {
        return NULL;
    }

    if(session->raw_update) {
        raw_update_file = session->raw_update->file;
    }

    stats = json_pack("{si si si si si si si si si si}",
                      "messages-rx", session->stats.message_rx,
                      "messages-tx", session->stats.message_tx,
                      "keepalive-rx", session->stats.keepalive_rx,
                      "keepalive-tx", session->stats.keepalive_tx,
                      "update-rx", session->stats.update_rx,
                      "update-tx", session->stats.update_tx,
                      "evpn-reach-rx", session->stats.evpn_reach_rx,
                      "evpn-withdraw-rx", session->stats.evpn_withdraw_rx,
                      "route-reach-rx", session->stats.route_reach_rx,
                      "route-withdraw-rx", session->stats.route_withdraw_rx);

    if(!stats) {
        return NULL;
    }

    /* peer.id is a host-order value (read_be_uint), unlike config->id which
     * is raw network order from inet_pton; convert before formatting. */
    peer_id_be = htobe32(session->peer.id);

    root = json_pack("{ss ss ss si si ss ss si si ss ss* ss* si si si ss so*}",
                     "interface", session->interface->name,
                     "local-address", session->local_address_str,
                     "local-id", format_ipv4_address(&session->config->id),
                     "local-as", session->config->local_as,
                     "local-hold-time", session->config->hold_time,
                     "peer-address", session->peer_address_str,
                     "peer-id", format_ipv4_address(&peer_id_be),
                     "peer-as", session->peer.as,
                     "peer-hold-time", session->peer.hold_time,
                     "state", bgp_session_state_string(session->state),
                     "raw-update-state", raw_update_state(session),
                     "raw-update-file", raw_update_file,
                     "raw-update-start-epoch", session->update_start_timestamp.tv_sec,
                     "raw-update-stop-epoch", session->update_stop_timestamp.tv_sec,
                     "raw-update-duration", session->update_duration.tv_sec,
                     "tcp-auth", session->config->tcp_ao_enabled ?
                                 bbl_tcp_ao_algo_string(session->config->tcp_ao_algo) : "none",
                     "stats", stats);

    if(!root) {
        if(stats) json_decref(stats);
    }
    return root;
}

int
bgp_ctrl_sessions(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root, *sessions, *session;

    bgp_session_s *bgp_session = g_ctx->bgp_sessions;

    const char *s;
    uint32_t ipv4_local_address = 0;
    uint32_t ipv4_peer_address = 0;
    ipv6addr_t ipv6_local_address = {0};
    ipv6addr_t ipv6_peer_address = {0};

    /* Unpack further arguments */
    if(json_unpack(arguments, "{s:s}", "local-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4_local_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid local-ipv4-address");
        }
    }
    if(json_unpack(arguments, "{s:s}", "peer-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4_peer_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid peer-ipv4-address");
        }
    }
    if(json_unpack(arguments, "{s:s}", "local-ipv6-address", &s) == 0) {
        if(!inet_pton(AF_INET6, s, &ipv6_local_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid local-ipv6-address");
        }
    }
    if(json_unpack(arguments, "{s:s}", "peer-ipv6-address", &s) == 0) {
        if(!inet_pton(AF_INET6, s, &ipv6_peer_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid peer-ipv6-address");
        }
    }

    sessions = json_array();
    while(bgp_session) {
        if(ipv4_local_address && bgp_session->ipv4_local_address != ipv4_local_address) {
            bgp_session = bgp_session->next;
            continue;
        }
        if(ipv4_peer_address && bgp_session->ipv4_peer_address != ipv4_peer_address) {
            bgp_session = bgp_session->next;
            continue;
        }
        if(ipv6_addr_not_zero(&ipv6_local_address) && bgp_session->ipv6_local_address && memcmp(bgp_session->ipv6_local_address, ipv6_local_address, sizeof(ipv6addr_t)) != 0) {
            bgp_session = bgp_session->next;
            continue;
        }
        if(ipv6_addr_not_zero(&ipv6_peer_address) && bgp_session->ipv6_peer_address && memcmp(bgp_session->ipv6_peer_address, ipv6_peer_address, sizeof(ipv6addr_t)) != 0) {
            bgp_session = bgp_session->next;
            continue;
        }


        session = bgp_ctrl_session_json(bgp_session);
        if(session) {
            json_array_append_new(sessions, session);
        }
        bgp_session = bgp_session->next;
    }

    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "bgp-sessions", sessions);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(sessions);
    }
    return result;
}

int
bgp_ctrl_teardown(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    bgp_teardown();
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bgp_ctrl_raw_update(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root;

    bgp_session_s *bgp_session = g_ctx->bgp_sessions;
    bgp_raw_update_s *raw_update;

    const char *s;
    const char *file_path;

    uint16_t started = 0;
    uint16_t skipped = 0;
    uint16_t filtered = 0;

    uint32_t ipv4_local_address = 0;
    uint32_t ipv4_peer_address = 0;
    ipv6addr_t ipv6_local_address = {0};
    ipv6addr_t ipv6_peer_address = {0};

    /* Unpack further arguments */
    if(json_unpack(arguments, "{s:s}", "file", &file_path) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing argument file");
    }
    if(json_unpack(arguments, "{s:s}", "local-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4_local_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid local-ipv4-address");
        }
    }
    if(json_unpack(arguments, "{s:s}", "peer-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4_peer_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid peer-ipv4-address");
        }
    }
    if(json_unpack(arguments, "{s:s}", "local-ipv6-address", &s) == 0) {
        if(!inet_pton(AF_INET6, s, &ipv6_local_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid local-ipv6-address");
        }
    }
    if(json_unpack(arguments, "{s:s}", "peer-ipv6-address", &s) == 0) {
        if(!inet_pton(AF_INET6, s, &ipv6_peer_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid peer-ipv6-address");
        }
    }

    /* Load file. */
    raw_update = bgp_raw_update_load(file_path, true);
    if(!raw_update) {
        return bbl_ctrl_status(fd, "error", 400, "failed to load file");
    }

    while(bgp_session) {
        if(ipv4_local_address && bgp_session->ipv4_local_address != ipv4_local_address) {
            bgp_session = bgp_session->next;
            filtered++;
            continue;
        }
        if(ipv4_peer_address && bgp_session->ipv4_peer_address != ipv4_peer_address) {
            bgp_session = bgp_session->next;
            filtered++;
            continue;
        }
        if(ipv6_addr_not_zero(&ipv6_local_address) && bgp_session->ipv6_local_address && memcmp(bgp_session->ipv6_local_address, ipv6_local_address, sizeof(ipv6addr_t)) != 0) {
            bgp_session = bgp_session->next;
            filtered++;
            continue;
        }
        if(ipv6_addr_not_zero(&ipv6_peer_address) && bgp_session->ipv6_peer_address && memcmp(bgp_session->ipv6_peer_address, ipv6_peer_address, sizeof(ipv6addr_t)) != 0) {
            bgp_session = bgp_session->next;
            filtered++;
            continue;
        }
        if(bgp_session->raw_update_sending) {
            bgp_session = bgp_session->next;
            skipped++;
            continue;
        }

        bgp_session->raw_update = raw_update;
        bgp_session->update_start_timestamp.tv_sec = 0;
        bgp_session->update_start_timestamp.tv_nsec = 0;
        timer_add(&g_ctx->timer_root, &bgp_session->update_timer, 
                 "BGP UPDATE", 0, 0, bgp_session,
                 &bgp_session_update_job);
        
        started++;
        bgp_session = bgp_session->next;
    }

    root = json_pack("{ss si s{si si si}}",
                     "status", "ok",
                     "code", 200,
                     "bgp-raw-update",
                     "started", started,
                     "skipped", skipped,
                     "filtered", filtered);

    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
    }
    return result;
}

int
bgp_ctrl_raw_update_list(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    int result = 0;
    bgp_raw_update_s *raw_update = g_ctx->bgp_raw_updates;
    json_t *root, *updates, *update;

    updates = json_array();

    while(raw_update){
        update = json_pack("{ss* si si}",
                           "file", raw_update->file,
                           "len", raw_update->len,
                           "updates", raw_update->updates);
        if(update) {
            json_array_append_new(updates, update);
        }
        raw_update = raw_update->next;
    }
    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "bgp-raw-update-list", updates);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(updates);
    }
    return result;
}

int
bgp_ctrl_disconnect(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root;

    bgp_session_s *bgp_session = g_ctx->bgp_sessions;

    const char *s;

    uint16_t disconnected = 0;
    uint16_t skipped = 0;
    uint16_t filtered = 0;

    uint32_t ipv4_local_address = 0;
    uint32_t ipv4_peer_address = 0;
    ipv6addr_t ipv6_local_address = {0};
    ipv6addr_t ipv6_peer_address = {0};

    /* Unpack further arguments */
    if(json_unpack(arguments, "{s:s}", "local-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4_local_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid local-ipv4-address");
        }
    }
    if(json_unpack(arguments, "{s:s}", "peer-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4_peer_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid peer-ipv4-address");
        }
    }
    if(json_unpack(arguments, "{s:s}", "local-ipv6-address", &s) == 0) {
        if(!inet_pton(AF_INET6, s, &ipv6_local_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid local-ipv6-address");
        }
    }
    if(json_unpack(arguments, "{s:s}", "peer-ipv6-address", &s) == 0) {
        if(!inet_pton(AF_INET6, s, &ipv6_peer_address)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid peer-ipv6-address");
        }
    }

    while(bgp_session) {
        if(ipv4_local_address && bgp_session->ipv4_local_address != ipv4_local_address) {
            bgp_session = bgp_session->next;
            filtered++;
            continue;
        }
        if(ipv4_peer_address && bgp_session->ipv4_peer_address != ipv4_peer_address) {
            bgp_session = bgp_session->next;
            filtered++;
            continue;
        }
        if(ipv6_addr_not_zero(&ipv6_local_address) && bgp_session->ipv6_local_address && memcmp(bgp_session->ipv6_local_address, ipv6_local_address, sizeof(ipv6addr_t)) != 0) {
            bgp_session = bgp_session->next;
            filtered++;
            continue;
        }
        if(ipv6_addr_not_zero(&ipv6_peer_address) && bgp_session->ipv6_peer_address && memcmp(bgp_session->ipv6_peer_address, ipv6_peer_address, sizeof(ipv6addr_t)) != 0) {
            bgp_session = bgp_session->next;
            filtered++;
            continue;
        }
        if(bgp_session->state == BGP_CLOSED || bgp_session->state == BGP_CLOSING) {
            bgp_session = bgp_session->next;
            skipped++;
            continue;
        }
        if(!bgp_session->error_code) {
            bgp_session->error_code = 6; /* Cease */
            bgp_session->error_subcode = 2; /* Shutdown */
        }
        bgp_session_close(bgp_session);
        disconnected++;
        bgp_session = bgp_session->next;
    }

    root = json_pack("{ss si s{si si si}}",
                     "status", "ok",
                     "code", 200,
                     "bgp-disconnect",
                     "disconnected", disconnected,
                     "skipped", skipped,
                     "filtered", filtered);

    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
    }
    return result;
}
static const char *
bgp_ctrl_evpn_ip_string(uint8_t af, uint8_t *ip)
{
    if(af == AF_INET) {
        return format_ipv4_address((uint32_t*)ip);
    } else if(af == AF_INET6) {
        return format_ipv6_address((ipv6addr_t*)ip);
    }
    return NULL;
}

static json_t *
bgp_ctrl_evpn_entry_json(bgp_evpn_entry_s *entry)
{
    bgp_evpn_key_s *key = &entry->key;
    json_t *root, *rts, *pmsi, *l2;
    ipv4_prefix ipv4;
    ipv6_prefix ipv6;
    uint8_t i;

    root = json_object();
    if(!root) {
        return NULL;
    }
    json_object_set_new(root, "route-type", json_integer(key->route_type));
    json_object_set_new(root, "rd", json_string(bgp_evpn_format_rd(key->rd)));
    json_object_set_new(root, "active", json_boolean(entry->active));
    json_object_set_new(root, "version", json_integer(entry->version));
    json_object_set_new(root, "esi", json_string(bgp_evpn_format_esi(entry->esi)));
    if(key->route_type != BGP_EVPN_ROUTE_ES) {
        json_object_set_new(root, "ethernet-tag", json_integer(key->ethernet_tag));
    }
    if(key->route_type == BGP_EVPN_ROUTE_MAC_IP) {
        json_object_set_new(root, "mac", json_string(format_mac_address(key->mac)));
    }
    if(key->route_type == BGP_EVPN_ROUTE_IP_PREFIX) {
        if(key->ip_af == AF_INET) {
            memcpy(&ipv4.address, key->ip, IPV4_ADDR_LEN);
            ipv4.len = key->ip_len;
            json_object_set_new(root, "prefix", json_string(format_ipv4_prefix(&ipv4)));
        } else {
            memcpy(&ipv6.address, key->ip, IPV6_ADDR_LEN);
            ipv6.len = key->ip_len;
            json_object_set_new(root, "prefix", json_string(format_ipv6_prefix(&ipv6)));
        }
        json_object_set_new(root, "gateway", json_string(bgp_ctrl_evpn_ip_string(entry->gateway_af, entry->gateway)));
    } else if(key->ip_af) {
        json_object_set_new(root, "ip", json_string(bgp_ctrl_evpn_ip_string(key->ip_af, key->ip)));
    }
    json_object_set_new(root, "encapsulation", json_string(bgp_evpn_encap_string(entry->encap)));
    if(entry->labels > 0) {
        json_object_set_new(root, "label1", json_integer(entry->label1));
    }
    if(entry->labels > 1) {
        json_object_set_new(root, "label2", json_integer(entry->label2));
    }
    if(entry->nexthop_af) {
        json_object_set_new(root, "nexthop", json_string(bgp_ctrl_evpn_ip_string(entry->nexthop_af, entry->nexthop)));
    }
    if(entry->rt_count) {
        rts = json_array();
        for(i = 0; i < entry->rt_count; i++) {
            json_array_append_new(rts, json_string(bgp_evpn_format_rt(entry->rt[i])));
        }
        json_object_set_new(root, "route-targets", rts);
    }
    if(entry->pmsi.present) {
        pmsi = json_pack("{si si si ss*}",
                         "flags", entry->pmsi.flags,
                         "tunnel-type", entry->pmsi.tunnel_type,
                         "label", entry->pmsi.label,
                         "tunnel-id", bgp_ctrl_evpn_ip_string(entry->pmsi.tunnel_id_af, entry->pmsi.tunnel_id));
        if(pmsi) {
            json_object_set_new(root, "pmsi-tunnel", pmsi);
        }
    }
    if(entry->router_mac_present) {
        json_object_set_new(root, "router-mac", json_string(format_mac_address(entry->router_mac)));
    }
    if(entry->mac_mobility_present) {
        json_object_set_new(root, "mac-mobility-sequence", json_integer(entry->mac_mobility_seq));
        json_object_set_new(root, "sticky", json_boolean(entry->sticky));
    }
    if(entry->esi_label_present) {
        json_object_set_new(root, "esi-label", json_integer(entry->esi_label));
        json_object_set_new(root, "single-active", json_boolean(entry->single_active));
    }
    if(entry->l2_attr_present) {
        l2 = json_pack("{si sb sb sb si}",
                       "flags", entry->l2_flags,
                       "primary", (entry->l2_flags & BGP_EVPN_L2_FLAG_PRIMARY) != 0,
                       "backup", (entry->l2_flags & BGP_EVPN_L2_FLAG_BACKUP) != 0,
                       "control-word", (entry->l2_flags & BGP_EVPN_L2_FLAG_CW) != 0,
                       "mtu", entry->l2_mtu);
        if(l2) {
            json_object_set_new(root, "l2-attributes", l2);
        }
    }
    return root;
}

typedef struct bgp_ctrl_filter_ {
    uint32_t ipv4_local_address;
    uint32_t ipv4_peer_address;
    ipv6addr_t ipv6_local_address;
    ipv6addr_t ipv6_peer_address;
} bgp_ctrl_filter_s;

static const char *
bgp_ctrl_filter_parse(json_t *arguments, bgp_ctrl_filter_s *filter)
{
    const char *s;

    memset(filter, 0x0, sizeof(bgp_ctrl_filter_s));
    if(json_unpack(arguments, "{s:s}", "local-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &filter->ipv4_local_address)) {
            return "invalid local-ipv4-address";
        }
    }
    if(json_unpack(arguments, "{s:s}", "peer-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &filter->ipv4_peer_address)) {
            return "invalid peer-ipv4-address";
        }
    }
    if(json_unpack(arguments, "{s:s}", "local-ipv6-address", &s) == 0) {
        if(!inet_pton(AF_INET6, s, &filter->ipv6_local_address)) {
            return "invalid local-ipv6-address";
        }
    }
    if(json_unpack(arguments, "{s:s}", "peer-ipv6-address", &s) == 0) {
        if(!inet_pton(AF_INET6, s, &filter->ipv6_peer_address)) {
            return "invalid peer-ipv6-address";
        }
    }
    return NULL;
}

static bool
bgp_ctrl_filter_match(bgp_ctrl_filter_s *filter, bgp_session_s *session)
{
    if(filter->ipv4_local_address && session->ipv4_local_address != filter->ipv4_local_address) {
        return false;
    }
    if(filter->ipv4_peer_address && session->ipv4_peer_address != filter->ipv4_peer_address) {
        return false;
    }
    if(ipv6_addr_not_zero(&filter->ipv6_local_address) &&
       !(session->ipv6_local_address && memcmp(session->ipv6_local_address, filter->ipv6_local_address, sizeof(ipv6addr_t)) == 0)) {
        return false;
    }
    if(ipv6_addr_not_zero(&filter->ipv6_peer_address) &&
       !(session->ipv6_peer_address && memcmp(session->ipv6_peer_address, filter->ipv6_peer_address, sizeof(ipv6addr_t)) == 0)) {
        return false;
    }
    return true;
}

int
bgp_ctrl_evpn_routes(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root, *sessions, *session, *routes, *route;
    bgp_session_s *bgp_session = g_ctx->bgp_sessions;
    bgp_ctrl_filter_s filter;
    bgp_evpn_entry_s *entry;
    hb_itor *itor;
    bool next;

    const char *error;
    const char *s;
    int route_type = 0;
    uint8_t rd[BGP_RD_LEN];
    bool rd_filter = false;

    error = bgp_ctrl_filter_parse(arguments, &filter);
    if(error) {
        return bbl_ctrl_status(fd, "error", 400, error);
    }
    if(json_unpack(arguments, "{s:i}", "route-type", &route_type) == 0) {
        if(route_type < BGP_EVPN_ROUTE_AD || route_type > BGP_EVPN_ROUTE_IP_PREFIX) {
            return bbl_ctrl_status(fd, "error", 400, "invalid route-type");
        }
    }
    if(json_unpack(arguments, "{s:s}", "rd", &s) == 0) {
        if(!bgp_evpn_scan_rd(s, rd)) {
            return bbl_ctrl_status(fd, "error", 400, "invalid rd");
        }
        rd_filter = true;
    }

    sessions = json_array();
    while(bgp_session) {
        if(bgp_session->rib.evpn_db && bgp_ctrl_filter_match(&filter, bgp_session)) {
            routes = json_array();
            itor = hb_itor_new(bgp_session->rib.evpn_db);
            next = hb_itor_first(itor);
            while(next) {
                entry = *hb_itor_datum(itor);
                next = hb_itor_next(itor);
                if(route_type && entry->key.route_type != route_type) {
                    continue;
                }
                if(rd_filter && memcmp(entry->key.rd, rd, BGP_RD_LEN) != 0) {
                    continue;
                }
                route = bgp_ctrl_evpn_entry_json(entry);
                if(route) {
                    json_array_append_new(routes, route);
                }
            }
            hb_itor_free(itor);
            session = json_pack("{ss ss ss so}",
                                "interface", bgp_session->interface->name,
                                "local-address", bgp_session->local_address_str,
                                "peer-address", bgp_session->peer_address_str,
                                "routes", routes);
            if(session) {
                json_array_append_new(sessions, session);
            } else {
                json_decref(routes);
            }
        }
        bgp_session = bgp_session->next;
    }

    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "bgp-evpn-routes", sessions);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(sessions);
    }
    return result;
}

static const char *
bgp_ctrl_family_string(uint16_t afi, uint8_t safi)
{
    if(afi == BGP_AFI_IPV4) {
        return safi == BGP_SAFI_UNICAST ? "ipv4-unicast" : "ipv4-labeled-unicast";
    }
    return safi == BGP_SAFI_UNICAST ? "ipv6-unicast" : "ipv6-labeled-unicast";
}

static json_t *
bgp_ctrl_rib_attr_json(json_t *root, bgp_rib_attr_s *attr)
{
    json_t *array;
    uint8_t *data = attr->data + attr->as_path_len;
    uint16_t i;
    char str[64];

    if(attr->nexthop_af) {
        json_object_set_new(root, "nexthop", json_string(bgp_ctrl_evpn_ip_string(attr->nexthop_af, attr->nexthop)));
    }
    if(attr->flags & BGP_RIB_ATTR_ORIGIN) {
        switch(attr->origin) {
            case 0: json_object_set_new(root, "origin", json_string("igp")); break;
            case 1: json_object_set_new(root, "origin", json_string("egp")); break;
            default: json_object_set_new(root, "origin", json_string("incomplete")); break;
        }
    }
    json_object_set_new(root, "as-path", json_string(bgp_rib_format_as_path(attr)));
    if(attr->flags & BGP_RIB_ATTR_MED) {
        json_object_set_new(root, "med", json_integer(attr->med));
    }
    if(attr->flags & BGP_RIB_ATTR_LOCAL_PREF) {
        json_object_set_new(root, "local-pref", json_integer(attr->local_pref));
    }
    if(attr->communities_len) {
        array = json_array();
        for(i = 0; i < attr->communities_len; i += 4) {
            snprintf(str, sizeof(str), "%u:%u",
                     (uint32_t)read_be_uint(data+i, 2),
                     (uint32_t)read_be_uint(data+i+2, 2));
            json_array_append_new(array, json_string(str));
        }
        json_object_set_new(root, "communities", array);
        data += attr->communities_len;
    }
    if(attr->large_communities_len) {
        array = json_array();
        for(i = 0; i < attr->large_communities_len; i += 12) {
            snprintf(str, sizeof(str), "%u:%u:%u",
                     (uint32_t)read_be_uint(data+i, 4),
                     (uint32_t)read_be_uint(data+i+4, 4),
                     (uint32_t)read_be_uint(data+i+8, 4));
            json_array_append_new(array, json_string(str));
        }
        json_object_set_new(root, "large-communities", array);
        data += attr->large_communities_len;
    }
    if(attr->ext_communities_len) {
        array = json_array();
        for(i = 0; i < attr->ext_communities_len; i += 8) {
            if(data[i] <= 0x02 && data[i+1] == 0x02) {
                snprintf(str, sizeof(str), "rt:%s", bgp_evpn_format_rt(data+i));
            } else if(data[i] <= 0x02 && data[i+1] == 0x03) {
                snprintf(str, sizeof(str), "soo:%s", bgp_evpn_format_rt(data+i));
            } else {
                snprintf(str, sizeof(str), "0x%016lx", (unsigned long)read_be_uint(data+i, 8));
            }
            json_array_append_new(array, json_string(str));
        }
        json_object_set_new(root, "extended-communities", array);
    }
    return root;
}

static json_t *
bgp_ctrl_rib_route_json(uint16_t afi, bgp_rib_route_s *route)
{
    json_t *root;
    ipv4_prefix ipv4;
    ipv6_prefix ipv6;

    root = json_object();
    if(!root) {
        return NULL;
    }
    json_object_set_new(root, "family", json_string(bgp_ctrl_family_string(afi, route->safi)));
    if(afi == BGP_AFI_IPV4) {
        memcpy(&ipv4.address, route->prefix, IPV4_ADDR_LEN);
        ipv4.len = route->prefix_len;
        json_object_set_new(root, "prefix", json_string(format_ipv4_prefix(&ipv4)));
    } else {
        memcpy(&ipv6.address, route->prefix, IPV6_ADDR_LEN);
        ipv6.len = route->prefix_len;
        json_object_set_new(root, "prefix", json_string(format_ipv6_prefix(&ipv6)));
    }
    if(route->safi == BGP_SAFI_LABELED_UNICAST) {
        json_object_set_new(root, "label", json_integer(route->label));
    }
    return bgp_ctrl_rib_attr_json(root, route->attr);
}

static void
bgp_ctrl_rib_route_append(json_t *routes, uint16_t afi, bgp_rib_route_s *route)
{
    json_t *json_route = bgp_ctrl_rib_route_json(afi, route);
    if(json_route) {
        json_array_append_new(routes, json_route);
    }
}

/*
 * Append all routes matching the prefix filter (exact match or
 * exact and longer match). Routes are ordered by SAFI, prefix and
 * prefix length, so all longer matches of a prefix are adjacent.
 */
static void
bgp_ctrl_rib_routes_match(json_t *routes, hb_tree *tree, uint16_t afi, uint8_t safi,
                          bgp_rib_route_s *prefix, bool longer)
{
    bgp_rib_route_s key = *prefix;
    bgp_rib_route_s *route;
    uint8_t masked[IPV6_ADDR_LEN];
    uint8_t af = afi == BGP_AFI_IPV4 ? AF_INET : AF_INET6;
    void **search;
    hb_itor *itor;
    bool next;

    key.safi = safi;
    if(!longer) {
        search = hb_tree_search(tree, &key);
        if(search) {
            bgp_ctrl_rib_route_append(routes, afi, *search);
        }
        return;
    }

    key.prefix_len = 0;
    itor = hb_itor_new(tree);
    next = hb_itor_search_ge(itor, &key);
    while(next) {
        route = *hb_itor_datum(itor);
        next = hb_itor_next(itor);
        if(route->safi != safi) {
            break;
        }
        memcpy(masked, route->prefix, IPV6_ADDR_LEN);
        bgp_evpn_mask_ip(masked, af, prefix->prefix_len);
        if(memcmp(masked, prefix->prefix, IPV6_ADDR_LEN) != 0) {
            break;
        }
        /* Skip shorter prefixes with same address (e.g. 10.0.0.0/8 for 10.0.0.0/24). */
        if(route->prefix_len >= prefix->prefix_len) {
            bgp_ctrl_rib_route_append(routes, afi, route);
        }
    }
    hb_itor_free(itor);
}

static void
bgp_ctrl_rib_routes(json_t *routes, hb_tree *tree, uint16_t afi, int safi,
                    bgp_rib_route_s *prefix, bool longer)
{
    bgp_rib_route_s *route;
    hb_itor *itor;
    bool next;

    if(prefix) {
        if(!safi || safi == BGP_SAFI_UNICAST) {
            bgp_ctrl_rib_routes_match(routes, tree, afi, BGP_SAFI_UNICAST, prefix, longer);
        }
        if(!safi || safi == BGP_SAFI_LABELED_UNICAST) {
            bgp_ctrl_rib_routes_match(routes, tree, afi, BGP_SAFI_LABELED_UNICAST, prefix, longer);
        }
        return;
    }

    itor = hb_itor_new(tree);
    next = hb_itor_first(itor);
    while(next) {
        route = *hb_itor_datum(itor);
        next = hb_itor_next(itor);
        if(safi && route->safi != safi) {
            continue;
        }
        bgp_ctrl_rib_route_append(routes, afi, route);
    }
    hb_itor_free(itor);
}

int
bgp_ctrl_routes(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root, *sessions, *session, *routes;
    bgp_session_s *bgp_session = g_ctx->bgp_sessions;
    bgp_ctrl_filter_s filter;
    bgp_rib_route_s prefix = {0};
    bgp_rib_route_s *prefix_filter = NULL;
    ipv4_prefix ipv4;
    ipv6_prefix ipv6;
    const char *error;
    const char *s;
    uint16_t afi = 0;
    int safi = 0;
    bool longer = false;

    error = bgp_ctrl_filter_parse(arguments, &filter);
    if(error) {
        return bbl_ctrl_status(fd, "error", 400, error);
    }
    if(json_unpack(arguments, "{s:s}", "family", &s) == 0) {
        if(strcmp(s, "ipv4-unicast") == 0) {
            afi = BGP_AFI_IPV4; safi = BGP_SAFI_UNICAST;
        } else if(strcmp(s, "ipv4-labeled-unicast") == 0) {
            afi = BGP_AFI_IPV4; safi = BGP_SAFI_LABELED_UNICAST;
        } else if(strcmp(s, "ipv6-unicast") == 0) {
            afi = BGP_AFI_IPV6; safi = BGP_SAFI_UNICAST;
        } else if(strcmp(s, "ipv6-labeled-unicast") == 0) {
            afi = BGP_AFI_IPV6; safi = BGP_SAFI_LABELED_UNICAST;
        } else {
            return bbl_ctrl_status(fd, "error", 400, "invalid family");
        }
    }
    if(json_unpack(arguments, "{s:s}", "prefix", &s) == 0) {
        if(scan_ipv4_prefix(s, &ipv4)) {
            if(afi == BGP_AFI_IPV6) {
                return bbl_ctrl_status(fd, "error", 400, "invalid prefix for family");
            }
            afi = BGP_AFI_IPV4;
            memcpy(prefix.prefix, &ipv4.address, IPV4_ADDR_LEN);
            prefix.prefix_len = ipv4.len;
            bgp_evpn_mask_ip(prefix.prefix, AF_INET, prefix.prefix_len);
        } else if(scan_ipv6_prefix(s, &ipv6)) {
            if(afi == BGP_AFI_IPV4) {
                return bbl_ctrl_status(fd, "error", 400, "invalid prefix for family");
            }
            afi = BGP_AFI_IPV6;
            memcpy(prefix.prefix, &ipv6.address, IPV6_ADDR_LEN);
            prefix.prefix_len = ipv6.len;
            bgp_evpn_mask_ip(prefix.prefix, AF_INET6, prefix.prefix_len);
        } else {
            return bbl_ctrl_status(fd, "error", 400, "invalid prefix");
        }
        prefix_filter = &prefix;
    }
    if(json_unpack(arguments, "{s:s}", "match", &s) == 0) {
        if(strcmp(s, "longer") == 0) {
            longer = true;
        } else if(strcmp(s, "exact") != 0) {
            return bbl_ctrl_status(fd, "error", 400, "invalid match (exact or longer)");
        }
        if(!prefix_filter) {
            return bbl_ctrl_status(fd, "error", 400, "missing prefix");
        }
    }

    sessions = json_array();
    while(bgp_session) {
        if(bgp_session->rib.ipv4 && bgp_ctrl_filter_match(&filter, bgp_session)) {
            routes = json_array();
            if(afi != BGP_AFI_IPV6) {
                bgp_ctrl_rib_routes(routes, bgp_session->rib.ipv4, BGP_AFI_IPV4, safi, prefix_filter, longer);
            }
            if(afi != BGP_AFI_IPV4) {
                bgp_ctrl_rib_routes(routes, bgp_session->rib.ipv6, BGP_AFI_IPV6, safi, prefix_filter, longer);
            }
            session = json_pack("{ss ss ss so}",
                                "interface", bgp_session->interface->name,
                                "local-address", bgp_session->local_address_str,
                                "peer-address", bgp_session->peer_address_str,
                                "routes", routes);
            if(session) {
                json_array_append_new(sessions, session);
            } else {
                json_decref(routes);
            }
        }
        bgp_session = bgp_session->next;
    }

    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "bgp-routes", sessions);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(sessions);
    }
    return result;
}

int
bgp_ctrl_routes_stats(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    json_t *root, *sessions, *session;
    bgp_session_s *bgp_session = g_ctx->bgp_sessions;
    bgp_ctrl_filter_s filter;
    const char *error;

    error = bgp_ctrl_filter_parse(arguments, &filter);
    if(error) {
        return bbl_ctrl_status(fd, "error", 400, error);
    }

    sessions = json_array();
    while(bgp_session) {
        if(bgp_ctrl_filter_match(&filter, bgp_session)) {
            session = json_pack("{ss ss ss ss sb si si si si si si si si si si}",
                                "interface", bgp_session->interface->name,
                                "local-address", bgp_session->local_address_str,
                                "peer-address", bgp_session->peer_address_str,
                                "state", bgp_session_state_string(bgp_session->state),
                                "learn-routes", bgp_session->config->learn_routes,
                                "ipv4-unicast", bgp_session->rib.ipv4_unicast,
                                "ipv4-labeled-unicast", bgp_session->rib.ipv4_labeled_unicast,
                                "ipv6-unicast", bgp_session->rib.ipv6_unicast,
                                "ipv6-labeled-unicast", bgp_session->rib.ipv6_labeled_unicast,
                                "evpn", bgp_session->rib.evpn,
                                "attribute-sets", bgp_session->rib.attr ? (int)hashtable2_count(bgp_session->rib.attr) : 0,
                                "route-reach-rx", bgp_session->stats.route_reach_rx,
                                "route-withdraw-rx", bgp_session->stats.route_withdraw_rx,
                                "evpn-reach-rx", bgp_session->stats.evpn_reach_rx,
                                "evpn-withdraw-rx", bgp_session->stats.evpn_withdraw_rx);
            if(session) {
                json_array_append_new(sessions, session);
            }
        }
        bgp_session = bgp_session->next;
    }

    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "bgp-routes-stats", sessions);
    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
        json_decref(sessions);
    }
    return result;
}
