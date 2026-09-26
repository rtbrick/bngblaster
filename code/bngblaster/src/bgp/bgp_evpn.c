/*
 * BNG Blaster (BBL) - BGP EVPN
 *
 * EVPN route learning (RFC 7432, RFC 8365, RFC 9136) used
 * to resolve dynamic VPN labels for traffic streams.
 *
 * Christian Giese, September 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"

#define BGP_EVPN_STR_LEN 32

/* Decoded EVPN NLRI (route key and non-key fields). */
typedef struct bgp_evpn_route_ {
    bgp_evpn_key_s key;
    uint8_t  esi[BGP_ESI_LEN];
    uint8_t  gateway_af;
    uint8_t  gateway[IPV6_ADDR_LEN];
    uint8_t  labels;
    uint32_t label[2]; /* raw 3 byte label fields */
} bgp_evpn_route_s;

static int
bgp_evpn_compare(void *key1, void *key2)
{
    return memcmp(key1, key2, sizeof(bgp_evpn_key_s));
}

bool
bgp_evpn_init(bgp_session_s *session)
{
    session->rib.evpn_db = hb_tree_new((dict_compare_func)bgp_evpn_compare);
    return session->rib.evpn_db != NULL;
}

/* Encapsulations which carry a 24 bit VNI instead of an MPLS label (RFC 8365). */
static bool
bgp_evpn_encap_vni(uint16_t encap)
{
    switch(encap) {
        case BGP_ENCAP_VXLAN:
        case BGP_ENCAP_NVGRE:
        case BGP_ENCAP_VXLAN_GPE:
        case BGP_ENCAP_GENEVE:
            return true;
        default:
            return false;
    }
}

static uint32_t
bgp_evpn_label(uint16_t encap, uint32_t raw)
{
    if(bgp_evpn_encap_vni(encap)) {
        return raw;
    }
    /* 20 bit MPLS label in the high-order bits. */
    return raw >> 4;
}

const char *
bgp_evpn_encap_string(uint16_t encap)
{
    switch(encap) {
        case 0: return "mpls";
        case BGP_ENCAP_VXLAN: return "vxlan";
        case BGP_ENCAP_NVGRE: return "nvgre";
        case BGP_ENCAP_MPLS: return "mpls";
        case 11: return "mpls-gre";
        case BGP_ENCAP_VXLAN_GPE: return "vxlan-gpe";
        case 13: return "mpls-udp";
        case BGP_ENCAP_GENEVE: return "geneve";
        default: return "unknown";
    }
}

void
bgp_evpn_mask_ip(uint8_t *ip, uint8_t af, uint8_t len)
{
    uint8_t bytes = (af == AF_INET6) ? IPV6_ADDR_LEN : IPV4_ADDR_LEN;
    uint8_t i;

    for(i = 0; i < bytes; i++) {
        if(len >= 8) {
            len -= 8;
        } else {
            ip[i] &= (uint8_t)(0xff << (8 - len));
            len = 0;
        }
    }
}

static bool
bgp_evpn_read_ip(uint8_t *buf, uint8_t bits, uint8_t *af, uint8_t *ip)
{
    if(bits == 32) {
        *af = AF_INET;
        memcpy(ip, buf, IPV4_ADDR_LEN);
    } else if(bits == 128) {
        *af = AF_INET6;
        memcpy(ip, buf, IPV6_ADDR_LEN);
    } else {
        return false;
    }
    return true;
}

/*
 * Decode a single EVPN NLRI. The route key is normalized
 * (zero padded, prefix masked) for exact match lookups.
 */
static bool
bgp_evpn_decode_route(uint8_t type, uint8_t *buf, uint8_t len, bgp_evpn_route_s *route)
{
    bgp_evpn_key_s *key = &route->key;
    uint8_t ip_bits, ip_bytes, remaining;

    memset(route, 0x0, sizeof(bgp_evpn_route_s));
    key->route_type = type;
    if(len < BGP_RD_LEN) {
        return false;
    }
    memcpy(key->rd, buf, BGP_RD_LEN);
    buf += BGP_RD_LEN; len -= BGP_RD_LEN;

    switch(type) {
        case BGP_EVPN_ROUTE_AD:
            /* ESI (10), Ethernet Tag (4), Label (3) */
            if(len != 17) return false;
            memcpy(key->esi, buf, BGP_ESI_LEN);
            memcpy(route->esi, buf, BGP_ESI_LEN);
            key->ethernet_tag = read_be_uint(buf+10, 4);
            route->label[0] = read_be_uint(buf+14, 3);
            route->labels = 1;
            break;
        case BGP_EVPN_ROUTE_MAC_IP:
            /* ESI (10), Ethernet Tag (4), MAC Length (1), MAC (6),
             * IP Length (1), IP (0/4/16), Label1 (3), Label2 (0/3) */
            if(len < 25) return false;
            memcpy(route->esi, buf, BGP_ESI_LEN);
            key->ethernet_tag = read_be_uint(buf+10, 4);
            if(buf[14] != 48) return false;
            memcpy(key->mac, buf+15, ETH_ADDR_LEN);
            ip_bits = buf[21];
            ip_bytes = ip_bits / 8;
            if(ip_bits) {
                if(len < 22 + ip_bytes) return false;
                if(!bgp_evpn_read_ip(buf+22, ip_bits, &key->ip_af, key->ip)) return false;
                key->ip_len = ip_bits;
            }
            remaining = len - 22 - ip_bytes;
            buf += 22 + ip_bytes;
            if(remaining == 3) {
                route->label[0] = read_be_uint(buf, 3);
                route->labels = 1;
            } else if(remaining == 6) {
                route->label[0] = read_be_uint(buf, 3);
                route->label[1] = read_be_uint(buf+3, 3);
                route->labels = 2;
            } else {
                return false;
            }
            break;
        case BGP_EVPN_ROUTE_IMET:
            /* Ethernet Tag (4), IP Length (1), IP (4/16) */
            if(len < 5) return false;
            key->ethernet_tag = read_be_uint(buf, 4);
            ip_bits = buf[4];
            if(len != 5 + ip_bits / 8) return false;
            if(!bgp_evpn_read_ip(buf+5, ip_bits, &key->ip_af, key->ip)) return false;
            key->ip_len = ip_bits;
            break;
        case BGP_EVPN_ROUTE_ES:
            /* ESI (10), IP Length (1), IP (4/16) */
            if(len < 11) return false;
            memcpy(key->esi, buf, BGP_ESI_LEN);
            memcpy(route->esi, buf, BGP_ESI_LEN);
            ip_bits = buf[10];
            if(len != 11 + ip_bits / 8) return false;
            if(!bgp_evpn_read_ip(buf+11, ip_bits, &key->ip_af, key->ip)) return false;
            key->ip_len = ip_bits;
            break;
        case BGP_EVPN_ROUTE_IP_PREFIX:
            /* ESI (10), Ethernet Tag (4), IP Prefix Length (1),
             * IP Prefix (4/16), GW IP (4/16), Label (3) */
            if(len == 26) {
                key->ip_af = AF_INET;
                ip_bytes = IPV4_ADDR_LEN;
            } else if(len == 50) {
                key->ip_af = AF_INET6;
                ip_bytes = IPV6_ADDR_LEN;
            } else {
                return false;
            }
            memcpy(route->esi, buf, BGP_ESI_LEN);
            key->ethernet_tag = read_be_uint(buf+10, 4);
            key->ip_len = buf[14];
            if(key->ip_len > ip_bytes * 8) return false;
            memcpy(key->ip, buf+15, ip_bytes);
            bgp_evpn_mask_ip(key->ip, key->ip_af, key->ip_len);
            route->gateway_af = key->ip_af;
            memcpy(route->gateway, buf+15+ip_bytes, ip_bytes);
            route->label[0] = read_be_uint(buf+15+(2*ip_bytes), 3);
            route->labels = 1;
            break;
        default:
            return false;
    }
    return true;
}

static void
bgp_evpn_decode_ext_communities(uint8_t *buf, uint16_t len, bgp_evpn_entry_s *attr)
{
    uint8_t type, sub_type;

    while(len >= 8) {
        type = buf[0];
        sub_type = buf[1];
        switch(type) {
            case 0x00: /* Transitive Two-Octet AS-Specific */
            case 0x01: /* Transitive IPv4-Address-Specific */
            case 0x02: /* Transitive Four-Octet AS-Specific */
                if(sub_type == 0x02 && attr->rt_count < BGP_EVPN_MAX_RT) {
                    memcpy(attr->rt[attr->rt_count++], buf, 8);
                }
                break;
            case 0x03: /* Transitive Opaque */
                if(sub_type == 0x0c) { /* Encapsulation (RFC 9012) */
                    attr->encap = read_be_uint(buf+6, 2);
                }
                break;
            case 0x06: /* EVPN (RFC 7432) */
                switch(sub_type) {
                    case 0x00: /* MAC Mobility */
                        attr->mac_mobility_present = true;
                        attr->sticky = buf[2] & 0x01;
                        attr->mac_mobility_seq = read_be_uint(buf+4, 4);
                        break;
                    case 0x01: /* ESI Label */
                        attr->esi_label_present = true;
                        attr->single_active = buf[2] & 0x01;
                        attr->esi_label = read_be_uint(buf+5, 3);
                        break;
                    case 0x03: /* Router's MAC (RFC 9135) */
                        attr->router_mac_present = true;
                        memcpy(attr->router_mac, buf+2, ETH_ADDR_LEN);
                        break;
                    case 0x04: /* Layer 2 Attributes (RFC 8214) */
                        attr->l2_attr_present = true;
                        attr->l2_flags = read_be_uint(buf+2, 2);
                        attr->l2_mtu = read_be_uint(buf+4, 2);
                        break;
                    default:
                        break;
                }
                break;
            default:
                break;
        }
        buf += 8;
        len -= 8;
    }
}

static bool
bgp_evpn_decode_pmsi_tunnel(uint8_t *buf, uint16_t len, bgp_evpn_entry_s *attr)
{
    /* Flags (1), Tunnel Type (1), MPLS Label (3), Tunnel Identifier */
    if(len < 5) {
        return false;
    }
    attr->pmsi.present = true;
    attr->pmsi.flags = buf[0];
    attr->pmsi.tunnel_type = buf[1];
    attr->pmsi.label = read_be_uint(buf+2, 3);
    if(len == 5 + IPV4_ADDR_LEN) {
        attr->pmsi.tunnel_id_af = AF_INET;
        memcpy(attr->pmsi.tunnel_id, buf+5, IPV4_ADDR_LEN);
    } else if(len == 5 + IPV6_ADDR_LEN) {
        attr->pmsi.tunnel_id_af = AF_INET6;
        memcpy(attr->pmsi.tunnel_id, buf+5, IPV6_ADDR_LEN);
    }
    return true;
}

/* Fields after version, updated in place for existing entries. */
#define BGP_EVPN_ENTRY_DATA_OFFSET offsetof(bgp_evpn_entry_s, encap)

static void
bgp_evpn_db_add(bgp_session_s *session, bgp_evpn_route_s *route, bgp_evpn_entry_s *attr)
{
    void **search = NULL;
    dict_insert_result result;
    bgp_evpn_entry_s *entry;
    bgp_evpn_entry_s update = *attr;
    uint16_t encap = attr->encap;

    /* Build the complete new state first because traffic streams
     * (TX threads) read the entries while they are updated. */
    update.key = route->key;
    memcpy(update.esi, route->esi, BGP_ESI_LEN);
    update.gateway_af = route->gateway_af;
    memcpy(update.gateway, route->gateway, IPV6_ADDR_LEN);
    update.labels = route->labels;
    update.label1 = route->labels > 0 ? bgp_evpn_label(encap, route->label[0]) : 0;
    update.label2 = route->labels > 1 ? bgp_evpn_label(encap, route->label[1]) : 0;
    if(update.pmsi.present) {
        update.pmsi.label = bgp_evpn_label(encap, update.pmsi.label);
    }
    if(update.esi_label_present) {
        update.esi_label = bgp_evpn_label(encap, update.esi_label);
    }

    /* The L3 label of MAC/IP routes (symmetric IRB) or the IP prefix
     * label can be used for IP traffic, the label of per-EVI A-D
     * routes for EVPN VPWS (E-LINE) traffic. */
    update.vpn_label_valid = false;
    update.vpn_label = 0;
    if(!bgp_evpn_encap_vni(encap)) {
        if(update.key.route_type == BGP_EVPN_ROUTE_AD && update.key.ethernet_tag != BGP_EVPN_MAX_ET) {
            update.vpn_label_valid = true;
            update.vpn_label = update.label1;
        } else if(update.key.route_type == BGP_EVPN_ROUTE_MAC_IP && update.labels == 2) {
            update.vpn_label_valid = true;
            update.vpn_label = update.label2;
        } else if(update.key.route_type == BGP_EVPN_ROUTE_IP_PREFIX) {
            update.vpn_label_valid = true;
            update.vpn_label = update.label1;
        }
    }
    update.source = session;
    update.active = true;

    search = hb_tree_search(session->rib.evpn_db, &route->key);
    if(search) {
        entry = *search;
        if(!entry->active) {
            session->rib.evpn++;
        }
        /* The key must not change while stored in the tree and the
         * version is updated last to trigger stream packet rebuild. */
        memcpy((uint8_t*)entry + BGP_EVPN_ENTRY_DATA_OFFSET,
               (uint8_t*)&update + BGP_EVPN_ENTRY_DATA_OFFSET,
               sizeof(bgp_evpn_entry_s) - BGP_EVPN_ENTRY_DATA_OFFSET);
        __atomic_store_n(&entry->active, true, __ATOMIC_RELEASE);
        __atomic_store_n(&entry->version, entry->version + 1, __ATOMIC_RELEASE);
    } else {
        entry = malloc(sizeof(bgp_evpn_entry_s));
        if(!entry) {
            LOG(ERROR, "BGP (%s %s - %s) failed to add EVPN route to database (out of memory)\n",
                session->interface->name,
                session->local_address_str,
                session->peer_address_str);
            return;
        }
        *entry = update;
        entry->version = 1;
        result = hb_tree_insert(session->rib.evpn_db, &entry->key);
        if(!result.inserted) {
            free(entry);
            LOG(ERROR, "BGP (%s %s - %s) failed to add EVPN route to database\n",
                session->interface->name,
                session->local_address_str,
                session->peer_address_str);
            return;
        }
        *result.datum_ptr = entry;
        session->rib.evpn++;
    }
    g_ctx->bgp_evpn_version++;
}

static void
bgp_evpn_db_withdraw(bgp_session_s *session, bgp_evpn_route_s *route)
{
    void **search = NULL;
    bgp_evpn_entry_s *entry;

    search = hb_tree_search(session->rib.evpn_db, &route->key);
    if(search) {
        entry = *search;
        if(entry->active) {
            entry->active = false;
            entry->version++;
            session->rib.evpn--;
            g_ctx->bgp_evpn_version++;
        }
    }
}

static bool
bgp_evpn_nlri(bgp_session_s *session, uint8_t *buf, uint16_t len, bgp_evpn_entry_s *attr)
{
    bgp_evpn_route_s route;
    uint8_t type, route_len;

    while(len) {
        if(len < 2) {
            return false;
        }
        type = buf[0];
        route_len = buf[1];
        buf += 2; len -= 2;
        if(route_len > len) {
            return false;
        }
        if(type >= BGP_EVPN_ROUTE_AD && type <= BGP_EVPN_ROUTE_IP_PREFIX) {
            if(!bgp_evpn_decode_route(type, buf, route_len, &route)) {
                /* The route boundaries are known, so only this route is
                 * ignored instead of resetting the session (RFC 7606). */
                LOG(BGP, "BGP (%s %s - %s) ignore invalid EVPN route type %u (length %u)\n",
                    session->interface->name,
                    session->local_address_str,
                    session->peer_address_str,
                    type, route_len);
            } else if(attr) {
                session->stats.evpn_reach_rx++;
                bgp_evpn_db_add(session, &route, attr);
            } else {
                session->stats.evpn_withdraw_rx++;
                bgp_evpn_db_withdraw(session, &route);
            }
        } else {
            LOG(DEBUG, "BGP (%s %s - %s) ignore EVPN route type %u\n",
                session->interface->name,
                session->local_address_str,
                session->peer_address_str,
                type);
        }
        buf += route_len; len -= route_len;
    }
    return true;
}

/**
 * bgp_evpn_update
 *
 * Learn or withdraw EVPN routes from the MP_REACH_NLRI
 * and MP_UNREACH_NLRI attributes of a received UPDATE.
 *
 * @param session BGP session
 * @param update path attributes of the UPDATE message
 * @return false if the EVPN NLRI can't be parsed (session reset)
 */
bool
bgp_evpn_update(bgp_session_s *session, bgp_update_s *update)
{
    bgp_evpn_entry_s attr;
    uint8_t nh_len;

    if(!session->rib.evpn_db) {
        return true;
    }

    if(update->mp_unreach &&
       update->mp_unreach_afi == BGP_AFI_L2VPN &&
       update->mp_unreach_safi == BGP_SAFI_EVPN) {
        if(!bgp_evpn_nlri(session, update->mp_unreach_nlri, update->mp_unreach_nlri_len, NULL)) {
            return false;
        }
    }

    if(update->mp_reach &&
       update->mp_reach_afi == BGP_AFI_L2VPN &&
       update->mp_reach_safi == BGP_SAFI_EVPN) {
        memset(&attr, 0x0, sizeof(attr));
        nh_len = update->mp_reach_nexthop_len;
        if(nh_len == IPV4_ADDR_LEN) {
            attr.nexthop_af = AF_INET;
            memcpy(attr.nexthop, update->mp_reach_nexthop, IPV4_ADDR_LEN);
        } else if(nh_len >= IPV6_ADDR_LEN) {
            /* Global address optionally followed by link-local address. */
            attr.nexthop_af = AF_INET6;
            memcpy(attr.nexthop, update->mp_reach_nexthop, IPV6_ADDR_LEN);
        }
        if(update->ext_communities) {
            bgp_evpn_decode_ext_communities(update->ext_communities,
                                            update->ext_communities_len, &attr);
        }
        if(update->pmsi_tunnel &&
           !bgp_evpn_decode_pmsi_tunnel(update->pmsi_tunnel,
                                        update->pmsi_tunnel_len, &attr)) {
            /* Malformed attribute: treat-as-withdraw (RFC 7606). */
            LOG(BGP, "BGP (%s %s - %s) invalid PMSI tunnel attribute (treat-as-withdraw)\n",
                session->interface->name,
                session->local_address_str,
                session->peer_address_str);
            return bgp_evpn_nlri(session, update->mp_reach_nlri, update->mp_reach_nlri_len, NULL);
        }
        if(!bgp_evpn_nlri(session, update->mp_reach_nlri, update->mp_reach_nlri_len, &attr)) {
            return false;
        }
    }
    return true;
}

/**
 * bgp_evpn_session_down
 *
 * Mark all EVPN routes learned from this session as inactive.
 * Entries are kept because traffic streams hold references.
 *
 * @param session BGP session
 */
void
bgp_evpn_session_down(bgp_session_s *session)
{
    bgp_evpn_entry_s *entry;
    hb_itor *itor;
    bool next;

    if(!(session->rib.evpn_db && session->rib.evpn)) {
        return;
    }
    itor = hb_itor_new(session->rib.evpn_db);
    next = hb_itor_first(itor);
    while(next) {
        entry = *hb_itor_datum(itor);
        if(entry->active) {
            entry->active = false;
            entry->version++;
        }
        next = hb_itor_next(itor);
    }
    hb_itor_free(itor);
    session->rib.evpn = 0;
    g_ctx->bgp_evpn_version++;
}

/**
 * bgp_evpn_lookup
 *
 * Search all sessions (in configuration order) for an active
 * EVPN route with a label usable for traffic streams.
 *
 * @param key EVPN route key
 * @return EVPN entry of the first matching session or NULL
 */
bgp_evpn_entry_s *
bgp_evpn_lookup(bgp_evpn_key_s *key)
{
    bgp_session_s *session = g_ctx->bgp_sessions;
    bgp_evpn_entry_s *entry;
    void **search = NULL;

    while(session) {
        if(session->rib.evpn) {
            search = hb_tree_search(session->rib.evpn_db, key);
            if(search) {
                entry = *search;
                if(entry->active && entry->vpn_label_valid) {
                    return entry;
                }
            }
        }
        session = session->next;
    }
    return NULL;
}

/**
 * bgp_evpn_scan_rd
 *
 * Parse a route distinguisher (RFC 4364) from string:
 * <ipv4>:<number> (type 1), <as>:<number> (type 0 if AS
 * fits in two octets, otherwise type 2) or <as>L:<number>
 * (type 2).
 *
 * @param str input string
 * @param rd output buffer (8 bytes)
 * @return true on success
 */
bool
bgp_evpn_scan_rd(const char *str, uint8_t *rd)
{
    char admin[64];
    const char *sep;
    char *end;
    size_t admin_len;
    unsigned long long as, number;
    uint32_t ipv4;
    bool four_octet = false;

    sep = strrchr(str, ':');
    if(!sep) {
        return false;
    }
    admin_len = sep - str;
    if(admin_len == 0 || admin_len >= sizeof(admin)) {
        return false;
    }
    memcpy(admin, str, admin_len);
    admin[admin_len] = '\0';

    errno = 0;
    number = strtoull(sep+1, &end, 10);
    if(errno || *end || end == sep+1) {
        return false;
    }

    if(strchr(admin, '.')) {
        if(inet_pton(AF_INET, admin, &ipv4) != 1 || number > UINT16_MAX) {
            return false;
        }
        write_be_uint(rd, 2, 1);
        memcpy(rd+2, &ipv4, IPV4_ADDR_LEN);
        write_be_uint(rd+6, 2, number);
        return true;
    }

    if(admin[admin_len-1] == 'L' || admin[admin_len-1] == 'l') {
        four_octet = true;
        admin[admin_len-1] = '\0';
    }
    as = strtoull(admin, &end, 10);
    if(errno || *end || end == admin || as > UINT32_MAX) {
        return false;
    }
    if(four_octet || as > UINT16_MAX) {
        if(number > UINT16_MAX) {
            return false;
        }
        write_be_uint(rd, 2, 2);
        write_be_uint(rd+2, 4, as);
        write_be_uint(rd+6, 2, number);
    } else {
        if(number > UINT32_MAX) {
            return false;
        }
        write_be_uint(rd, 2, 0);
        write_be_uint(rd+2, 2, as);
        write_be_uint(rd+4, 4, number);
    }
    return true;
}

/* Format the 6 byte value of a RD or RT with the given type. */
static char *
bgp_evpn_format_admin_value(uint16_t type, uint8_t *value)
{
    static char buffer[32][BGP_EVPN_STR_LEN];
    static int idx = 0;
    char *ret;
    uint32_t ipv4;
    uint32_t as;

    ret = buffer[idx];
    idx = (idx+1) & 31;

    switch(type) {
        case 0:
            snprintf(ret, BGP_EVPN_STR_LEN, "%u:%u",
                     (uint32_t)read_be_uint(value, 2),
                     (uint32_t)read_be_uint(value+2, 4));
            break;
        case 1:
            memcpy(&ipv4, value, IPV4_ADDR_LEN);
            snprintf(ret, BGP_EVPN_STR_LEN, "%s:%u",
                     format_ipv4_address(&ipv4),
                     (uint32_t)read_be_uint(value+4, 2));
            break;
        case 2:
            as = read_be_uint(value, 4);
            /* Add L suffix if not distinguishable from type 0. */
            snprintf(ret, BGP_EVPN_STR_LEN, as > UINT16_MAX ? "%u:%u" : "%uL:%u",
                     as, (uint32_t)read_be_uint(value+4, 2));
            break;
        default:
            snprintf(ret, BGP_EVPN_STR_LEN, "%u:%02x%02x%02x%02x%02x%02x", type,
                     value[0], value[1], value[2], value[3], value[4], value[5]);
            break;
    }
    return ret;
}

char *
bgp_evpn_format_rd(uint8_t *rd)
{
    return bgp_evpn_format_admin_value(read_be_uint(rd, 2), rd+2);
}

char *
bgp_evpn_format_rt(uint8_t *rt)
{
    return bgp_evpn_format_admin_value(rt[0], rt+2);
}

/**
 * bgp_evpn_scan_esi
 *
 * Parse an Ethernet segment identifier from string
 * (10 hex bytes separated by colon).
 *
 * @param str input string
 * @param esi output buffer (10 bytes)
 * @return true on success
 */
bool
bgp_evpn_scan_esi(const char *str, uint8_t *esi)
{
    int n = 0;
    if(sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%n",
              &esi[0], &esi[1], &esi[2], &esi[3], &esi[4],
              &esi[5], &esi[6], &esi[7], &esi[8], &esi[9], &n) != 10) {
        return false;
    }
    return str[n] == '\0';
}

char *
bgp_evpn_format_esi(uint8_t *esi)
{
    static char buffer[16][BGP_EVPN_STR_LEN];
    static int idx = 0;
    char *ret;

    ret = buffer[idx];
    idx = (idx+1) & 15;
    snprintf(ret, BGP_EVPN_STR_LEN, "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
             esi[0], esi[1], esi[2], esi[3], esi[4],
             esi[5], esi[6], esi[7], esi[8], esi[9]);
    return ret;
}
