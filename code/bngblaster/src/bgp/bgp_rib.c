/*
 * BNG Blaster (BBL) - BGP RIB (Adj-RIB-In)
 *
 * Optional per session storage of received IPv4 and IPv6
 * unicast and labeled unicast routes. Path attributes are
 * interned and shared by all routes with equal attributes.
 *
 * Christian Giese, September 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"

#define BGP_RIB_ATTR_HASHTABLE_SIZE 1024
#define BGP_RIB_ATTR_KEY_OFFSET     offsetof(bgp_rib_attr_s, len)
#define BGP_RIB_ATTR_KEY_LEN(_attr) (sizeof(bgp_rib_attr_s) - BGP_RIB_ATTR_KEY_OFFSET + (_attr)->len)

/* Normalized AS_PATH might be twice the size of the received one. */
static uint8_t g_attr_buf[sizeof(bgp_rib_attr_s) + 3*BGP_MAX_MESSAGE_SIZE];

static int
bgp_rib_route_compare(void *key1, void *key2)
{
    return memcmp(key1, key2, BGP_RIB_ROUTE_KEY_LEN);
}

static int
bgp_rib_attr_compare(void *key1, void *key2)
{
    bgp_rib_attr_s *a1 = key1;
    bgp_rib_attr_s *a2 = key2;
    if(a1->len != a2->len) {
        return a1->len < a2->len ? -1 : 1;
    }
    return memcmp((uint8_t*)a1 + BGP_RIB_ATTR_KEY_OFFSET,
                  (uint8_t*)a2 + BGP_RIB_ATTR_KEY_OFFSET,
                  BGP_RIB_ATTR_KEY_LEN(a1));
}

/* FNV-1a */
static unsigned
bgp_rib_attr_hash(const void *key)
{
    const bgp_rib_attr_s *attr = key;
    const uint8_t *data = (const uint8_t*)attr + BGP_RIB_ATTR_KEY_OFFSET;
    size_t len = BGP_RIB_ATTR_KEY_LEN(attr);
    uint32_t hash = 2166136261U;

    while(len--) {
        hash ^= *data++;
        hash *= 16777619U;
    }
    return hash;
}

bool
bgp_rib_init(bgp_session_s *session)
{
    session->rib.ipv4 = hb_tree_new((dict_compare_func)bgp_rib_route_compare);
    session->rib.ipv6 = hb_tree_new((dict_compare_func)bgp_rib_route_compare);
    session->rib.attr = hashtable2_new((dict_compare_func)bgp_rib_attr_compare,
                                       bgp_rib_attr_hash, BGP_RIB_ATTR_HASHTABLE_SIZE);
    return session->rib.ipv4 && session->rib.ipv6 && session->rib.attr;
}

static void
bgp_rib_free_cb(void *key, void *datum)
{
    UNUSED(key);
    free(datum);
}

/**
 * bgp_rib_flush
 *
 * Remove all routes learned from this session.
 *
 * @param session BGP session
 */
void
bgp_rib_flush(bgp_session_s *session)
{
    if(!session->rib.ipv4) {
        return;
    }
    hb_tree_clear(session->rib.ipv4, bgp_rib_free_cb);
    hb_tree_clear(session->rib.ipv6, bgp_rib_free_cb);
    hashtable2_clear(session->rib.attr, bgp_rib_free_cb);
    session->rib.ipv4_unicast = 0;
    session->rib.ipv4_labeled_unicast = 0;
    session->rib.ipv6_unicast = 0;
    session->rib.ipv6_labeled_unicast = 0;
}

static uint32_t *
bgp_rib_counter(bgp_session_s *session, uint16_t afi, uint8_t safi)
{
    if(afi == BGP_AFI_IPV4) {
        return safi == BGP_SAFI_UNICAST ? &session->rib.ipv4_unicast : &session->rib.ipv4_labeled_unicast;
    }
    return safi == BGP_SAFI_UNICAST ? &session->rib.ipv6_unicast : &session->rib.ipv6_labeled_unicast;
}

/*
 * Build the path attribute set of a received UPDATE in
 * g_attr_buf with AS_PATH normalized to 4-octet AS numbers.
 */
static bgp_rib_attr_s *
bgp_rib_attr_build(bgp_session_s *session, bgp_update_s *update, uint8_t nexthop_af, uint8_t *nexthop)
{
    bgp_rib_attr_s *attr = (bgp_rib_attr_s*)g_attr_buf;
    uint8_t *data = attr->data;
    uint8_t *as_path = update->as_path;
    uint16_t len = update->as_path_len;
    uint8_t as_size = session->peer.as4 ? 4 : 2;
    uint16_t seg_len;
    uint8_t count, i;

    memset(attr, 0x0, sizeof(bgp_rib_attr_s));
    if(update->origin) {
        attr->flags |= BGP_RIB_ATTR_ORIGIN;
        attr->origin = *update->origin;
    }
    if(update->med) {
        attr->flags |= BGP_RIB_ATTR_MED;
        attr->med = read_be_uint(update->med, 4);
    }
    if(update->local_pref) {
        attr->flags |= BGP_RIB_ATTR_LOCAL_PREF;
        attr->local_pref = read_be_uint(update->local_pref, 4);
    }
    attr->nexthop_af = nexthop_af;
    if(nexthop_af == AF_INET) {
        memcpy(attr->nexthop, nexthop, IPV4_ADDR_LEN);
    } else if(nexthop_af == AF_INET6) {
        memcpy(attr->nexthop, nexthop, IPV6_ADDR_LEN);
    }

    /* AS_PATH segments: Type (1), Count (1), AS numbers */
    while(len) {
        if(len < 2) {
            return NULL;
        }
        count = as_path[1];
        seg_len = 2 + count * as_size;
        if(seg_len > len) {
            return NULL;
        }
        data[0] = as_path[0];
        data[1] = count;
        for(i = 0; i < count; i++) {
            write_be_uint(data+2+(i*4), 4, read_be_uint(as_path+2+(i*as_size), as_size));
        }
        data += 2 + count * 4;
        as_path += seg_len;
        len -= seg_len;
    }
    attr->as_path_len = data - attr->data;

    if(update->communities) {
        memcpy(data, update->communities, update->communities_len);
        data += update->communities_len;
        attr->communities_len = update->communities_len;
    }
    if(update->large_communities) {
        memcpy(data, update->large_communities, update->large_communities_len);
        data += update->large_communities_len;
        attr->large_communities_len = update->large_communities_len;
    }
    if(update->ext_communities) {
        memcpy(data, update->ext_communities, update->ext_communities_len);
        data += update->ext_communities_len;
        attr->ext_communities_len = update->ext_communities_len;
    }
    attr->len = data - attr->data;
    return attr;
}

/* Return the shared copy of the attribute set (refcount not incremented). */
static bgp_rib_attr_s *
bgp_rib_attr_intern(bgp_session_s *session, bgp_rib_attr_s *tmp)
{
    void **search = NULL;
    dict_insert_result result;
    bgp_rib_attr_s *attr;
    size_t size;

    search = hashtable2_search(session->rib.attr, tmp);
    if(search) {
        return *search;
    }
    size = sizeof(bgp_rib_attr_s) + tmp->len;
    attr = malloc(size);
    if(!attr) {
        return NULL;
    }
    memcpy(attr, tmp, size);
    attr->refcount = 0;
    result = hashtable2_insert(session->rib.attr, attr);
    if(!result.inserted) {
        free(attr);
        return NULL;
    }
    *result.datum_ptr = attr;
    return attr;
}

static void
bgp_rib_attr_release(bgp_session_s *session, bgp_rib_attr_s *attr)
{
    if(--attr->refcount == 0) {
        hashtable2_remove(session->rib.attr, attr);
        free(attr);
    }
}

static void
bgp_rib_add(bgp_session_s *session, uint16_t afi, bgp_rib_route_s *key, bgp_rib_attr_s *attr)
{
    hb_tree *tree = afi == BGP_AFI_IPV4 ? session->rib.ipv4 : session->rib.ipv6;
    void **search = NULL;
    dict_insert_result result;
    bgp_rib_route_s *route;

    /* Take the new reference first, the old and
     * new attribute set might be the same. */
    attr->refcount++;
    search = hb_tree_search(tree, key);
    if(search) {
        route = *search;
        bgp_rib_attr_release(session, route->attr);
    } else {
        route = malloc(sizeof(bgp_rib_route_s));
        if(!route) {
            bgp_rib_attr_release(session, attr);
            return;
        }
        *route = *key;
        result = hb_tree_insert(tree, route);
        if(!result.inserted) {
            free(route);
            bgp_rib_attr_release(session, attr);
            return;
        }
        *result.datum_ptr = route;
        (*bgp_rib_counter(session, afi, key->safi))++;
    }
    route->label = key->label;
    route->attr = attr;
}

static void
bgp_rib_withdraw(bgp_session_s *session, uint16_t afi, bgp_rib_route_s *key)
{
    hb_tree *tree = afi == BGP_AFI_IPV4 ? session->rib.ipv4 : session->rib.ipv6;
    dict_remove_result result;
    bgp_rib_route_s *route;

    result = hb_tree_remove(tree, key);
    if(result.removed) {
        route = result.datum;
        bgp_rib_attr_release(session, route->attr);
        free(route);
        (*bgp_rib_counter(session, afi, key->safi))--;
    }
}

/*
 * Parse IPv4/IPv6 unicast (RFC 4271, RFC 4760) or labeled
 * unicast (RFC 8277) NLRI. The attribute set is interned
 * with the first route, withdraw if tmp is NULL.
 */
static bool
bgp_rib_nlri(bgp_session_s *session, uint16_t afi, uint8_t safi,
             uint8_t *buf, uint16_t len, bgp_rib_attr_s *tmp)
{
    bgp_rib_route_s key;
    bgp_rib_attr_s *attr = NULL;
    uint8_t max_bits = afi == BGP_AFI_IPV4 ? 32 : 128;
    uint8_t bits, bytes;
    uint32_t label;
    bool first;
    bool valid = false;

    while(len) {
        memset(&key, 0x0, sizeof(key));
        key.safi = safi;
        bits = buf[0];
        buf++; len--;
        if(safi == BGP_SAFI_LABELED_UNICAST) {
            first = true;
            while(true) {
                if(bits < 24 || len < 3) {
                    goto EXIT;
                }
                label = read_be_uint(buf, 3);
                buf += 3; len -= 3; bits -= 24;
                if(first) {
                    key.label = label >> 4;
                    first = false;
                }
                /* Stop at bottom of stack. Withdrawn routes carry a single
                 * label field which is ignored (0x800000 or 0x000000). */
                if(!tmp || (label & 0x01) || label == 0x800000) {
                    break;
                }
            }
        }
        if(bits > max_bits) {
            goto EXIT;
        }
        bytes = (bits + 7) / 8;
        if(bytes > len) {
            goto EXIT;
        }
        memcpy(key.prefix, buf, bytes);
        bgp_evpn_mask_ip(key.prefix, afi == BGP_AFI_IPV4 ? AF_INET : AF_INET6, bits);
        key.prefix_len = bits;
        buf += bytes; len -= bytes;

        if(tmp) {
            if(!attr) {
                attr = bgp_rib_attr_intern(session, tmp);
                if(!attr) {
                    LOG(ERROR, "BGP (%s %s - %s) failed to add routes (out of memory)\n",
                        session->interface->name,
                        session->local_address_str,
                        session->peer_address_str);
                    valid = true;
                    goto EXIT;
                }
                /* Hold a reference while adding the routes of this
                 * update, the attribute set must not be freed if
                 * adding a route fails. */
                attr->refcount++;
            }
            session->stats.route_reach_rx++;
            bgp_rib_add(session, afi, &key, attr);
        } else {
            session->stats.route_withdraw_rx++;
            bgp_rib_withdraw(session, afi, &key);
        }
    }
    valid = true;
EXIT:
    if(attr) {
        bgp_rib_attr_release(session, attr);
    }
    return valid;
}

static bool
bgp_rib_afi_safi(uint16_t afi, uint8_t safi)
{
    return (afi == BGP_AFI_IPV4 || afi == BGP_AFI_IPV6) &&
           (safi == BGP_SAFI_UNICAST || safi == BGP_SAFI_LABELED_UNICAST);
}

static bool
bgp_rib_error(bgp_session_s *session, uint8_t error_subcode)
{
    session->error_code = 3; /* UPDATE Message Error */
    session->error_subcode = error_subcode;
    return false;
}

/**
 * bgp_rib_update
 *
 * Add or remove IPv4 and IPv6 routes of a received UPDATE.
 *
 * @param session BGP session
 * @param update path attributes of the UPDATE message
 * @return false if the UPDATE is malformed (error code set)
 */
bool
bgp_rib_update(bgp_session_s *session, bgp_update_s *update)
{
    bgp_rib_attr_s *tmp;
    uint8_t nexthop_af = 0;

    if(!session->rib.ipv4) {
        return true;
    }

    /* Withdrawn routes */
    if(update->withdrawn_len) {
        if(!bgp_rib_nlri(session, BGP_AFI_IPV4, BGP_SAFI_UNICAST,
                         update->withdrawn, update->withdrawn_len, NULL)) {
            return bgp_rib_error(session, 10); /* Invalid Network Field */
        }
    }
    if(update->mp_unreach && bgp_rib_afi_safi(update->mp_unreach_afi, update->mp_unreach_safi)) {
        if(!bgp_rib_nlri(session, update->mp_unreach_afi, update->mp_unreach_safi,
                         update->mp_unreach_nlri, update->mp_unreach_nlri_len, NULL)) {
            return bgp_rib_error(session, 9); /* Optional Attribute Error */
        }
    }

    /* Reachable routes */
    if(update->nlri_len) {
        tmp = bgp_rib_attr_build(session, update, update->next_hop ? AF_INET : 0, update->next_hop);
        if(!tmp) {
            return bgp_rib_error(session, 11); /* Malformed AS_PATH */
        }
        if(!bgp_rib_nlri(session, BGP_AFI_IPV4, BGP_SAFI_UNICAST,
                         update->nlri, update->nlri_len, tmp)) {
            return bgp_rib_error(session, 10); /* Invalid Network Field */
        }
    }
    if(update->mp_reach && bgp_rib_afi_safi(update->mp_reach_afi, update->mp_reach_safi)) {
        if(update->mp_reach_nexthop_len == IPV4_ADDR_LEN) {
            nexthop_af = AF_INET;
        } else if(update->mp_reach_nexthop_len >= IPV6_ADDR_LEN) {
            /* Global address optionally followed by link-local address. */
            nexthop_af = AF_INET6;
        }
        tmp = bgp_rib_attr_build(session, update, nexthop_af, update->mp_reach_nexthop);
        if(!tmp) {
            return bgp_rib_error(session, 11); /* Malformed AS_PATH */
        }
        if(!bgp_rib_nlri(session, update->mp_reach_afi, update->mp_reach_safi,
                         update->mp_reach_nlri, update->mp_reach_nlri_len, tmp)) {
            return bgp_rib_error(session, 9); /* Optional Attribute Error */
        }
    }
    return true;
}

/**
 * bgp_rib_format_as_path
 *
 * Format AS_PATH as string, e.g. "65001 65002 {65003,65004}".
 *
 * @param attr path attributes
 * @return AS_PATH string in static buffer
 */
char *
bgp_rib_format_as_path(bgp_rib_attr_s *attr)
{
    static char buffer[BGP_MAX_MESSAGE_SIZE * 6];
    uint8_t *data = attr->data;
    uint16_t len = attr->as_path_len;
    uint8_t type, count, i;
    size_t idx = 0;
    bool set;

    buffer[0] = '\0';
    while(len >= 2) {
        type = data[0];
        count = data[1];
        set = (type == 1 || type == 4); /* AS_SET or AS_CONFED_SET */
        if(idx) buffer[idx++] = ' ';
        if(set) buffer[idx++] = type == 1 ? '{' : '[';
        else if(type == 3) buffer[idx++] = '(';
        for(i = 0; i < count; i++) {
            idx += snprintf(buffer+idx, sizeof(buffer)-idx, "%s%u",
                            i ? (set ? "," : " ") : "",
                            (uint32_t)read_be_uint(data+2+(i*4), 4));
        }
        if(set) buffer[idx++] = type == 1 ? '}' : ']';
        else if(type == 3) buffer[idx++] = ')';
        buffer[idx] = '\0';
        data += 2 + count * 4;
        len -= 2 + count * 4;
    }
    return buffer;
}
