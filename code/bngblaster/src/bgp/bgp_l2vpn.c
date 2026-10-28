/*
 * BNG Blaster (BBL) - BGP L2VPN
 *
 * BGP L2VPN route learning (RFC 6624, RFC 4761) used to
 * resolve pseudowire labels for traffic streams.
 *
 * Christian Giese, October 2026
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bgp.h"

/* RD (8), CE ID (2), label block offset (2), size (2), label base (3) */
#define BGP_L2VPN_NLRI_MIN_LEN 17

static int
bgp_l2vpn_compare(void *key1, void *key2)
{
    return memcmp(key1, key2, sizeof(bgp_l2vpn_key_s));
}

bool
bgp_l2vpn_init(bgp_session_s *session)
{
    session->rib.l2vpn_db = hb_tree_new((dict_compare_func)bgp_l2vpn_compare);
    return session->rib.l2vpn_db != NULL;
}

const char *
bgp_l2vpn_encap_string(uint8_t encap)
{
    switch(encap) {
        case 1: return "frame-relay";
        case 2: return "atm-aal5";
        case 3: return "atm-cell";
        case 4: return "ethernet-vlan";
        case 5: return "ethernet";
        case 6: return "cisco-hdlc";
        case 7: return "ppp";
        case 11: return "ip";
        case 19: return "vpls";
        default: return "unknown";
    }
}

static void
bgp_l2vpn_decode_ext_communities(uint8_t *buf, uint16_t len, bgp_l2vpn_entry_s *attr)
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
            case 0x80:
                if(sub_type == 0x0a) { /* Layer2 Info (RFC 4761) */
                    attr->l2_info_present = true;
                    attr->encap = buf[2];
                    attr->flags = buf[3];
                    attr->mtu = read_be_uint(buf+4, 2);
                }
                break;
            default:
                break;
        }
        buf += 8;
        len -= 8;
    }
}

/* Decode the TLVs (RFC 6624) of a single NLRI. */
static bool
bgp_l2vpn_decode_tlvs(uint8_t *buf, uint16_t len, bgp_l2vpn_entry_s *entry)
{
    uint8_t type;
    uint16_t bits, bytes;

    while(len) {
        if(len < 3) return false;
        type = buf[0];
        bits = read_be_uint(buf+1, 2);
        bytes = (bits + 7) / 8;
        buf += 3; len -= 3;
        if(bytes > len) return false;
        if(type == BGP_L2VPN_TLV_CSV) {
            /* Status bits beyond the stored length are considered up. */
            entry->csv_bits = bits;
            memcpy(entry->csv, buf, bytes < BGP_L2VPN_MAX_CSV ? bytes : BGP_L2VPN_MAX_CSV);
        }
        buf += bytes; len -= bytes;
    }
    return true;
}

/* Fields after version, updated in place for existing entries. */
#define BGP_L2VPN_ENTRY_DATA_OFFSET offsetof(bgp_l2vpn_entry_s, size)

static void
bgp_l2vpn_db_add(bgp_session_s *session, bgp_l2vpn_entry_s *update)
{
    void **search = NULL;
    dict_insert_result result;
    bgp_l2vpn_entry_s *entry;

    /* The complete new state is built first because traffic
     * streams (TX threads) read the entries while updated. */
    update->source = session;
    update->active = true;

    pthread_rwlock_wrlock(&g_ctx->label_db_lock);
    search = hb_tree_search(session->rib.l2vpn_db, &update->key);
    if(search) {
        entry = *search;
        if(!entry->active) {
            session->rib.l2vpn++;
        }
        /* The key must not change while stored in the tree and the
         * version is updated last to trigger stream packet rebuild. */
        memcpy((uint8_t*)entry + BGP_L2VPN_ENTRY_DATA_OFFSET,
               (uint8_t*)update + BGP_L2VPN_ENTRY_DATA_OFFSET,
               sizeof(bgp_l2vpn_entry_s) - BGP_L2VPN_ENTRY_DATA_OFFSET);
        __atomic_store_n(&entry->active, true, __ATOMIC_RELAXED);
        bgp_evpn_version_increment();
        __atomic_store_n(&entry->version, entry->version + 1, __ATOMIC_RELEASE);
    } else {
        entry = malloc(sizeof(bgp_l2vpn_entry_s));
        if(!entry) {
            pthread_rwlock_unlock(&g_ctx->label_db_lock);
            LOG(ERROR, "BGP (%s %s - %s) failed to add L2VPN route to database (out of memory)\n",
                session->interface->name,
                session->local_address_str,
                session->peer_address_str);
            return;
        }
        *entry = *update;
        entry->version = 1;
        result = hb_tree_insert(session->rib.l2vpn_db, &entry->key);
        if(!result.inserted) {
            pthread_rwlock_unlock(&g_ctx->label_db_lock);
            free(entry);
            LOG(ERROR, "BGP (%s %s - %s) failed to add L2VPN route to database\n",
                session->interface->name,
                session->local_address_str,
                session->peer_address_str);
            return;
        }
        *result.datum_ptr = entry;
        session->rib.l2vpn++;
        bgp_evpn_version_increment();
    }
    pthread_rwlock_unlock(&g_ctx->label_db_lock);
}

static void
bgp_l2vpn_db_withdraw(bgp_session_s *session, bgp_l2vpn_key_s *key)
{
    void **search = NULL;
    bgp_l2vpn_entry_s *entry;

    search = hb_tree_search(session->rib.l2vpn_db, key);
    if(search) {
        entry = *search;
        if(entry->active) {
            pthread_rwlock_wrlock(&g_ctx->label_db_lock);
            __atomic_store_n(&entry->active, false, __ATOMIC_RELAXED);
            session->rib.l2vpn--;
            bgp_evpn_version_increment();
            __atomic_store_n(&entry->version, entry->version + 1, __ATOMIC_RELEASE);
            pthread_rwlock_unlock(&g_ctx->label_db_lock);
        }
    }
}

static bool
bgp_l2vpn_nlri(bgp_session_s *session, uint8_t *buf, uint16_t len, bgp_l2vpn_entry_s *attr)
{
    bgp_l2vpn_entry_s entry;
    uint16_t nlri_len;

    while(len) {
        if(len < 2) {
            return false;
        }
        nlri_len = read_be_uint(buf, 2);
        buf += 2; len -= 2;
        if(nlri_len > len) {
            return false;
        }
        if(attr) {
            entry = *attr;
        } else {
            memset(&entry, 0x0, sizeof(entry));
        }
        if(nlri_len < BGP_L2VPN_NLRI_MIN_LEN ||
           !bgp_l2vpn_decode_tlvs(buf+BGP_L2VPN_NLRI_MIN_LEN,
                                  nlri_len-BGP_L2VPN_NLRI_MIN_LEN, &entry)) {
            /* The route boundaries are known, so only this route is
             * ignored instead of resetting the session (RFC 7606). */
            LOG(BGP, "BGP (%s %s - %s) ignore invalid L2VPN route (length %u)\n",
                session->interface->name,
                session->local_address_str,
                session->peer_address_str,
                nlri_len);
        } else {
            memset(&entry.key, 0x0, sizeof(entry.key));
            memcpy(entry.key.rd, buf, BGP_RD_LEN);
            entry.key.ce_id = read_be_uint(buf+8, 2);
            entry.key.offset = read_be_uint(buf+10, 2);
            entry.size = read_be_uint(buf+12, 2);
            /* 20 bit MPLS label in the high-order bits. */
            entry.label_base = read_be_uint(buf+14, 3) >> 4;
            if(attr) {
                session->stats.l2vpn_reach_rx++;
                bgp_l2vpn_db_add(session, &entry);
            } else {
                session->stats.l2vpn_withdraw_rx++;
                bgp_l2vpn_db_withdraw(session, &entry.key);
            }
        }
        buf += nlri_len; len -= nlri_len;
    }
    return true;
}

/**
 * bgp_l2vpn_update
 *
 * Learn or withdraw L2VPN label blocks from the MP_REACH_NLRI
 * and MP_UNREACH_NLRI attributes of a received UPDATE.
 *
 * @param session BGP session
 * @param update path attributes of the UPDATE message
 * @return false if the L2VPN NLRI can't be parsed (session reset)
 */
bool
bgp_l2vpn_update(bgp_session_s *session, bgp_update_s *update)
{
    bgp_l2vpn_entry_s attr;
    uint8_t nh_len;

    if(!session->rib.l2vpn_db) {
        return true;
    }

    if(update->mp_unreach &&
       update->mp_unreach_afi == BGP_AFI_L2VPN &&
       update->mp_unreach_safi == BGP_SAFI_VPLS) {
        if(!bgp_l2vpn_nlri(session, update->mp_unreach_nlri, update->mp_unreach_nlri_len, NULL)) {
            return false;
        }
    }

    if(update->mp_reach &&
       update->mp_reach_afi == BGP_AFI_L2VPN &&
       update->mp_reach_safi == BGP_SAFI_VPLS) {
        memset(&attr, 0x0, sizeof(attr));
        nh_len = update->mp_reach_nexthop_len;
        if(nh_len == IPV4_ADDR_LEN) {
            attr.nexthop_af = AF_INET;
            memcpy(attr.nexthop, update->mp_reach_nexthop, IPV4_ADDR_LEN);
        } else if(nh_len >= IPV6_ADDR_LEN) {
            attr.nexthop_af = AF_INET6;
            memcpy(attr.nexthop, update->mp_reach_nexthop, IPV6_ADDR_LEN);
        }
        if(update->ext_communities) {
            bgp_l2vpn_decode_ext_communities(update->ext_communities,
                                             update->ext_communities_len, &attr);
        }
        if(!bgp_l2vpn_nlri(session, update->mp_reach_nlri, update->mp_reach_nlri_len, &attr)) {
            return false;
        }
    }
    return true;
}

/**
 * bgp_l2vpn_session_down
 *
 * Mark all L2VPN routes learned from this session as inactive.
 * Entries are kept because traffic streams hold references.
 *
 * @param session BGP session
 */
void
bgp_l2vpn_session_down(bgp_session_s *session)
{
    bgp_l2vpn_entry_s *entry;
    hb_itor *itor;
    bool next;

    if(!(session->rib.l2vpn_db && session->rib.l2vpn)) {
        return;
    }
    pthread_rwlock_wrlock(&g_ctx->label_db_lock);
    bgp_evpn_version_increment();
    itor = hb_itor_new(session->rib.l2vpn_db);
    next = hb_itor_first(itor);
    while(next) {
        entry = *hb_itor_datum(itor);
        if(entry->active) {
            __atomic_store_n(&entry->active, false, __ATOMIC_RELAXED);
            __atomic_store_n(&entry->version, entry->version + 1, __ATOMIC_RELEASE);
        }
        next = hb_itor_next(itor);
    }
    hb_itor_free(itor);
    session->rib.l2vpn = 0;
    pthread_rwlock_unlock(&g_ctx->label_db_lock);
}

static bool
bgp_l2vpn_covers(bgp_l2vpn_entry_s *entry, uint16_t local_ce_id)
{
    return entry->active &&
           local_ce_id >= entry->key.offset &&
           (uint32_t)local_ce_id < (uint32_t)entry->key.offset + entry->size;
}

/* Label block of the session for the remote CE which covers the local CE. */
static bgp_l2vpn_entry_s *
bgp_l2vpn_lookup_session(bgp_session_s *session, uint8_t *rd,
                         uint16_t ce_id, uint16_t local_ce_id)
{
    bgp_l2vpn_key_s key = {0};
    bgp_l2vpn_entry_s *entry = NULL;
    hb_itor *itor;
    bool next;

    memcpy(key.rd, rd, BGP_RD_LEN);
    key.ce_id = ce_id;

    /* The offset is the last part of the key, so all
     * label blocks of the remote CE are adjacent. */
    itor = hb_itor_new(session->rib.l2vpn_db);
    if(!itor) {
        return NULL;
    }
    next = hb_itor_search_ge(itor, &key);
    while(next) {
        entry = *hb_itor_datum(itor);
        if(memcmp(&entry->key, &key, offsetof(bgp_l2vpn_key_s, offset)) != 0) {
            entry = NULL;
            break;
        }
        if(bgp_l2vpn_covers(entry, local_ce_id)) {
            break;
        }
        entry = NULL;
        next = hb_itor_next(itor);
    }
    hb_itor_free(itor);
    return entry;
}

/**
 * bgp_l2vpn_lookup
 *
 * Search all sessions (in configuration order) for an active label
 * block of the remote CE which covers the local CE ID (RFC 4761
 * section 3.2.3).
 *
 * @param rd route distinguisher of the remote CE
 * @param ce_id remote CE ID
 * @param local_ce_id local CE ID
 * @return L2VPN entry of the first matching session or NULL
 */
bgp_l2vpn_entry_s *
bgp_l2vpn_lookup(uint8_t *rd, uint16_t ce_id, uint16_t local_ce_id)
{
    bgp_session_s *session = g_ctx->bgp_sessions;
    bgp_l2vpn_entry_s *entry;

    while(session) {
        if(session->rib.l2vpn) {
            entry = bgp_l2vpn_lookup_session(session, rd, ce_id, local_ce_id);
            if(entry) {
                return entry;
            }
        }
        session = session->next;
    }
    return NULL;
}

bool
bgp_l2vpn_usable(bgp_l2vpn_entry_s *entry, uint16_t local_ce_id)
{
    return bgp_l2vpn_covers(entry, local_ce_id);
}

/**
 * bgp_l2vpn_label
 *
 * @param entry label block of the remote CE
 * @param local_ce_id local CE ID covered by this label block
 * @return label to send traffic from the local to the remote CE
 */
uint32_t
bgp_l2vpn_label(bgp_l2vpn_entry_s *entry, uint16_t local_ce_id)
{
    return entry->label_base + local_ce_id - entry->key.offset;
}

/**
 * bgp_l2vpn_status_up
 *
 * @param entry label block of the remote CE
 * @param local_ce_id local CE ID covered by this label block
 * @return false if the circuit status vector signals the PVC as down
 */
bool
bgp_l2vpn_status_up(bgp_l2vpn_entry_s *entry, uint16_t local_ce_id)
{
    uint16_t index = local_ce_id - entry->key.offset;

    if(index >= entry->csv_bits || index / 8 >= BGP_L2VPN_MAX_CSV) {
        return true;
    }
    /* Bit 0 is the most significant bit of the first byte. */
    return !(entry->csv[index / 8] & (0x80 >> (index % 8)));
}
