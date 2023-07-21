/*
 * BNG Blaster (BBL) - OSPF Neighbor/Adjacency Functions
 * 
 * Christian Giese, July 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

protocol_error_t
ospf_neighbor_dbd_tx(ospf_neighbor_s *ospf_neighbor);

void
ospf_neigbor_dbd_retry_job(timer_s *timer)
{
    ospf_neighbor_s *ospf_neighbor = timer->data;
    switch(ospf_neighbor->state) {
        case OSPF_NBSTATE_EXSTART:
        case OSPF_NBSTATE_EXCHANGE:
            ospf_neighbor_dbd_tx(ospf_neighbor);
            break;
        default:
            break;
    }
}

protocol_error_t
ospf_neighbor_dbd_tx(ospf_neighbor_s *ospf_neighbor)
{
    ospf_interface_s *ospf_interface = ospf_neighbor->interface;
    ospf_instance_s  *ospf_instance = ospf_interface->instance;
    bbl_network_interface_s *interface = ospf_interface->interface;

    ospf_lsa_s *lsa; 
    ospf_pdu_s pdu = {0};
    uint8_t pdu_buf[OSPF_TX_BUF_LEN];

    uint8_t options = OSPF_DBD_OPTION_E|OSPF_DBD_OPTION_L|OSPF_DBD_OPTION_O;
    uint8_t flags = 0;

    hb_itor *itor;
    bool next;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    ospf_pdu_init(&pdu, OSPF_PDU_DB_DESC, ospf_neighbor->version);
    pdu.pdu = pdu_buf;
    pdu.pdu_buf_len = OSPF_TX_BUF_LEN;

    /* OSPF header */
    ospf_pdu_add_u8(&pdu, ospf_neighbor->version);
    ospf_pdu_add_u8(&pdu, pdu.pdu_type);
    ospf_pdu_add_u16(&pdu, 0); /* skip length */
    ospf_pdu_add_u32(&pdu, ospf_instance->config->router_id); /* Router ID */
    ospf_pdu_add_u32(&pdu, ospf_instance->config->area); /* Area ID */
    ospf_pdu_add_u16(&pdu, 0); /* skip checksum */
    if(ospf_neighbor->version == OSPF_VERSION_2) {
        /* Authentication */
        ospf_pdu_add_u16(&pdu, OSPF_AUTH_NONE);
        ospf_pdu_zero_bytes(&pdu, OSPFV2_AUTH_DATA_LEN);
    } else {
        ospf_pdu_add_u16(&pdu, 0);
        ospf_pdu_add_u32(&pdu, 0);
    }
    ospf_pdu_add_u16(&pdu, interface->mtu);
    ospf_pdu_add_u8(&pdu, options);
    ospf_pdu_add_u8(&pdu, flags);
    ospf_pdu_add_u32(&pdu, ospf_neighbor->dd);

    if(ospf_neighbor->state == OSPF_NBSTATE_EXSTART) {
        flags |= OSPF_DBD_FLAG_I;
    } else {
        /* Add LSA header */
        itor = hb_itor_new(ospf_instance->lsdb);
        if(ospf_neighbor->dbd_lsa_start.type) {
            next = hb_itor_search_ge(itor, &ospf_neighbor->dbd_lsa_start);
        } else {
            next = hb_itor_first(itor);
        }

        while(true) {
            if(!next) {
                ospf_neighbor->dbd_more = false;
                break;
            }
            lsa = *hb_itor_datum(itor);
            if(lsa->deleted) {
                /* Ignore deleted LSA. */
                next = hb_itor_next(itor);
                continue;
            }
            if((pdu.cur + OSPF_LLS_HDR_LEN + OSPF_LSA_HDR_LEN) 
                > ospf_interface->max_len) {
                memcpy(&ospf_neighbor->dbd_lsa_next, &lsa->key, sizeof(ospf_lsa_key_s));
                break;
            }

            ospf_lsa_update_age(lsa, &now);
            ospf_pdu_add_bytes(&pdu, lsa->lsa, OSPF_LSA_HDR_LEN);

            next = hb_itor_next(itor);
        }
    }

    /* Update DBD flags */
    if(ospf_neighbor->master) flags |= OSPF_DBD_FLAG_MS;
    if(ospf_neighbor->dbd_more) flags |= OSPF_DBD_FLAG_M;
    if(ospf_neighbor->version == OSPF_VERSION_2) {
        *OSPF_PDU_OFFSET(&pdu, OSPFV2_OFFSET_DBD_FLAGS) = flags;
    } else {
        *OSPF_PDU_OFFSET(&pdu, OSPFV3_OFFSET_DBD_FLAGS) = flags;
    }

    /* Update length and checksum */
    ospf_pdu_update_len(&pdu);
    ospf_pdu_update_checksum(&pdu);

    /* Add LLS Data Block */
    OSPF_PDU_CURSOR_SET(&pdu, pdu.packet_len);
    ospf_pdu_add_u16(&pdu, 0xfff6); /* checksum */
    ospf_pdu_add_u16(&pdu, 3); /* length */
    ospf_pdu_add_u16(&pdu, OSPF_EXTENDED_OPTION_TLV);
    ospf_pdu_add_u16(&pdu, OSPF_EXTENDED_OPTION_TLV_LEN);
    ospf_pdu_add_u32(&pdu, OSPF_EXT_OPTION_LSDB_RESYNC);

    if(ospf_pdu_tx(&pdu, ospf_interface, ospf_neighbor) == PROTOCOL_SUCCESS) {
        ospf_interface->stats.db_des_tx++;
        timer_add(&g_ctx->timer_root, &ospf_neighbor->timer_dbd_retry, "OSPF DBD RETRY", 
                  5, 0, ospf_neighbor, &ospf_neigbor_dbd_retry_job);
        return PROTOCOL_SUCCESS;
    } else {
        timer_add(&g_ctx->timer_root, &ospf_neighbor->timer_dbd_retry, "OSPF DBD RETRY", 
                  1, 0, ospf_neighbor, &ospf_neigbor_dbd_retry_job);
        return SEND_ERROR;
    }
}

void
ospf_neigbor_req_job(timer_s *timer)
{
    ospf_neighbor_s *ospf_neighbor = timer->data;
    ospf_lsa_req_tx(ospf_neighbor->interface, ospf_neighbor);
}

void
ospf_neigbor_retry_job(timer_s *timer)
{
    ospf_neighbor_s *ospf_neighbor = timer->data;
    ospf_lsa_update_tx(ospf_neighbor->interface, ospf_neighbor, true);
}

static void
ospf_neighbor_clear(ospf_neighbor_s *ospf_neighbor)
{
    hb_tree_clear(ospf_neighbor->lsa_update_tree, ospf_lsa_tree_entry_clear);
    hb_tree_clear(ospf_neighbor->lsa_retry_tree, ospf_lsa_tree_entry_clear);
    hb_tree_clear(ospf_neighbor->lsa_request_tree, ospf_lsa_tree_entry_clear);
    hb_tree_clear(ospf_neighbor->lsa_ack_tree, ospf_lsa_tree_entry_clear);

    timer_del(ospf_neighbor->timer_lsa_retry);
}

static void
ospf_neigbor_exstart(ospf_neighbor_s *ospf_neighbor)
{
    ospf_neighbor->master = true;
    ospf_neighbor->dd = (rand() & 0xffff)+1;
    ospf_neighbor->dbd_more = true;
    memset(&ospf_neighbor->dbd_lsa_start, 0x0, sizeof(ospf_lsa_key_s));
    memset(&ospf_neighbor->dbd_lsa_next, 0x0, sizeof(ospf_lsa_key_s));

    ospf_neighbor_dbd_tx(ospf_neighbor);

    timer_add_periodic(&g_ctx->timer_root, &ospf_neighbor->timer_lsa_request, "OSPF LSA REQ", 
                       1, 0, ospf_neighbor, &ospf_neigbor_req_job);

    timer_add_periodic(&g_ctx->timer_root, &ospf_neighbor->timer_lsa_retry, "OSPF LSA RETRY", 
                       1, 0, ospf_neighbor, &ospf_neigbor_retry_job);
}

static void
ospf_neigbor_loading(ospf_neighbor_s *ospf_neighbor)
{
    UNUSED(ospf_neighbor);
}

void
ospf_neigbor_state(ospf_neighbor_s *ospf_neighbor, uint8_t state)
{
    if(ospf_neighbor->state == state) return;

    LOG(OSPF, "OSPFv%u neighbor %s state %s -> %s on interface %s\n",
        ospf_neighbor->version,
        format_ipv4_address(&ospf_neighbor->router_id), 
        ospf_neighbor_state_string(ospf_neighbor->state),
        ospf_neighbor_state_string(state),
        ospf_neighbor->interface->interface->name);

    ospf_neighbor->state = state;

    switch(state) {
        case OSPF_NBSTATE_DOWN:
        case OSPF_NBSTATE_ATTEMPT:
        case OSPF_NBSTATE_INIT:
        case OSPF_NBSTATE_2WAY:
            ospf_neighbor_clear(ospf_neighbor);
            break;
        case OSPF_NBSTATE_EXSTART:
            ospf_neighbor_clear(ospf_neighbor);
            ospf_neigbor_exstart(ospf_neighbor);
            break;
        case OSPF_NBSTATE_LOADING:
            ospf_neigbor_loading(ospf_neighbor);
            break;
        default:
            break;
    }
}

ospf_neighbor_s *
ospf_neigbor_new(ospf_interface_s *ospf_interface, ospf_pdu_s *pdu)
{
    ospf_neighbor_s *ospf_neighbor;

    ospf_neighbor = calloc(1, sizeof(ospf_neighbor_s));
    ospf_neighbor->router_id = pdu->router_id;

    memcpy(ospf_neighbor->mac, pdu->mac, ETH_ADDR_LEN);
    if(pdu->pdu_version == OSPF_VERSION_2) {
        ospf_neighbor->ipv4 = *(ipv4addr_t*)pdu->source;
        ospf_neighbor->version = OSPF_VERSION_2;
        ospf_neighbor->priority = *OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_HELLO_PRIORITY);
        ospf_neighbor->dr = *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_HELLO_DR);
        ospf_neighbor->bdr = *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_HELLO_BDR);
    } else {
        memcpy(ospf_neighbor->ipv6, pdu->source, sizeof(ipv6addr_t));
        ospf_neighbor->version = OSPF_VERSION_3;
        ospf_neighbor->priority = *OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_HELLO_PRIORITY);
        ospf_neighbor->dr = *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_HELLO_DR);
        ospf_neighbor->bdr = *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_HELLO_BDR);
    }

    ospf_neighbor->state = OSPF_NBSTATE_DOWN;
    ospf_neighbor->interface = ospf_interface;

    ospf_neighbor->lsa_update_tree = hb_tree_new((dict_compare_func)ospf_lsa_id_compare);
    ospf_neighbor->lsa_retry_tree = hb_tree_new((dict_compare_func)ospf_lsa_id_compare);
    ospf_neighbor->lsa_request_tree = hb_tree_new((dict_compare_func)ospf_lsa_id_compare);
    ospf_neighbor->lsa_ack_tree = hb_tree_new((dict_compare_func)ospf_lsa_id_compare);

    LOG(OSPF, "OSPFv%u new neighbor %s on interface %s\n",
        ospf_neighbor->version,
        format_ipv4_address(&ospf_neighbor->router_id), 
        ospf_interface->interface->name);

    ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_INIT);
    return ospf_neighbor;
}

void
ospf_neigbor_update(ospf_neighbor_s *ospf_neighbor, ospf_pdu_s *pdu)
{
    ospf_interface_s *ospf_interface = ospf_neighbor->interface;
    
    uint8_t priority;
    uint32_t dr, bdr;

    if(pdu->pdu_version == OSPF_VERSION_2) {
        priority = *OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_HELLO_PRIORITY);
        dr = *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_HELLO_DR);
        bdr = *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_HELLO_BDR);
    } else {
        priority = *OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_HELLO_PRIORITY);
        dr = *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_HELLO_DR);
        bdr = *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_HELLO_BDR);
    }

    if(priority != ospf_neighbor->priority ||
       dr != ospf_neighbor->dr ||
       bdr != ospf_neighbor->bdr) {
        ospf_neighbor->priority = priority;
        ospf_neighbor->dr = dr;
        ospf_neighbor->bdr = bdr;
        ospf_interface_neighbor_change(ospf_interface);
    } 
}

/**
 * ospf_neigbor_adjok:
 *
 * Check active (state > 2WAY) OSPF adjcencies if they are 
 * still allowed and clear if not.
 *
 * @param ospf_neighbor OSPF neighbor
 */
void
ospf_neigbor_adjok(ospf_neighbor_s *ospf_neighbor)
{
    ospf_interface_s *ospf_interface = ospf_neighbor->interface;

    if(ospf_neighbor->state > OSPF_NBSTATE_2WAY) {
        if(!(ospf_interface->state == OSPF_IFSTATE_P2P || 
             ospf_interface->state == OSPF_IFSTATE_DR || 
             ospf_interface->state == OSPF_IFSTATE_BACKUP ||
             ospf_interface->dr == ospf_neighbor->router_id || 
             ospf_interface->bdr == ospf_neighbor->router_id)) {
            ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_2WAY);
        }
    }
}

/**
 * ospf_neighbor_dbd_rx:
 *
 * @param ospf_interface receive interface
 * @param ospf_neighbor receive OSPF neighbor
 * @param pdu received OSPF PDU
 */
void
ospf_neighbor_dbd_rx(ospf_interface_s *ospf_interface, 
                     ospf_neighbor_s *ospf_neighbor, 
                     ospf_pdu_s *pdu)
{
    bbl_network_interface_s *interface = ospf_interface->interface;
    ospf_instance_s *ospf_instance = ospf_interface->instance;

    ospf_lsa_header_s *hdr;
    ospf_lsa_s *lsa;

    void **search = NULL;

    uint32_t dd;
    uint16_t mtu;

    uint8_t options;
    uint8_t flags;

    ospf_interface->stats.db_des_rx++;

    if(!ospf_neighbor) {
        ospf_rx_error(interface, pdu, "no neighbor");
        return;
    }
    if(ospf_neighbor->state < OSPF_NBSTATE_EXSTART) {
        ospf_rx_error(interface, pdu, "wrong state");
        return;
    }

    if(ospf_interface->version == OSPF_VERSION_2) {
        if(pdu->pdu_len < OSPFV2_DBD_LEN_MIN) {
            ospf_rx_error(interface, pdu, "decode");
            return;
        }
        mtu = be16toh(*(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_DBD_MTU));
        options = *OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_DBD_OPTIONS);
        flags = *OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_DBD_FLAGS);
        dd = be32toh(*(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_DBD_DD_SEQ));
        OSPF_PDU_CURSOR_SET(pdu, OSPFV2_OFFSET_DBD_LSA);
    } else {
        if(pdu->pdu_len < OSPFV3_DBD_LEN_MIN) {
            ospf_rx_error(interface, pdu, "decode");
            return;
        }
        mtu = be16toh(*(uint16_t*)OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_DBD_MTU));
        options = *OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_DBD_OPTIONS);
        flags = *OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_DBD_FLAGS);
        dd = be32toh(*(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_DBD_DD_SEQ));
        OSPF_PDU_CURSOR_SET(pdu, OSPFV3_OFFSET_DBD_LSA);
    }

    if(mtu > interface->mtu) {
        ospf_rx_error(interface, pdu, "MTU");
        return;
    }

    if(ospf_neighbor->state == OSPF_NBSTATE_EXSTART) {
        ospf_neighbor->options = options;
        if(flags & OSPF_DBD_FLAG_I && 
           flags & OSPF_DBD_FLAG_M && 
           flags & OSPF_DBD_FLAG_MS && 
           be32toh(ospf_neighbor->router_id) > 
           be32toh(ospf_instance->config->router_id)) {
            /* SLAVE */
            ospf_neighbor->master = false;
            ospf_neighbor->dd = dd;
            ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_EXCHANGE);
        } else if(!(flags & (OSPF_DBD_FLAG_I|OSPF_DBD_FLAG_MS)) &&
                  dd == ospf_neighbor->dd && 
                  be32toh(ospf_neighbor->router_id) < 
                  be32toh(ospf_instance->config->router_id)) {
            /* MASTER */
            ospf_neighbor->master = true;
            ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_EXCHANGE);
        }
        ospf_neighbor_dbd_tx(ospf_neighbor);
        return;
    }

    if(flags & OSPF_DBD_FLAG_I) {
        /* I flag not expected after ExStart */
        ospf_rx_error(interface, pdu, "init");
        ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_EXSTART);
        return;
    }
    if(ospf_neighbor->options != options) {
        ospf_rx_error(interface, pdu, "options");
        ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_EXSTART);
        return;
    }
    if(ospf_neighbor->master) {
        if(flags & OSPF_DBD_FLAG_MS) {
            ospf_rx_error(interface, pdu, "master/slave");
            ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_EXSTART);
            return;
        }
        if(dd != ospf_neighbor->dd) {
            ospf_rx_error(interface, pdu, "DD sequence");
            ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_EXSTART);
            return;
        }
        if(ospf_neighbor->dbd_more || flags & OSPF_DBD_FLAG_M) {
            /* Next */
            ospf_neighbor->dd++;
            memcpy(&ospf_neighbor->dbd_lsa_start, &ospf_neighbor->dbd_lsa_next, sizeof(ospf_lsa_key_s));
            memset(&ospf_neighbor->dbd_lsa_next, UINT8_MAX, sizeof(ospf_lsa_key_s));
            ospf_neighbor_dbd_tx(ospf_neighbor);
        }
    } else {
        if(!(flags & OSPF_DBD_FLAG_MS)) {
            ospf_rx_error(interface, pdu, "master/slave");
            ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_EXSTART);
            return;
        }
        if(dd == ospf_neighbor->dd) {
            /* Retry */
            ospf_neighbor_dbd_tx(ospf_neighbor);
        } else if(dd == ospf_neighbor->dd+1) {
            /* Next */
            ospf_neighbor->dd = dd;
            memcpy(&ospf_neighbor->dbd_lsa_start, &ospf_neighbor->dbd_lsa_next, sizeof(ospf_lsa_key_s));
            memset(&ospf_neighbor->dbd_lsa_next, UINT8_MAX, sizeof(ospf_lsa_key_s));
            ospf_neighbor_dbd_tx(ospf_neighbor);
        } else {
            ospf_rx_error(interface, pdu, "DD sequence");
            ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_EXSTART);
            return;
        }
    }

    /* Update LSA request-tree. */
    while(OSPF_PDU_CURSOR_LEN(pdu) >= OSPF_LSA_HDR_LEN) {
        hdr = (ospf_lsa_header_s*)OSPF_PDU_CURSOR(pdu);
        OSPF_PDU_CURSOR_INC(pdu, OSPF_LSA_HDR_LEN);

        search = hb_tree_search(ospf_instance->lsdb, &hdr->type);
        if(search) {
            lsa = *search;
            if(ospf_lsa_compare(hdr, (ospf_lsa_header_s*)lsa->lsa) != 1) {
                continue;
            }
        }
        ospf_lsa_tree_add(NULL, hdr, ospf_neighbor->lsa_request_tree);
    }

    /* Change state to loading if all DBD messages have been exchanged. */
    if(!(ospf_neighbor->dbd_more || flags & OSPF_DBD_FLAG_M)) {
        ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_LOADING);
    }
}