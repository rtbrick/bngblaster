/*
 * BNG Blaster (BBL) - OSPF Adjacency
 * 
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

protocol_error_t
ospf_neighbor_dbd_tx(ospf_neighbor_s *ospf_neighbor)
{
    ospf_interface_s *ospf_interface = ospf_neighbor->interface;
    ospf_instance_s  *ospf_instance = ospf_interface->instance;
    bbl_network_interface_s *interface = ospf_interface->interface;

    bbl_ethernet_header_s eth = {0};
    bbl_ipv4_s ipv4 = {0};
    bbl_ipv6_s ipv6 = {0};
    bbl_ospf_s ospf = {0};

    ospf_pdu_s pdu = {0};
    uint8_t pdu_buf[OSPF_TX_BUF_LEN];

    uint8_t options = OSPF_DBD_OPTION_E|OSPF_DBD_OPTION_L|OSPF_DBD_OPTION_O;
    uint8_t flags = 0;

    switch(ospf_neighbor->state) {
        case OSPF_NBSTATE_EXSTART:
            flags = OSPF_DBD_FLAG_I|OSPF_DBD_FLAG_M|OSPF_DBD_FLAG_MS;
            break;
        case OSPF_NBSTATE_EXCHANGE:
        case OSPF_NBSTATE_LOADING:
        case OSPF_NBSTATE_FULL:
            break;
        default:
            return WRONG_PROTOCOL_STATE;
    }

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
    
        /* Packet */
        eth.type = ETH_TYPE_IPV4;
        eth.next = &ipv4;
        ipv4.dst = IPV4_MC_ALL_OSPF_ROUTERS;
        ipv4.src = interface->ip.address;
        ipv4.ttl = 1;
        ipv4.protocol = PROTOCOL_IPV4_OSPF;
        ipv4.next = &ospf;
    } else {
        ospf_pdu_add_u16(&pdu, 0);
        ospf_pdu_add_u32(&pdu, 0);

        /* Packet */
        eth.type = ETH_TYPE_IPV6;
        eth.next = &ipv6;
        ipv6.ttl = 1;
        ipv6.protocol = IPV6_NEXT_HEADER_OSPF;
        ipv6.next = &ospf;
    }
    ospf_pdu_add_u16(&pdu, interface->mtu);
    ospf_pdu_add_u8(&pdu, options);
    ospf_pdu_add_u8(&pdu, flags);
    ospf_pdu_add_u32(&pdu, ospf_neighbor->dd);

    ospf_pdu_update_len(&pdu);
    ospf_pdu_update_checksum(&pdu);

    /* Add LLS Data Block */
    OSPF_PDU_CURSOR_SET(&pdu, pdu.packet_len);
    ospf_pdu_add_u16(&pdu, 0xfff6); /* checksum */
    ospf_pdu_add_u16(&pdu, 3); /* length */
    ospf_pdu_add_u16(&pdu, OSPF_EXTENDED_OPTION_TLV);
    ospf_pdu_add_u16(&pdu, OSPF_EXTENDED_OPTION_TLV_LEN);
    ospf_pdu_add_u32(&pdu, OSPF_EXT_OPTION_LSDB_RESYNC);

    /* Build packet ... */
    eth.src = interface->mac;
    eth.dst = (uint8_t*)all_ospf_routers_mac;
    ospf.version = pdu.pdu_version;
    ospf.type = pdu.pdu_type;
    ospf.pdu = pdu.pdu;
    ospf.pdu_len = pdu.pdu_len;
    if(bbl_txq_to_buffer(interface->txq, &eth) == BBL_TXQ_OK) {
        LOG(PACKET, "OSPFv%u TX %s on interface %s\n",
            ospf_neighbor->version,
            ospf_pdu_type_string(ospf.type), interface->name);
        ospf_interface->stats.db_des_tx++;
        return PROTOCOL_SUCCESS;
    } else {
        return SEND_ERROR;
    }
}

void
ospf_neigbor_retry_job(timer_s *timer)
{
    ospf_neighbor_s *ospf_neighbor = timer->data;
    switch(ospf_neighbor->state) {
        case OSPF_NBSTATE_EXSTART:
            ospf_neighbor_dbd_tx(ospf_neighbor);
            break;
        default:
            break;
    }
}

static void
ospf_neigbor_exstart(ospf_neighbor_s *ospf_neighbor)
{
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);

    ospf_neighbor->master = true;
    ospf_neighbor->dd = now.tv_sec;

    ospf_neighbor_dbd_tx(ospf_neighbor);
    timer_add_periodic(&g_ctx->timer_root, &ospf_neighbor->timer_retry, "OSPF RETRY", 
                       5, 0, ospf_neighbor, &ospf_neigbor_retry_job);
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
        case OSPF_NBSTATE_EXSTART:
            ospf_neigbor_exstart(ospf_neighbor);
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

    if(pdu->pdu_version == OSPF_VERSION_2) {
        ospf_neighbor->version = OSPF_VERSION_2;
        ospf_neighbor->priority = *OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_HELLO_PRIORITY);
        ospf_neighbor->dr = *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_HELLO_DR);
        ospf_neighbor->bdr = *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV2_OFFSET_HELLO_BDR);
    } else {
        ospf_neighbor->version = OSPF_VERSION_3;
        ospf_neighbor->priority = *OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_HELLO_PRIORITY);
        ospf_neighbor->dr = *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_HELLO_DR);
        ospf_neighbor->bdr = *(uint32_t*)OSPF_PDU_OFFSET(pdu, OSPFV3_OFFSET_HELLO_BDR);
    }

    ospf_neighbor->state = OSPF_NBSTATE_DOWN;
    ospf_neighbor->interface = ospf_interface;

    LOG(OSPF, "OSPFv%u new neighbor %s on interface %s\n",
        ospf_neighbor->version,
        format_ipv4_address(&ospf_neighbor->router_id), 
        ospf_interface->interface->name);

    ospf_neigbor_state(ospf_neighbor, OSPF_NBSTATE_INIT);
    return ospf_neighbor;
}

/**
 * ospf_neighbor_dbd_rx
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

    uint32_t dd;
    uint16_t mtu;

    uint8_t options;
    uint8_t flags;

    ospf_interface->stats.db_des_rx++;

    if(!ospf_neighbor) {
        ospf_rx_error(interface, pdu, "no neighbor");
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
        return;
    }

    UNUSED(options);
}

