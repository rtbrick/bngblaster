/*
 * BNG Blaster (BBL) - OSPF Helper Functions
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

const char *
ospf_source_string(uint8_t source)
{
    switch(source) {
        case OSPF_SOURCE_SELF: return "self";
        case OSPF_SOURCE_ADJACENCY: return "adjacency";
        case OSPF_SOURCE_EXTERNAL: return "external";
        default: return "INVALID";
    }
}

const char *
ospf_p2p_adjacency_state_string(uint8_t state)
{
    switch(state) {
        case OSPF_P2P_ADJACENCY_STATE_UP: return "Up";
        case OSPF_P2P_ADJACENCY_STATE_INIT: return "Init";
        case OSPF_P2P_ADJACENCY_STATE_DOWN: return "Down";
        default: return "INVALID";
    }
}

const char *
ospf_adjacency_state_string(uint8_t state)
{
    switch(state) {
        case OSPF_ADJACENCY_STATE_DOWN: return "Up";
        case OSPF_ADJACENCY_STATE_UP: return "Down";
        default: return "INVALID";
    }
}

const char *
ospf_neighbor_state_string(uint8_t state)
{
    switch(state) {
        case OSPF_NBSTATE_DOWN: return "Down";
        case OSPF_NBSTATE_ATTEMPT: return "Attempt";
        case OSPF_NBSTATE_INIT: return "Init";
        case OSPF_NBSTATE_2WAY: return "2-Way";
        case OSPF_NBSTATE_EXSTART: return "ExStart";
        case OSPF_NBSTATE_EXCHANGE: return "Exchange";
        case OSPF_NBSTATE_LOADING: return "Loading";
        case OSPF_NBSTATE_FULL: return "Full";
        default: return "INVALID";
    }
}

const char *
ospf_interface_state_string(uint8_t state)
{
    switch(state) {
        case OSPF_IFSTATE_DOWN: return "Down";
        case OSPF_IFSTATE_LOOPBACK: return "Loopback";
        case OSPF_IFSTATE_WAITING: return "Waiting";
        case OSPF_IFSTATE_P2P: return "P2P";
        case OSPF_IFSTATE_DR_OTHER: return "DROTHER";
        case OSPF_IFSTATE_BACKUP: return "BACKUP";
        case OSPF_IFSTATE_DR: return "DR";
        default: return "INVALID";
    }
}

const char *
ospf_interface_type_string(uint8_t state)
{
    switch(state) {
        case OSPF_INTERFACE_P2P: return "P2P";
        case OSPF_INTERFACE_BROADCAST: return "Broadcast";
        case OSPF_INTERFACE_VIRTUAL: return "Virtual";
        case OSPF_INTERFACE_NBMA: return "NBMA";
        case OSPF_INTERFACE_P2M: return "P2M";
        default: return "INVALID";
    }
}

const char *
ospf_pdu_type_string(uint8_t type)
{

    switch(type) {
        case OSPF_PDU_HELLO: return "Hello";
        case OSPF_PDU_DB_DESC: return "Database Description";
        case OSPF_PDU_LS_REQUEST: return "Link State Request";
        case OSPF_PDU_LS_UPDATE: return "Link State Update";
        case OSPF_PDU_LS_ACK: return "Link State Acknowledgment";
        default: return "UNKNOWN";
    }
}

void
ospf_rx_error(bbl_network_interface_s *interface, ospf_pdu_s *pdu, const char *error)
{
    LOG(OSPF, "OSPFv%u RX %s PDU %s error on interface %s\n", 
        pdu->pdu_version, ospf_pdu_type_string(pdu->pdu_type), 
        error, interface->name);

    interface->stats.ospf_rx_error++;
}

char *
ospf_lsa_hdr_string(ospf_lsa_header_s *hdr)
{
    static char buffer[8][OSPF_LSA_HDR_STRING_LEN];
    static int idx = 0;
    char *ret;
    ret = buffer[idx];
    idx = (idx+1) & 7;

    uint32_t id = hdr->id; 
    uint32_t router = hdr->router;
    snprintf(ret, OSPF_LSA_HDR_STRING_LEN, "TYPE%u:%s:%s:%04x", 
            hdr->type, 
            format_ipv4_address(&id),
            format_ipv4_address(&router),
            be32toh(hdr->seq));
    return ret;
}
