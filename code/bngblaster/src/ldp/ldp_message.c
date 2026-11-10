/*
 * BNG Blaster (BBL) - LDP Protocol Messages
 * 
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ldp.h"

void
ldp_pdu_close(ldp_session_s *session)
{
    io_buffer_t *buffer = &session->write_buf;
    uint16_t len;

    if(session->pdu_start_idx) {
        /* update PDU length */
        len = buffer->idx - session->pdu_start_idx;
        write_be_uint(buffer->data+session->pdu_start_idx-2, 2, len); 
        session->pdu_start_idx = 0;
    }
    session->stats.pdu_tx++;
}

bool
ldp_pdu_init(ldp_session_s *session)
{
    io_buffer_t *buffer = &session->write_buf;

    if(session->pdu_start_idx) {
        ldp_pdu_close(session);
    }

    if(IO_BUF_REMAINING(buffer) < LDP_MIN_PDU_LEN) {
        return false;
    }

    push_be_uint(buffer, 2, 1); /* PDU Version */
    push_be_uint(buffer, 2, 0); /* PDU Length */
    session->pdu_start_idx = buffer->idx;
    push_data(buffer, (uint8_t*)&session->local.lsr_id, 4);
    push_be_uint(buffer, 2, session->local.label_space_id);
    return true;
}

static void
ldp_msg_close(ldp_session_s *session)
{
    io_buffer_t *buffer = &session->write_buf;
    uint16_t len;

    if(session->msg_start_idx) {
        /* update message length */
        len = buffer->idx - session->msg_start_idx;
        write_be_uint(buffer->data+session->msg_start_idx-2, 2, len); 
        session->msg_start_idx = 0;
    }
    session->stats.message_tx++;
}

static bool
ldp_msg_init(ldp_session_s *session, uint16_t type)
{
    io_buffer_t *buffer = &session->write_buf;

    if(session->msg_start_idx) {
        ldp_msg_close(session);
    }

    if(IO_BUF_REMAINING(buffer) < LDP_MIN_MSG_LEN) {
        return false;
    }

    push_be_uint(buffer, 2, type); /* Type */
    push_be_uint(buffer, 2, 0); /* Length */
    session->msg_start_idx = buffer->idx;
    push_be_uint(buffer, 4, session->message_id++);
    return true;
}

static void
ldp_tlv_close(ldp_session_s *session)
{
    io_buffer_t *buffer = &session->write_buf;
    uint16_t len;

    if(session->tlv_start_idx) {
        /* update length */
        len = buffer->idx - session->tlv_start_idx;
        write_be_uint(buffer->data+session->tlv_start_idx-2, 2, len); 
        session->tlv_start_idx = 0;
    }
}

static bool
ldp_tlv_init(ldp_session_s *session, uint16_t type)
{
    io_buffer_t *buffer = &session->write_buf;

    if(session->tlv_start_idx) {
        ldp_tlv_close(session);
    }

    if(IO_BUF_REMAINING(buffer) < LDP_MIN_TLV_LEN) {
        return false;
    }

    push_be_uint(buffer, 2, type); /* Type */
    push_be_uint(buffer, 2, 0); /* Length */
    session->tlv_start_idx = buffer->idx;
    return true;
}

void
ldp_push_init_message(ldp_session_s *session)
{
    io_buffer_t *buffer = &session->write_buf;
    ldp_msg_init(session, LDP_MESSAGE_TYPE_INITIALIZATION);
    ldp_tlv_init(session, LDP_TLV_TYPE_COMMON_SESSION_PARAMETERS);
    push_be_uint(buffer, 2, 1);
    push_be_uint(buffer, 2, session->local.keepalive_time);
    push_be_uint(buffer, 2, 0);
    push_be_uint(buffer, 2, LDP_MAX_PDU_LEN_INIT);
    push_data(buffer, (uint8_t*)&session->peer.lsr_id, 4);
    push_be_uint(buffer, 2, session->peer.label_space_id);
    ldp_tlv_close(session);
    ldp_msg_close(session);
}

void
ldp_push_keepalive_message(ldp_session_s *session)
{
    ldp_msg_init(session, LDP_MESSAGE_TYPE_KEEPALIVE);
    ldp_msg_close(session);
    session->stats.keepalive_tx++;
}

void
ldp_push_notification_message(ldp_session_s *session)
{
    io_buffer_t *buffer = &session->write_buf;
    ldp_msg_init(session, LDP_MESSAGE_TYPE_NOTIFICATION);
    ldp_tlv_init(session, LDP_TLV_TYPE_STATUS);
    push_be_uint(buffer, 4, session->error_code);
    push_be_uint(buffer, 4, 0);
    push_be_uint(buffer, 2, 0);
    ldp_tlv_close(session);
    ldp_msg_close(session);
}

void
ldp_push_label_mapping_message(ldp_session_s *session, ipv4_prefix *prefix, uint32_t label)
{
    io_buffer_t *buffer = &session->write_buf;
    uint8_t prefix_bytes = BITS_TO_BYTES(prefix->len);

    ldp_msg_init(session, LDP_MESSAGE_TYPE_LABEL_MAPPING);
    ldp_tlv_init(session, LDP_TLV_TYPE_FEC);
    push_be_uint(buffer, 1, 2); /* Prefix FEC */
    push_be_uint(buffer, 2, 1); /* IPv4 */
    push_be_uint(buffer, 1, prefix->len); /* IPv4 */
    push_data(buffer, (uint8_t*)&prefix->address, prefix_bytes);
    ldp_tlv_close(session);
    ldp_tlv_init(session, LDP_TLV_TYPE_GENERIC_LABEL);
    push_be_uint(buffer, 4, label);
    ldp_tlv_close(session);
    ldp_msg_close(session);
}

/* Check if len more bytes fit into the current PDU. */
static bool
ldp_pdu_space(ldp_session_s *session, uint16_t len)
{
    return (session->write_buf.idx - session->pdu_start_idx) + len <= session->max_pdu_len;
}

/**
 * Push address messages (RFC 5036 section 3.5.5), which are
 * split into further PDUs if exceeding the maximum PDU length.
 */
static void
ldp_push_address_messages(ldp_session_s *session, uint16_t afi,
                          uint8_t *addresses, uint8_t address_len, uint32_t count)
{
    io_buffer_t *buffer = &session->write_buf;
    uint32_t i;

    for(i = 0; i < count; i++) {
        if(i == 0 || !ldp_pdu_space(session, address_len)) {
            if(i) {
                ldp_tlv_close(session);
                ldp_msg_close(session);
                ldp_pdu_init(session);
            } else if(!ldp_pdu_space(session, LDP_MIN_MSG_LEN+LDP_MIN_TLV_LEN+2+address_len)) {
                ldp_pdu_init(session);
            }
            ldp_msg_init(session, LDP_MESSAGE_TYPE_ADDRESS);
            ldp_tlv_init(session, LDP_TLV_TYPE_ADDRESS_LIST);
            push_be_uint(buffer, 2, afi);
        }
        push_data(buffer, addresses+(i*address_len), address_len);
    }
    if(count) {
        ldp_tlv_close(session);
        ldp_msg_close(session);
    }
}

static void
ldp_push_implicit_null(ldp_session_s *session)
{
    ldp_tlv_close(session);
    ldp_tlv_init(session, LDP_TLV_TYPE_GENERIC_LABEL);
    push_be_uint(&session->write_buf, 4, LDP_LABEL_IMPLICIT_NULL);
    ldp_tlv_close(session);
    ldp_msg_close(session);
}

/**
 * Push label mapping messages with implicit null label for the
 * prefixes (address with prefix length in network byte order), which
 * are split into further PDUs if exceeding the maximum PDU length.
 */
static void
ldp_push_implicit_null_messages(ldp_session_s *session, uint16_t afi,
                                uint8_t *addresses, uint8_t *prefix_len,
                                uint8_t address_len, uint32_t count)
{
    io_buffer_t *buffer = &session->write_buf;
    uint8_t prefix_bytes;
    uint32_t i;
    /* FEC element and generic label TLV */
    uint16_t len;

    for(i = 0; i < count; i++) {
        prefix_bytes = BITS_TO_BYTES(prefix_len[i]);
        len = LDP_FEC_LEN_MIN+prefix_bytes+LDP_MIN_TLV_LEN+4;
        if(i == 0 || !ldp_pdu_space(session, len)) {
            if(i) {
                ldp_push_implicit_null(session);
                ldp_pdu_init(session);
            } else if(!ldp_pdu_space(session, LDP_MIN_MSG_LEN+LDP_MIN_TLV_LEN+len)) {
                ldp_pdu_init(session);
            }
            ldp_msg_init(session, LDP_MESSAGE_TYPE_LABEL_MAPPING);
            ldp_tlv_init(session, LDP_TLV_TYPE_FEC);
        }
        push_be_uint(buffer, 1, LDP_FEC_ELEMENT_TYPE_PREFIX);
        push_be_uint(buffer, 2, afi);
        push_be_uint(buffer, 1, prefix_len[i]);
        push_data(buffer, addresses+(i*address_len), prefix_bytes);
    }
    if(count) {
        ldp_push_implicit_null(session);
    }
}

/* Clear all bits beyond the prefix length. */
static void
ldp_ipv6_mask(ipv6addr_t *address, uint8_t len)
{
    uint8_t *bytes = (uint8_t*)address;
    for(uint8_t i = 0; i < IPV6_ADDR_LEN; i++) {
        if(len >= 8) {
            len -= 8;
        } else {
            bytes[i] &= (uint8_t)(0xff << (8 - len));
            len = 0;
        }
    }
}

/* Add address if not zero and not yet added. */
static uint32_t
ldp_self_add(uint8_t *addresses, uint8_t *prefix_len, uint32_t count,
             uint8_t *address, uint8_t len, uint8_t address_len)
{
    uint8_t zero[IPV6_ADDR_LEN] = {0};
    uint32_t i;

    if(memcmp(address, zero, address_len) == 0) {
        return count;
    }
    for(i = 0; i < count; i++) {
        if(memcmp(addresses+(i*address_len), address, address_len) == 0 && prefix_len[i] == len) {
            return count;
        }
    }
    memcpy(addresses+(count*address_len), address, address_len);
    prefix_len[count] = len;
    return count+1;
}

/**
 * ldp_push_self_message
 *
 * Push the address messages and the label mappings with implicit null
 * label for the own addresses and interface prefixes, IPv4 with the
 * LSR identifier and IPv6 (RFC 7552) if the IPv6 transport is enabled.
 * Interfaces shared by link and targeted adjacencies are added once.
 *
 * @param session LDP session
 */
void
ldp_push_self_message(ldp_session_s *session)
{
    ldp_instance_s *instance = session->instance;
    ldp_config_s *config = instance->config;
    ldp_adjacency_s *adjacency;
    bbl_network_interface_s *interface;
    bbl_network_interface_s **interfaces;

    uint32_t interface_count = 0;
    uint32_t count, i;

    uint8_t *addresses;
    uint8_t *prefix_len;
    ipv4addr_t ipv4;
    ipv6addr_t ipv6;

    /* Unique interfaces of all adjacencies. */
    count = 0;
    adjacency = instance->adjacencies;
    while(adjacency) {
        count++;
        adjacency = adjacency->next;
    }
    interfaces = calloc(count+1, sizeof(bbl_network_interface_s*));
    adjacency = instance->adjacencies;
    while(adjacency) {
        for(i = 0; i < interface_count; i++) {
            if(interfaces[i] == adjacency->interface) break;
        }
        if(i == interface_count) {
            interfaces[interface_count++] = adjacency->interface;
        }
        adjacency = adjacency->next;
    }
    addresses = calloc(interface_count+2, IPV6_ADDR_LEN);
    prefix_len = calloc(interface_count+2, 1);

    /* IPv4 addresses and prefixes */
    count = ldp_self_add(addresses, prefix_len, 0, (uint8_t*)&config->lsr_id, 32, IPV4_ADDR_LEN);
    if(!config->no_ipv4_transport) {
        count = ldp_self_add(addresses, prefix_len, count, (uint8_t*)&config->ipv4_transport_address, 32, IPV4_ADDR_LEN);
    }
    for(i = 0; i < interface_count; i++) {
        count = ldp_self_add(addresses, prefix_len, count, (uint8_t*)&interfaces[i]->ip.address, 32, IPV4_ADDR_LEN);
    }
    ldp_push_address_messages(session, IANA_AFI_IPV4, addresses, IPV4_ADDR_LEN, count);

    count = ldp_self_add(addresses, prefix_len, 0, (uint8_t*)&config->lsr_id, 32, IPV4_ADDR_LEN);
    for(i = 0; i < interface_count; i++) {
        interface = interfaces[i];
        if(!interface->ip.address) continue;
        ipv4 = interface->ip.address & ipv4_len_to_mask(interface->ip.len);
        count = ldp_self_add(addresses, prefix_len, count, (uint8_t*)&ipv4, interface->ip.len, IPV4_ADDR_LEN);
    }
    ldp_push_implicit_null_messages(session, IANA_AFI_IPV4, addresses, prefix_len, IPV4_ADDR_LEN, count);

    /* IPv6 addresses and prefixes */
    if(ipv6_addr_not_zero(&config->ipv6_transport_address)) {
        count = ldp_self_add(addresses, prefix_len, 0, (uint8_t*)&config->ipv6_transport_address, 128, IPV6_ADDR_LEN);
        for(i = 0; i < interface_count; i++) {
            count = ldp_self_add(addresses, prefix_len, count, (uint8_t*)&interfaces[i]->ip6.address, 128, IPV6_ADDR_LEN);
        }
        ldp_push_address_messages(session, IANA_AFI_IPV6, addresses, IPV6_ADDR_LEN, count);

        count = ldp_self_add(addresses, prefix_len, 0, (uint8_t*)&config->ipv6_transport_address, 128, IPV6_ADDR_LEN);
        for(i = 0; i < interface_count; i++) {
            interface = interfaces[i];
            if(!interface->ip6.len) continue;
            memcpy(&ipv6, &interface->ip6.address, sizeof(ipv6addr_t));
            ldp_ipv6_mask(&ipv6, interface->ip6.len);
            count = ldp_self_add(addresses, prefix_len, count, (uint8_t*)&ipv6, interface->ip6.len, IPV6_ADDR_LEN);
        }
        ldp_push_implicit_null_messages(session, IANA_AFI_IPV6, addresses, prefix_len, IPV6_ADDR_LEN, count);
    }

    free(addresses);
    free(prefix_len);
    free(interfaces);
}
