/*
 * BNG Blaster (BBL) - L2TPv2 Functions (RFC2661)
 *
 * Christian Giese, February 2021
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_L2TP_AVP_H__
#define __BBL_L2TP_AVP_H__

typedef enum l2tp_avp_type_ {
    L2TP_AVP_MESSAGE_TYPE                = 0,
    L2TP_AVP_RESULT_CODE                 = 1,
    L2TP_AVP_PROTOCOL_VERSION            = 2,
    L2TP_AVP_FRAMING_CAPABILITIES        = 3,
    L2TP_AVP_BEARER_CAPABILITIES         = 4,
    L2TP_AVP_TIE_BREAKER                 = 5,
    L2TP_AVP_FIRMWARE_REVISION           = 6,
    L2TP_AVP_HOST_NAME                   = 7,
    L2TP_AVP_VENDOR_NAME                 = 8,
    L2TP_AVP_ASSIGNED_TUNNEL_ID          = 9,
    L2TP_AVP_RECEIVE_WINDOW_SIZE         = 10,
    L2TP_AVP_CHALLENGE                   = 11,
    L2TP_AVP_CHALLENGE_RESPONSE          = 13,
    L2TP_AVP_ASSIGNED_SESSION_ID         = 14,
    L2TP_AVP_CALL_SERIAL_NUMBER          = 15,
    L2TP_AVP_MINIMUM_BPS                 = 16,
    L2TP_AVP_MAXIMUM_BPS                 = 17,
    L2TP_AVP_BEARER_TYPE                 = 18,
    L2TP_AVP_FRAMING_TYPE                = 19,
    L2TP_AVP_CALLED_NUMBER               = 21,
    L2TP_AVP_CALLING_NUMBER              = 22,
    L2TP_AVP_SUB_ADDRESS                 = 23,
    L2TP_AVP_TX_CONNECT_SPEED            = 24,
    L2TP_AVP_PHYSICAL_CHANNEL_ID         = 25,
    L2TP_AVP_INITIAL_RECEIVED_CONFREQ    = 26,
    L2TP_AVP_LAST_SENT_CONFREQ           = 27,
    L2TP_AVP_LAST_RECEIVED_CONFREQ       = 28,
    L2TP_AVP_PROXY_AUTHEN_TYPE           = 29,
    L2TP_AVP_PROXY_AUTHEN_NAME           = 30,
    L2TP_AVP_PROXY_AUTHEN_CHALLENGE      = 31,
    L2TP_AVP_PROXY_AUTHEN_ID             = 32,
    L2TP_AVP_PROXY_AUTHEN_RESPONSE       = 33,
    L2TP_AVP_CALL_ERRORS                 = 34,
    L2TP_AVP_ACCM                        = 35,
    L2TP_AVP_RANDOM_VECTOR               = 36,
    L2TP_AVP_PRIVATE_GROUP_ID            = 37,
    L2TP_AVP_RX_CONNECT_SPEED            = 38,
    L2TP_AVP_SEQUENCING_REQUIRED         = 39,
    L2TP_AVP_PPP_DISCONNECT_CODE         = 46,
    L2TP_AVP_CONNECT_SPEED_UPDATE        = 97,
    L2TP_AVP_CONNECT_SPEED_UPDATE_ENABLE = 98,
    L2TP_AVP_MAX
} l2tp_avp_type_t;

typedef enum l2tp_avp_value_type_ {
    L2TP_AVP_VALUE_BYTES = 0,
    L2TP_AVP_VALUE_UINT16,
    L2TP_AVP_VALUE_UINT32,
    L2TP_AVP_VALUE_UINT64
} l2tp_avp_value_type_t;

typedef struct bbl_l2tp_avp_
{
    bool m;
    bool h;
    uint16_t len;
    uint16_t vendor;
    uint16_t type;
    uint8_t *value;
    uint8_t  value_type;
} bbl_l2tp_avp_t;

bool
bbl_l2tp_avp_decode_session(bbl_l2tp_s *l2tp, bbl_l2tp_tunnel_s *l2tp_tunnel, bbl_l2tp_session_s *l2tp_session);

bool
bbl_l2tp_avp_decode_tunnel(bbl_l2tp_s *l2tp, bbl_l2tp_tunnel_s *l2tp_tunnel);

bool
bbl_l2tp_avp_decode_csun(bbl_l2tp_s *l2tp, bbl_l2tp_tunnel_s *l2tp_tunnel);

void
bbl_l2tp_avp_encode_attributes(bbl_l2tp_tunnel_s *l2tp_tunnel, bbl_l2tp_session_s *l2tp_session,
                               l2tp_message_t l2tp_type, uint8_t *buf, uint16_t *len);

#endif
