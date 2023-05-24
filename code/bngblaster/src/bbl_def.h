/*
 * BNG Blaster (BBL) - Defines
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_DEF_H__
#define __BBL_DEF_H__

#include <string.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <sys/queue.h>
#include <sys/time.h>
#include <signal.h>
#include <math.h>
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <sys/epoll.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <common.h>

#include "libdict/dict.h"

/* LwIP */
#ifdef BNGBLASTER_LWIP
#include "lwip/timeouts.h"
#include "lwip/init.h"
#include "lwip/tcp.h"
#include "lwip/api.h"
#endif

#define IO_BUFFER_LEN               9216
#define SCRATCHPAD_LEN              4096
#define CHALLENGE_LEN               16

#define FILE_PATH_LEN               128

#define BBL_SESSION_HASHTABLE_SIZE 128993 /* is a prime number */
#define BBL_LI_HASHTABLE_SIZE 32771 /* is a prime number */
#define BBL_STREAM_FLOW_HASHTABLE_SIZE 128993 /* is a prime number */

/* Mock Addresses */
#define MOCK_IP_LOCAL               167772170   /* 10.0.0.10 */
#define MOCK_IP_REMOTE              168430090   /* 10.10.10.10 */

#define MOCK_DNS1                   134744072   /* 8.8.8.8 */
#define MOCK_DNS2                   16843009    /* 1.1.1.1 */

static const uint8_t mock_dhcpv6_server_duid[] = {0x00, 0x02, 0x00, 0x00, 0x8A, 0xC3, 0x01, 0x01};
static const ipv6addr_t mock_ipv6_local = {0xFC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
static const ipv6addr_t mock_ipv6_ia_na = {0xFC, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02};
static const ipv6_prefix mock_ipv6_ia_pd = {
    .len = 56,
    .address = {0xFC, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
};

/* Interface Send Mask */
#define BBL_SEND_LACP               0x00000001

/* Access Interface Send Mask */
#define BBL_SEND_DISCOVERY          0x00000001
#define BBL_SEND_LCP_RESPONSE       0x00000002
#define BBL_SEND_LCP_REQUEST        0x00000004
#define BBL_SEND_PAP_REQUEST        0x00000008
#define BBL_SEND_CHAP_RESPONSE      0x00000010
#define BBL_SEND_IPCP_RESPONSE      0x00000020
#define BBL_SEND_IPCP_REQUEST       0x00000040
#define BBL_SEND_IP6CP_REQUEST      0x00000080
#define BBL_SEND_IP6CP_RESPONSE     0x00000100
#define BBL_SEND_ICMPV6_RS          0x00000200
#define BBL_SEND_DHCPV6_REQUEST     0x00000400
#define BBL_SEND_IGMP               0x00000800
#define BBL_SEND_ARP_REQUEST        0x00010000
#define BBL_SEND_ARP_REPLY          0x00020000
#define BBL_SEND_DHCP_REQUEST       0x00040000
#define BBL_SEND_ICMPV6_REPLY       0x00080000
#define BBL_SEND_ICMPV6_NS          0x00100000
#define BBL_SEND_ICMPV6_NA          0x00200000
#define BBL_SEND_CFM_CC             0x00400000

/* Network Interface Send Mask */
#define BBL_IF_SEND_ARP_REQUEST     0x00000001
#define BBL_IF_SEND_ICMPV6_NS       0x00000002
#define BBL_IF_SEND_ICMPV6_RA       0x00000004
#define BBL_IF_SEND_ISIS_P2P_HELLO  0x00000008
#define BBL_IF_SEND_LDP_HELLO_IPV4  0x00000010
#define BBL_IF_SEND_LDP_HELLO_IPV6  0x00000020
#define BBL_IF_SEND_OSPFV2_HELLO    0x00000040
#define BBL_IF_SEND_OSPFV3_HELLO    0x00000080

#define BBL_AVG_SAMPLES             5
#define BBL_MAX_STREAM_OVERHEAD     128

#define DUID_LEN                    10
#define DHCPV6_BUFFER               64

#define ENABLE_ENDPOINT(_endpoint) \
    if(_endpoint != ENDPOINT_DISABLED) _endpoint = ENDPOINT_ENABLED

#define ACTIVATE_ENDPOINT(_endpoint) \
    if(_endpoint != ENDPOINT_DISABLED) _endpoint = ENDPOINT_ACTIVE

typedef enum {
    IANA_AFI_RESERVED   = 0,
    IANA_AFI_IPV4       = 1,
    IANA_AFI_IPV6       = 2,
} __attribute__ ((__packed__)) iana_afi_t;

typedef enum {
    ACCESS_TYPE_PPPOE = 0,
    ACCESS_TYPE_IPOE
} __attribute__ ((__packed__)) access_type_t;

typedef enum {
    VLAN_MODE_11 = 0,   /* VLAN mode 1:1 */
    VLAN_MODE_N1        /* VLAN mode N:1 */
} __attribute__ ((__packed__)) vlan_mode_t;

typedef enum {
    INTERFACE_DISABLED = 0,
    INTERFACE_UP,
    INTERFACE_DOWN,
    INTERFACE_STANDBY,
} __attribute__ ((__packed__)) interface_state_t;

typedef enum {
    DEFAULT_INTERFACE = 0,
    LAG_INTERFACE,
    LAG_MEMBER_INTERFACE,
} __attribute__ ((__packed__)) interface_type_t;

typedef enum {
    IGMP_GROUP_IDLE = 0,
    IGMP_GROUP_LEAVING,
    IGMP_GROUP_ACTIVE,
    IGMP_GROUP_JOINING,
    IGMP_GROUP_MAX
} __attribute__ ((__packed__)) igmp_group_state_t;

typedef enum {
    ENDPOINT_DISABLED = 0,
    ENDPOINT_ENABLED,
    ENDPOINT_ACTIVE,
} __attribute__ ((__packed__)) endpoint_state_t;

typedef enum {
    LACP_DISABLED = 0,
    LACP_EXPIRED,
    LACP_DEFAULTED,
    LACP_CURRENT
} __attribute__ ((__packed__)) lacp_state_t;

/*
 * Session state
 */
typedef enum {
    BBL_IDLE = 0,
    BBL_IPOE_SETUP,         /* IPoE setup */
    BBL_PPPOE_INIT,         /* send PADI */
    BBL_PPPOE_REQUEST,      /* send PADR */
    BBL_PPP_LINK,           /* send LCP requests */
    BBL_PPP_AUTH,           /* send authentication requests */
    BBL_PPP_NETWORK,        /* send NCP requests */
    BBL_ESTABLISHED,        /* established */
    BBL_PPP_TERMINATING,    /* send LCP terminate requests */
    BBL_TERMINATING,        /* send PADT */
    BBL_TERMINATED,         /* terminated */
    BBL_MAX
} __attribute__ ((__packed__)) session_state_t;

/*
 * PPP state (LCP, IPCP and IP6CP)
 *
 * This is a simple not fully RFC conform version
 * of the PPP FSM.
 */
typedef enum {
    BBL_PPP_DISABLED    = 0,
    BBL_PPP_REJECTED    = 1,
    BBL_PPP_CLOSED      = 2,
    BBL_PPP_INIT        = 3,
    BBL_PPP_LOCAL_ACK   = 4,
    BBL_PPP_PEER_ACK    = 5,
    BBL_PPP_OPENED      = 6,
    BBL_PPP_TERMINATE   = 7,
    BBL_PPP_MAX
} __attribute__ ((__packed__)) ppp_state_t;

/*
 * DHCP state
 *
 * This is a simple not fully RFC conform version
 * of the DHCP FSM.
 */
typedef enum {
    BBL_DHCP_DISABLED       = 0,
    BBL_DHCP_INIT           = 1,
    BBL_DHCP_SELECTING      = 2,
    BBL_DHCP_REQUESTING     = 3,
    BBL_DHCP_BOUND          = 4,
    BBL_DHCP_RENEWING       = 5,
    BBL_DHCP_RELEASE        = 6,
    BBL_DHCP_MAX
} __attribute__ ((__packed__)) dhcp_state_t;

typedef struct bbl_ctx_ bbl_ctx_s;
typedef struct bbl_txq_ bbl_txq_s;
typedef struct bbl_lag_ bbl_lag_s;
typedef struct bbl_lag_member_ bbl_lag_member_s;
typedef struct bbl_igmp_group_ bbl_igmp_group_s;
typedef struct bbl_interface_ bbl_interface_s;
typedef struct bbl_access_interface_ bbl_access_interface_s;
typedef struct bbl_network_interface_ bbl_network_interface_s;
typedef struct bbl_a10nsp_interface_ bbl_a10nsp_interface_s;
typedef struct bbl_a10nsp_session_ bbl_a10nsp_session_s;
typedef struct bbl_session_ bbl_session_s;
typedef struct bbl_stream_thread_ bbl_stream_thread_s;
typedef struct bbl_stream_config_ bbl_stream_config_s;
typedef struct bbl_stream_group_ bbl_stream_group_s;
typedef struct bbl_stream_ bbl_stream_s;
typedef struct bbl_tcp_ctx_ bbl_tcp_ctx_s;
typedef struct bbl_ctrl_thread_ bbl_ctrl_thread_s;

#endif