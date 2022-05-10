/*
 * BNG Blaster (BBL) - Defines
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
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

/* Experimental NETMAP Support */
#ifdef BNGBLASTER_NETMAP
#define LIBNETMAP_NOTHREADSAFE
#include <net/netmap.h>
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#endif

#define IO_BUFFER_LEN               9216
#define SCRATCHPAD_LEN              4096
#define CHALLENGE_LEN               16

#define FILE_PATH_LEN               128

#define BBL_SESSION_HASHTABLE_SIZE 128993 /* is a prime number */
#define BBL_LI_HASHTABLE_SIZE 32771 /* is a prime number */
#define BBL_STREAM_FLOW_HASHTABLE_SIZE 128993 /* is a prime number */

/* Mock Addresses */
#define MOCK_IP_LOCAL               168495882
#define MOCK_IP_REMOTE              168430090
#define MOCK_DNS1                   168561674
#define MOCK_DNS2                   168627466

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
#define BBL_SEND_SESSION_IPV4       0x00002000
#define BBL_SEND_SESSION_IPV6       0x00004000
#define BBL_SEND_SESSION_IPV6PD     0x00008000
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
#define BBL_IF_SEND_ISIS_P2P_HELLO  0x00000004

#define DUID_LEN                    10

#define DHCPV6_BUFFER               64

#define BBL_MAX_INTERFACES          32

#define BBL_AVG_SAMPLES             5
#define DATA_TRAFFIC_MAX_LEN        1920

typedef enum {
    IO_MODE_PACKET_MMAP_RAW = 0,    /* RX packet_mmap ring / TX raw sockets */
    IO_MODE_PACKET_MMAP,            /* RX/TX packet_mmap ring */
    IO_MODE_RAW,                    /* RX/TX raw sockets */
    IO_MODE_NETMAP                  /* RX/TX netmap ring */
} __attribute__ ((__packed__)) bbl_io_mode_t;

typedef enum {
    INTERFACE_TYPE_ACCESS = 0,
    INTERFACE_TYPE_NETWORK,
    INTERFACE_TYPE_A10NSP
} __attribute__ ((__packed__)) bbl_interface_type_t;

typedef enum {
    ACCESS_TYPE_PPPOE = 0,
    ACCESS_TYPE_IPOE
} __attribute__ ((__packed__)) bbl_access_type_t;

typedef enum {
    VLAN_MODE_11 = 0,   /* VLAN mode 1:1 */
    VLAN_MODE_N1        /* VLAN mode N:1 */
} __attribute__ ((__packed__)) bbl_vlan_mode_t;

typedef enum {
    IGMP_GROUP_IDLE = 0,
    IGMP_GROUP_LEAVING,
    IGMP_GROUP_ACTIVE,
    IGMP_GROUP_JOINING,
    IGMP_GROUP_MAX
} __attribute__ ((__packed__)) igmp_group_state_t;

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
    BBL_PPP_CLOSED      = 0,
    BBL_PPP_INIT        = 1,
    BBL_PPP_LOCAL_ACK   = 2,
    BBL_PPP_PEER_ACK    = 3,
    BBL_PPP_OPENED      = 4,
    BBL_PPP_TERMINATE   = 5,
    BBL_PPP_MAX
} __attribute__ ((__packed__)) ppp_state_t;

/*
 * DHCP state
 *
 * This is a simple not fully RFC conform version
 * of the DHCP FSM.
 */
typedef enum {
    BBL_DHCP_INIT           = 0,
    BBL_DHCP_SELECTING      = 1,
    BBL_DHCP_REQUESTING     = 2,
    BBL_DHCP_BOUND          = 3,
    BBL_DHCP_RENEWING       = 4,
    BBL_DHCP_RELEASE        = 5,
    BBL_DHCP_MAX
} __attribute__ ((__packed__)) dhcp_state_t;

typedef struct bbl_ctx_ bbl_ctx_s;
typedef struct bbl_interface_ bbl_interface_s;
typedef struct bbl_session_ bbl_session_s;
typedef struct bbl_a10nsp_session_ bbl_a10nsp_session_t;
typedef struct bbl_stream_thread_ bbl_stream_thread;
typedef struct bbl_stream_config_ bbl_stream_config;
typedef struct bbl_stream_ bbl_stream;
typedef struct bbl_tcp_ctx_ bbl_tcp_ctx_t;

#endif