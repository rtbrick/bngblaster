#ifndef __BBL_DEF_H__
#define __BBL_DEF_H__

#define IO_BUFFER_LEN               9216
#define SCRATCHPAD_LEN              4096
#define CHALLENGE_LEN               16

#define FILE_PATH_LEN               128

#define BBL_SESSION_HASHTABLE_SIZE 128993 /* is a prime number */
#define BBL_LI_HASHTABLE_SIZE 32771 /* is a prime number */
#define BBL_STREAM_FLOW_HASHTABLE_SIZE 128993 /* is a prime number */

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

#define DUID_LEN                    10

#define DHCPV6_BUFFER               64

#define BBL_MAX_INTERFACES          32

#define BBL_AVG_SAMPLES             5
#define DATA_TRAFFIC_MAX_LEN        1920

#define UNUSED(x)    (void)x

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

#endif