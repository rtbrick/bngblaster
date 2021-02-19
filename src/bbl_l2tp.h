/*
 * BNG Blaster (BBL) - L2TPv2 Functions (RFC2661)
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#ifndef __BBL_L2TP_H__
#define __BBL_L2TP_H__

#define L2TP_MD5_DIGEST_LEN         16
#define L2TP_MAX_PACKET_SIZE        1500
#define L2TP_MAX_AVP_SIZE           1024

#define L2TP_IPCP_IP_LOCAL          168495882
#define L2TP_IPCP_IP_REMOTE         168430090
#define L2TP_TX_WAIT_MS             10

#define L2TP_SEQ_LT(_a, _b)\
    (((_a) < (_b) && (_b) - (_a) < 32768) || ((_a) > (_b) && (_a) - (_b) > 32768))

#define L2TP_SEQ_GT(_a, _b)\
    (((_a) > (_b) && (_a) - (_b) < 32768) || ((_a) < (_b) && (_b) - (_a) > 32768))

typedef struct bbl_interface_ bbl_interface_s;
typedef struct bbl_ctx_ bbl_ctx_s;

/* L2TP Tunnel State */
typedef enum {
    BBL_L2TP_TUNNEL_IDLE             = 0,
    BBL_L2TP_TUNNEL_WAIT_CTR_CONN    = 1,
    BBL_L2TP_TUNNEL_ESTABLISHED      = 2,
    BBL_L2TP_TUNNEL_SEND_STOPCCN     = 3,
    BBL_L2TP_TUNNEL_RCVD_STOPCCN     = 4,
    BBL_L2TP_TUNNEL_TERMINATED       = 5,
    BBL_L2TP_TUNNEL_MAX
} __attribute__ ((__packed__)) l2tp_tunnel_state_t;

/* L2TP Session State */
typedef enum {
    BBL_L2TP_SESSION_IDLE           = 0,
    BBL_L2TP_SESSION_WAIT_CONN      = 1,
    BBL_L2TP_SESSION_ESTABLISHED    = 2,
    BBL_L2TP_SESSION_TERMINATED     = 3,
    BBL_L2TP_SESSION_MAX
} __attribute__ ((__packed__)) l2tp_session_state_t;

typedef enum {
    BBL_L2TP_CONGESTION_DEFAULT     = 0,
    BBL_L2TP_CONGESTION_SLOW        = 1,
    BBL_L2TP_CONGESTION_AGGRESSIVE  = 2,
    BBL_L2TP_CONGESTION_MAX
} l2tp_congestion_mode_t;


/* L2TP Server Configuration (LNS) */
typedef struct bbl_l2tp_server_
{
    /* Filled by configuration ...*/
    uint32_t ip;
    uint16_t idle_timeout;
    uint16_t hello_interval;
    uint16_t session_limit;
    uint16_t receive_window;
    uint16_t max_retry;

    l2tp_congestion_mode_t congestion_mode;

    char *secret;
    char *host_name;

    /* Pointer to next L2TP server 
     * configuration (simple list). */
    void *next; 

    /* List of L2TP tunnel instances 
     * for the corresponding server. */
    CIRCLEQ_HEAD(bbl_l2tp_server__, bbl_l2tp_tunnel_) tunnel_qhead; 
} bbl_l2tp_server_t;

/* L2TP Session Key */
typedef struct l2tp_key_ {
    uint16_t tunnel_id;
    uint16_t session_id;
} __attribute__ ((__packed__)) l2tp_key_t;

/* L2TP Control TX Queue Entry */
typedef struct bbl_l2tp_queue_
{
    bool data; /* l2tp data packets */
    uint16_t ns;
    uint8_t  ns_offset;
    uint8_t  nr_offset;
    uint8_t  retries;
    uint8_t *packet;
    uint16_t packet_len;
    struct timespec last_tx_time;
    struct bbl_l2tp_tunnel_ *tunnel;
    CIRCLEQ_ENTRY(bbl_l2tp_queue_) txq_qnode; /* TX queue */
    CIRCLEQ_ENTRY(bbl_l2tp_queue_) tx_qnode; /* TX request */
} bbl_l2tp_queue_t;

/* L2TP Data TX Queue Entry */
typedef struct bbl_l2tp_data_queue_
{
    uint8_t *packet;
    uint16_t packet_len;
    CIRCLEQ_ENTRY(bbl_l2tp_data_queue_) tx_qnode; /* TX request */
} bbl_l2tp_data_queue_t;

/* L2TP Tunnel Instance */
typedef struct bbl_l2tp_tunnel_
{
    CIRCLEQ_ENTRY(bbl_l2tp_tunnel_) tunnel_qnode;

    CIRCLEQ_HEAD(bbl_l2tp_tunnel__, bbl_l2tp_session_) session_qhead; 
    CIRCLEQ_HEAD(bbl_l2tp_tunnel___, bbl_l2tp_queue_) txq_qhead; 

    /* Pointer to corresponding network interface */
    struct bbl_interface_ *interface;

    /* Pointer to L2TP server configuration */
    bbl_l2tp_server_t *server;

    /* L2TP tunnel state */
    l2tp_tunnel_state_t state;
    uint32_t state_seconds;
    
    uint16_t tunnel_id;
    uint16_t peer_tunnel_id;
    uint16_t next_session_id;

    uint16_t ns;
    uint16_t nr;
    uint16_t peer_ns;
    uint16_t peer_nr;

    uint16_t peer_receive_window;
    uint16_t peer_firmware;
    uint32_t peer_ip;
    uint32_t peer_framing;
    uint32_t peer_bearer;
    uint32_t peer_tie_breaker;

    bool timer_tx_active;
    struct timer_ *timer_tx;
    struct timer_ *timer_ctrl;

    uint16_t retry;
    uint16_t cwnd;
    uint16_t ssthresh;
    uint16_t cwcount;
    uint32_t send_timestamp;

    bool zlb;
    bbl_l2tp_queue_t *zlb_qnode;

    struct {
        uint32_t control_rx;
        uint32_t control_rx_dup;
        uint32_t control_rx_ooo;
        uint32_t control_tx;
        uint32_t control_retry;
        uint64_t data_rx;
        uint64_t data_tx;
    } stats;

    uint16_t challenge_len;
    uint16_t peer_challenge_len;
    uint16_t challenge_response_len;
    uint16_t peer_challenge_response_len;

    /* The following members must be freed 
     * if tunnel is destroyed! */

    uint8_t *challenge;
    uint8_t *peer_challenge;
    uint8_t *challenge_response;
    uint8_t *peer_challenge_response;

    char *peer_name;
    char *peer_vendor;

} bbl_l2tp_tunnel_t;

/* L2TP Session Instance */
typedef struct bbl_l2tp_session_
{

    CIRCLEQ_ENTRY(bbl_l2tp_session_) session_qnode;

    bbl_l2tp_tunnel_t *tunnel;
    l2tp_session_state_t state;

    struct {
        uint16_t tunnel_id;
        uint16_t session_id;
    } key;

    uint16_t peer_session_id;

    bool data_sequencing;

    uint32_t peer_tx_bps;
    uint32_t peer_rx_bps;
    uint32_t peer_framing;
    uint32_t peer_bearer;
    uint32_t peer_physical_channel_id;
    uint32_t peer_private_group_id;
    uint32_t peer_call_serial_number;

    uint16_t proxy_auth_type;
    uint16_t proxy_auth_id;
    uint16_t proxy_auth_name_len;
    uint16_t proxy_auth_challenge_len;
    uint16_t proxy_auth_response_len;

    uint8_t ipcp_state;
    uint8_t ip6cp_state;

    /* The following members must be freed 
     * if session is destroyed! */

    uint8_t *proxy_auth_name;
    uint8_t *proxy_auth_challenge;
    uint8_t *proxy_auth_response;

    char *peer_called_number;
    char *peer_calling_number;
    char *peer_sub_address;

} bbl_l2tp_session_t;

const char* l2tp_message_string(l2tp_message_type type);
const char* l2tp_tunnel_state_string(l2tp_tunnel_state_t state);
const char* l2tp_session_state_string(l2tp_session_state_t state);

void bbl_l2tp_handler_rx(bbl_ethernet_header_t *eth, bbl_l2tp_t *l2tp, bbl_interface_s *interface);
void bbl_l2tp_stop_all_tunnel(bbl_ctx_s *ctx);

#endif