/*
 * BNG Blaster (BBL) - Configuration
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_CONFIG_H__
#define __BBL_CONFIG_H__

typedef struct bbl_access_config_
{
    bool exhausted;
    uint32_t sessions; /* per access config session counter */

    char *interface;
    char *network_interface;
    char *a10nsp_interface;

    access_type_t access_type; /* pppoe or ipoe */
    vlan_mode_t vlan_mode; /* 1:1 (default) or N:1 */

    uint16_t stream_group_id;

    uint16_t access_outer_vlan;
    uint16_t access_outer_vlan_min;
    uint16_t access_outer_vlan_max;
    uint16_t access_inner_vlan;
    uint16_t access_inner_vlan_min;
    uint16_t access_inner_vlan_max;
    uint16_t access_third_vlan;

    bool monkey; /* enable monkey testing */
    bool qinq; /* use ethertype 0x8818 */

    /* Static */
    uint32_t static_ip;
    uint32_t static_ip_iter;
    uint32_t static_gateway;
    uint32_t static_gateway_iter;

    /* Authentication */
    const char *username;
    const char *password;
    uint16_t authentication_protocol;

    /* Access Line */
    char *agent_remote_id;
    char *agent_circuit_id;
    uint32_t rate_up;
    uint32_t rate_down;
    uint32_t dsl_type;

    uint16_t access_line_profile_id;

    /* Protocols */
    bool ipcp_enable;
    bool ip6cp_enable;
    bool ipv4_enable;
    bool ipv6_enable;
    bool dhcp_enable;
    bool dhcpv6_enable;
    bool igmp_autostart;
    uint8_t igmp_version;
    bool session_traffic_autostart;

    /* CFM CC */
    bool cfm_cc;
    uint8_t cfm_level;
    uint16_t cfm_ma_id;
    char *cfm_ma_name;

    /* Iterator */
    uint32_t i1;
    uint32_t i1_step;
    uint32_t i2;
    uint32_t i2_step;

    uint16_t ppp_mru;

    void *next; /* pointer to next access config element */
    bbl_access_interface_s *access_interface;
} bbl_access_config_s;

typedef struct bbl_network_config_
{
    char *interface;
    
    uint8_t mac[ETH_ADDR_LEN];
    uint8_t gateway_mac[ETH_ADDR_LEN];
    bool gateway_resolve_wait;
    uint16_t vlan;
    uint16_t mtu;
    
    ipv4_prefix ip;
    ipv4addr_t gateway;

    ipv6_prefix ip6;
    ipv6addr_t gateway6;

    uint16_t isis_instance_id;
    uint8_t  isis_level;
    bool     isis_p2p;
    uint32_t isis_l1_metric;
    uint32_t isis_l2_metric;

    void *next; /* pointer to next network config element */
    bbl_network_interface_s *network_interface;
} bbl_network_config_s;

typedef struct bbl_a10nsp_config_
{
    char *interface;
    uint8_t mac[ETH_ADDR_LEN];
    bool qinq;

    void *next; /* pointer to next a10nsp config element */
    bbl_a10nsp_interface_s *a10nsp_interface;
} bbl_a10nsp_config_s;

typedef struct bbl_link_config_
{
    char *interface;
    char *description;
    uint8_t mac[ETH_ADDR_LEN];

    io_mode_t io_mode;

    uint16_t io_slots_tx;
    uint16_t io_slots_rx;

    bool qdisc_bypass;

    uint64_t tx_interval; /* TX interval in nsec */
    uint64_t rx_interval; /* RX interval in nsec */

    uint8_t tx_threads;
    uint8_t rx_threads;
    uint8_t lag_id;

    uint32_t lacp_priority;
    uint32_t lacp_interval;

    void *next; /* pointer to next link config element */
    bbl_interface_s *link;
} bbl_link_config_s;

typedef struct bbl_lag_config_
{
    uint8_t id;

    bool lacp_enable;
    uint32_t lacp_priority;

    void *next; /* pointer to next lag config element */
} bbl_lag_config_s;

bool
bbl_config_load_json(const char *filename);

bool
bbl_config_streams_load_json(const char *filename);

void
bbl_config_init_defaults();

#endif
