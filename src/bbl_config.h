/*
 * BNG Blaster (BBL) - Configuration
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_CONFIG_H__
#define __BBL_CONFIG_H__

typedef struct bbl_access_line_profile_
{
    uint16_t access_line_profile_id;

    // broadband forum tr101

    uint32_t act_up; /* Actual Data Rate Upstream */
    uint32_t act_down; /* Actual Data Rate Downstream */
    uint32_t min_up; /* Minimum Data Rate Upstream */
    uint32_t min_down; /* Minimum Data Rate Downstream */
    uint32_t att_up; /* Attainable DataRate Upstream */
    uint32_t att_down; /* Attainable DataRate Downstream */
    uint32_t max_up; /* Maximum Data Rate Upstream */
    uint32_t max_down; /* Maximum Data Rate Downstream */
    uint32_t min_up_low; /* Min Data Rate Upstream in low power state */
    uint32_t min_down_low; /* Min Data Rate Downstream in low power state */
    uint32_t max_interl_delay_up; /* Max Interleaving Delay Upstream */
    uint32_t act_interl_delay_up; /* Actual Interleaving Delay Upstream */
    uint32_t max_interl_delay_down; /* Max Interleaving Delay Downstream */
    uint32_t act_interl_delay_down; /* Actual Interleaving Delay Downstream */
    uint32_t data_link_encaps; /* Data Link Encapsulation */
    uint32_t dsl_type; /* DSL Type */

    // draft-lihawi-ancp-protocol-access-extension-04

    uint32_t pon_type; /* PON-Access-Type */
    uint32_t etr_up; /* Expected Throughput (ETR) Upstream */
    uint32_t etr_down; /* Expected Throughput (ETR) Downstream */
    uint32_t attetr_up; /* Attainable Expected Throughput (ATTETR) Upstream */
    uint32_t attetr_down; /* Attainable Expected Throughput (ATTETR) Downstream */
    uint32_t gdr_up; /* Gamma Data Rate (GDR) Upstream */
    uint32_t gdr_down; /* Gamma Data Rate (GDR) Downstream */
    uint32_t attgdr_up; /* Attainable Gamma Data Rate (ATTGDR) Upstream */
    uint32_t attgdr_down; /* Attainable Gamma Data Rate (ATTGDR) Downstream */
    uint32_t ont_onu_avg_down; /* ONT/ONU-Average-Data-Rate-Downstream */
    uint32_t ont_onu_peak_down; /* ONT/ONU-Peak-Data-Rate-Downstream */
    uint32_t ont_onu_max_up; /* ONT/ONU-Maximum-Data-Rate-Upstream */
    uint32_t ont_onu_ass_up; /* ONT/ONU-Assured-Data-Rate-Upstream */
    uint32_t pon_max_up; /* PON-Tree-Maximum-Data-Rate-Upstream */
    uint32_t pon_max_down; /* PON-Tree-Maximum-Data-Rate-Downstream */

    void *next; /* pointer to next access line profile element */
} bbl_access_line_profile_s;

typedef struct bbl_access_config_
{
    bool exhausted;
    uint32_t sessions; /* per access config session counter */
    struct bbl_interface_ *access_if;

    char *interface;
    char *network_interface;

    bbl_access_type_t access_type; /* pppoe or ipoe */
    bbl_vlan_mode_t vlan_mode; /* 1:1 (default) or N:1 */

    uint16_t stream_group_id;

    uint16_t access_outer_vlan;
    uint16_t access_outer_vlan_min;
    uint16_t access_outer_vlan_max;
    uint16_t access_inner_vlan;
    uint16_t access_inner_vlan_min;
    uint16_t access_inner_vlan_max;
    uint16_t access_third_vlan;

    bool qinq; /* use ethertype 0x8818 */
    
    /* Static */
    uint32_t static_ip;
    uint32_t static_ip_iter;
    uint32_t static_gateway;
    uint32_t static_gateway_iter;

    /* Authentication */
    char *username;
    char *password;
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

    void *next; /* pointer to next access config element */
} bbl_access_config_s;

typedef struct bbl_network_config_
{
    struct bbl_interface_ *network_if;
    char *interface;

    uint16_t vlan;
    uint32_t ip;
    uint32_t gateway;
    uint8_t gateway_mac[ETH_ADDR_LEN];

    ipv6_prefix ip6;
    ipv6_prefix gateway6;

    bool gateway_resolve_wait;

    void *next; /* pointer to next network config element */
} bbl_network_config_s;

typedef struct bbl_a10nsp_config_
{
    struct bbl_interface_ *a10nsp_if;
    char *interface;

    void *next; /* pointer to next a10nsp config element */
} bbl_a10nsp_config_s;

bool
bbl_config_load_json(char *filename, bbl_ctx_s *ctx);

void
bbl_config_init_defaults(bbl_ctx_s *ctx);

#endif