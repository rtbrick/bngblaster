/*
 * BNG Blaster (BBL) - Configuration
 *
 * Hannes Gredler, July 2020
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"
#include "bbl_config.h"
#include "bbl_stream.h"
#include <sys/stat.h>

const char g_default_user[] = "user{session-global}@rtbrick.com";
const char g_default_pass[] = "test";
const char g_default_hostname[] = "bngblaster";
const char g_default_router_id[] = "10.10.10.10";
const char g_default_system_id[] = "0100.1001.0010";
const char g_default_area[] = "49.0001/24";

static void
add_secondary_ipv4(uint32_t ipv4)
{
    bbl_secondary_ip_s  *secondary_ip;
    bbl_interface_s *interface;
    bbl_network_interface_s *network_interface;

    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        network_interface = interface->network;
        while(network_interface) {
            if(ipv4 == network_interface->ip.address) {
                return;
            }
            network_interface = network_interface->next;
        }
    }

    /* Add secondary IP address to be served by ARP */
    secondary_ip = g_ctx->config.secondary_ip_addresses;
    if(secondary_ip) {
        while(secondary_ip) {
            if(secondary_ip->ip == ipv4) {
                /* Address is already known ... */
                break;
            }
            if(secondary_ip->next) {
                /* Check next address ... */
                secondary_ip = secondary_ip->next;
            } else {
                /* Append secondary address ... */
                secondary_ip->next = calloc(1, sizeof(bbl_secondary_ip_s));
                secondary_ip = secondary_ip->next;
                secondary_ip->ip = ipv4;
                break;
            }
        }
    } else {
        /* Add first secondary address */
        g_ctx->config.secondary_ip_addresses = calloc(1, sizeof(bbl_secondary_ip_s));
        g_ctx->config.secondary_ip_addresses->ip = ipv4;
    }
}

static void
add_secondary_ipv6(ipv6addr_t ipv6)
{
    bbl_secondary_ip6_s *secondary_ip6;
    bbl_interface_s *interface;
    bbl_network_interface_s *network_interface;

    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        network_interface = interface->network;
        while(network_interface) {
            if(memcmp(ipv6, network_interface->ip6.address, IPV6_ADDR_LEN) == 0) {
                return;
            }
            network_interface = network_interface->next;
        }
    }

    /* Add secondary IP address to be served by ICMPv6 */
    secondary_ip6 = g_ctx->config.secondary_ip6_addresses;
    if(secondary_ip6) {
        while(secondary_ip6) {
            if(memcmp(secondary_ip6->ip, ipv6, IPV6_ADDR_LEN) == 0) {
                /* Address is already known ... */
                break;
            }
            if(secondary_ip6->next) {
                /* Check next address ... */
                secondary_ip6 = secondary_ip6->next;
            } else {
                /* Append secondary address ... */
                secondary_ip6->next = calloc(1, sizeof(bbl_secondary_ip6_s));
                secondary_ip6 = secondary_ip6->next;
                memcpy(secondary_ip6->ip, ipv6, IPV6_ADDR_LEN);
                break;
            }
        }
    } else {
        /* Add first secondary address */
        g_ctx->config.secondary_ip6_addresses = calloc(1, sizeof(bbl_secondary_ip6_s));
        memcpy(g_ctx->config.secondary_ip6_addresses->ip, ipv6, IPV6_ADDR_LEN);
    }
}

static bool
json_parse_access_line_profile(json_t *config, bbl_access_line_profile_s *profile)
{
    json_t *value = NULL;

    value = json_object_get(config, "access-line-profile-id");
    if(value) {
        profile->access_line_profile_id = json_number_value(value);
    } else {
        fprintf(stderr, "Config error: Missing value for access-line-profiles->access-line-profile-id\n");
        return false;
    }

    value = json_object_get(config, "act-up");
    if(value) {
        profile->act_up = json_number_value(value);
    }
    value = json_object_get(config, "act-down");
    if(value) {
        profile->act_down = json_number_value(value);
    }
    value = json_object_get(config, "min-up");
    if(value) {
        profile->min_up = json_number_value(value);
    }
    value = json_object_get(config, "min-down");
    if(value) {
        profile->min_down = json_number_value(value);
    }
    value = json_object_get(config, "att-up");
    if(value) {
        profile->att_up = json_number_value(value);
    }
    value = json_object_get(config, "att-down");
    if(value) {
        profile->att_down = json_number_value(value);
    }
    value = json_object_get(config, "min-up-low");
    if(value) {
        profile->min_up_low = json_number_value(value);
    }
    value = json_object_get(config, "min-down-low");
    if(value) {
        profile->min_down_low = json_number_value(value);
    }
    value = json_object_get(config, "max-interl-delay-up");
    if(value) {
        profile->max_interl_delay_up = json_number_value(value);
    }
    value = json_object_get(config, "act-interl-delay-up");
    if(value) {
        profile->act_interl_delay_up = json_number_value(value);
    }
    value = json_object_get(config, "max-interl-delay-down");
    if(value) {
        profile->max_interl_delay_down = json_number_value(value);
    }
    value = json_object_get(config, "act-interl-delay-down");
    if(value) {
        profile->act_interl_delay_down = json_number_value(value);
    }
    value = json_object_get(config, "data-link-encaps");
    if(value) {
        profile->data_link_encaps = json_number_value(value);
    }
    value = json_object_get(config, "dsl-type");
    if(value) {
        profile->dsl_type = json_number_value(value);
    }
    value = json_object_get(config, "pon-type");
    if(value) {
        profile->pon_type = json_number_value(value);
    }
    value = json_object_get(config, "etr-up");
    if(value) {
        profile->etr_up = json_number_value(value);
    }
    value = json_object_get(config, "etr-down");
    if(value) {
        profile->etr_down = json_number_value(value);
    }
    value = json_object_get(config, "attetr-up");
    if(value) {
        profile->attetr_up = json_number_value(value);
    }
    value = json_object_get(config, "attetr-down");
    if(value) {
        profile->attetr_down = json_number_value(value);
    }
    value = json_object_get(config, "gdr-up");
    if(value) {
        profile->gdr_up = json_number_value(value);
    }
    value = json_object_get(config, "gdr-down");
    if(value) {
        profile->gdr_down = json_number_value(value);
    }
    value = json_object_get(config, "attgdr-up");
    if(value) {
        profile->attgdr_up = json_number_value(value);
    }
    value = json_object_get(config, "attgdr-down");
    if(value) {
        profile->attgdr_down = json_number_value(value);
    }
    value = json_object_get(config, "ont-onu-avg-down");
    if(value) {
        profile->ont_onu_avg_down = json_number_value(value);
    }
    value = json_object_get(config, "ont-onu-peak-down");
    if(value) {
        profile->ont_onu_peak_down = json_number_value(value);
    }
    value = json_object_get(config, "ont-onu-max-up");
    if(value) {
        profile->ont_onu_max_up = json_number_value(value);
    }
    value = json_object_get(config, "ont-onu-ass-up");
    if(value) {
        profile->ont_onu_ass_up = json_number_value(value);
    }
    value = json_object_get(config, "pon-max-up");
    if(value) {
        profile->pon_max_up = json_number_value(value);
    }
    value = json_object_get(config, "pon-max-down");
    if(value) {
        profile->pon_max_down = json_number_value(value);
    }
    return true;
}

static bool
json_parse_lag(json_t *lag, bbl_lag_config_s *lag_config)
{
    json_t *value = NULL;
    const char *s = NULL;
    
    static uint8_t lag_id = 0;

    lag_config->id = ++lag_id;
    if(json_unpack(lag, "{s:s}", "interface", &s) == 0) {
        lag_config->interface = strdup(s);
    } else {
        fprintf(stderr, "JSON config error: Missing value for lag->interface\n");
        return false;
    }
    value = json_object_get(lag, "lacp");
    if(json_is_boolean(value)) {
        lag_config->lacp_enable = json_boolean_value(value);
    }
    value = json_object_get(lag, "lacp-timeout-short");
    if(json_is_boolean(value)) {
        lag_config->lacp_timeout_short = json_boolean_value(value);
    }
    value = json_object_get(lag, "lacp-system-priority");
    if(value) {
        lag_config->lacp_system_priority = json_number_value(value);
    } else {
        lag_config->lacp_system_priority = 32768;
    }
    if(json_unpack(lag, "{s:s}", "lacp-system-id", &s) == 0) {
        if(sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &lag_config->lacp_system_id[0],
                &lag_config->lacp_system_id[1],
                &lag_config->lacp_system_id[2],
                &lag_config->lacp_system_id[3],
                &lag_config->lacp_system_id[4],
                &lag_config->lacp_system_id[5]) < 6) {
            fprintf(stderr, "JSON config error: Invalid value for lag->lacp-system-id\n");
            return false;
        }
    } else {
        lag_config->lacp_system_id[0] = 0x02;
        lag_config->lacp_system_id[1] = 0xff;
        lag_config->lacp_system_id[2] = 0xff;
        lag_config->lacp_system_id[3] = 0xff;
        lag_config->lacp_system_id[4] = 0xff;
    }
    value = json_object_get(lag, "lacp-min-active-links");
    if(value) {
        lag_config->lacp_min_active_links = json_number_value(value);
    } else {
        lag_config->lacp_min_active_links = 0;
    }
    value = json_object_get(lag, "lacp-max-active-links");
    if(value) {
        lag_config->lacp_min_active_links = json_number_value(value);
    } else {
        lag_config->lacp_max_active_links = UINT8_MAX;
    }

    if(json_unpack(lag, "{s:s}", "mac", &s) == 0) {
        if(sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &lag_config->mac[0],
                &lag_config->mac[1],
                &lag_config->mac[2],
                &lag_config->mac[3],
                &lag_config->mac[4],
                &lag_config->mac[5]) < 6) {
            fprintf(stderr, "JSON config error: Invalid value for lag->mac\n");
            return false;
        }
    } else {
        lag_config->mac[0] = 0x02;
        lag_config->mac[1] = 0xff;
        lag_config->mac[2] = 0xff;
        lag_config->mac[3] = 0xff;
        lag_config->mac[4] = 0xff;
        lag_config->mac[5] = lag_config->id;
    }
    return true;
}

static bool
lag_present(char *interface)
{
    bbl_lag_config_s *config = g_ctx->config.lag_config;
    while(config) {
        if(strcmp(config->interface, interface) == 0) {
            return true;
        }
        config = config->next;
    }
    return false;
}

static bool
link_present(char *interface)
{
    bbl_link_config_s *config = g_ctx->config.link_config;
    while(config) {
        if(config->interface && strcmp(config->interface, interface) == 0) {
            return true;
        }
        config = config->next;
    }
    return false;
}

static void
link_add(char *interface_name)
{
    bbl_link_config_s *link_config;
    if(link_present(interface_name)|| lag_present(interface_name)) {
        return;
    }

    link_config = calloc(1, sizeof(bbl_link_config_s));
    link_config->interface = strdup(interface_name);
    link_config->io_mode = g_ctx->config.io_mode;
    link_config->io_slots_rx = g_ctx->config.io_slots;
    link_config->io_slots_tx = g_ctx->config.io_slots;
    link_config->qdisc_bypass = g_ctx->config.qdisc_bypass;
    link_config->tx_interval = g_ctx->config.tx_interval;
    link_config->rx_interval = g_ctx->config.rx_interval;
    link_config->tx_threads = g_ctx->config.tx_threads;
    link_config->rx_threads = g_ctx->config.rx_threads;
    link_config->next = g_ctx->config.link_config;
    g_ctx->config.link_config = link_config;
}

static bool
json_parse_link(json_t *link, bbl_link_config_s *link_config)
{
    json_t *value, *sub = NULL;
    char *s = NULL;
    int i, size;

    if(json_unpack(link, "{s:s}", "interface", &s) == 0) {
        if(link_present(s) || lag_present(s)) {
            fprintf(stderr, "JSON config error: Duplicate link configuration for %s\n", s);
            return false;
        }
        link_config->interface = strdup(s);
    } else {
        fprintf(stderr, "JSON config error: Missing value for links->interface\n");
        return false;
    }
    
    if(json_unpack(link, "{s:s}", "description", &s) == 0) {
        link_config->description = strdup(s);
    }
    if(json_unpack(link, "{s:s}", "mac", &s) == 0) {
        if(sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &link_config->mac[0],
                &link_config->mac[1],
                &link_config->mac[2],
                &link_config->mac[3],
                &link_config->mac[4],
                &link_config->mac[5]) < 6) {
            fprintf(stderr, "JSON config error: Invalid value for links->mac\n");
            return false;
        }
    }
    if(json_unpack(link, "{s:s}", "io-mode", &s) == 0) {
        if(strcmp(s, "packet_mmap_raw") == 0) {
            link_config->io_mode = IO_MODE_PACKET_MMAP_RAW;
        } else if(strcmp(s, "packet_mmap") == 0) {
            link_config->io_mode = IO_MODE_PACKET_MMAP;
        } else if(strcmp(s, "raw") == 0) {
            link_config->io_mode = IO_MODE_RAW;
#if BNGBLASTER_DPDK
        } else if(strcmp(s, "dpdk") == 0) {
            link_config->io_mode = IO_MODE_DPDK;
            g_ctx->dpdk = true;
#endif
        } else {
            fprintf(stderr, "Config error: Invalid value for links->io-mode\n");
            return false;
        }
    } else {
        link_config->io_mode = g_ctx->config.io_mode;
    }
    value = json_object_get(link, "io-slots");
    if(json_is_number(value)) {
        link_config->io_slots_tx = json_number_value(value);
        link_config->io_slots_rx = json_number_value(value);
    } else {
        link_config->io_slots_tx = g_ctx->config.io_slots;
        link_config->io_slots_rx = g_ctx->config.io_slots;
    }
    value = json_object_get(link, "io-slots-tx");
    if(json_is_number(value)) {
        link_config->io_slots_tx = json_number_value(value);
    }
    value = json_object_get(link, "io-slots-rx");
    if(json_is_number(value)) {
        link_config->io_slots_rx = json_number_value(value);
    }
    value = json_object_get(link, "qdisc-bypass");
    if(json_is_number(value)) {
        link_config->qdisc_bypass = json_number_value(value);
    } else {
        link_config->qdisc_bypass = g_ctx->config.qdisc_bypass;
    }
    value = json_object_get(link, "tx-interval");
    if(json_is_number(value)) {
        link_config->tx_interval = json_number_value(value) * MSEC;
    } else {
        link_config->tx_interval = g_ctx->config.tx_interval;
    }
    value = json_object_get(link, "rx-interval");
    if(json_is_number(value)) {
        link_config->rx_interval = json_number_value(value) * MSEC;
    } else {
        link_config->rx_interval = g_ctx->config.rx_interval;
    }
    value = json_object_get(link, "tx-threads");
    if(value) {
        link_config->tx_threads = json_number_value(value);
    } else {
        link_config->tx_threads = g_ctx->config.tx_threads;
    }
    value = json_object_get(link, "rx-threads");
    if(value) {
        link_config->rx_threads = json_number_value(value);
    } else {
        link_config->rx_threads = g_ctx->config.rx_threads;
    }

    value = json_object_get(link, "rx-cpuset");
    if(json_is_array(value)) {
        size = json_array_size(value);
        link_config->rx_cpuset_cur = 0;
        link_config->rx_cpuset_count = size;
        link_config->rx_cpuset = calloc(size, sizeof(uint16_t));
        for(i = 0; i < size; i++) {
            sub = json_array_get(value, i);
            if(json_is_number(sub)) {
                link_config->rx_cpuset[i] = json_number_value(sub);
            } else {
                fprintf(stderr, "JSON config error: Invalid value for links->rx-cpuset\n");
                return false;
            }
        }
    } else if(json_is_number(value)) {
        link_config->rx_cpuset = calloc(1, sizeof(uint16_t));
        link_config->rx_cpuset[0] = json_number_value(value);
        link_config->rx_cpuset_count = 1;
        link_config->rx_cpuset_cur = 0;
    }

    value = json_object_get(link, "tx-cpuset");
    if(json_is_array(value)) {
        size = json_array_size(value);
        link_config->tx_cpuset_cur = 0;
        link_config->tx_cpuset_count = size;
        link_config->tx_cpuset = calloc(size, sizeof(uint16_t));
        for(i = 0; i < size; i++) {
            sub = json_array_get(value, i);
            if(json_is_number(sub)) {
                link_config->tx_cpuset[i] = json_number_value(sub);
            } else {
                fprintf(stderr, "JSON config error: Invalid value for links->tx-cpuset\n");
                return false;
            }
        }
    } else if(json_is_number(value)) {
        link_config->tx_cpuset = calloc(1, sizeof(uint16_t));
        link_config->tx_cpuset[0] = json_number_value(value);
        link_config->tx_cpuset_count = 1;
        link_config->tx_cpuset_cur = 0;
    }

    /* Link Aggregation Group (LAG) Configuration */
    if(json_unpack(link, "{s:s}", "lag-interface", &s) == 0) {
        if(!lag_present(s)) {
            fprintf(stderr, "JSON config error: Missing configuration for lag-interface %s\n", s);
            return false;
        }
        link_config->lag_interface = strdup(s);
        value = json_object_get(link, "lacp-priority");
        if(value) {
            link_config->lacp_priority = json_number_value(value);
        } else {
            link_config->lacp_priority = 32768;
        }
    }
    return true;
}

static bool
json_parse_network_interface(json_t *network_interface, bbl_network_config_s *network_config)
{
    json_t *value = NULL;
    const char *s = NULL;
    ipv4addr_t ipv4 = {0};

    if(json_unpack(network_interface, "{s:s}", "interface", &s) == 0) {
        network_config->interface = strdup(s);
        link_add(network_config->interface);
    } else {
        fprintf(stderr, "JSON config error: Missing value for network->interface\n");
        return false;
    }
    if(json_unpack(network_interface, "{s:s}", "address", &s) == 0) {
        if(!scan_ipv4_prefix(s, &network_config->ip)) {
            fprintf(stderr, "JSON config error: Invalid value for network->address\n");
            return false;
        }
    }
    if(json_unpack(network_interface, "{s:s}", "gateway", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4)) {
            fprintf(stderr, "JSON config error: Invalid value for network->gateway\n");
            return false;
        }
        network_config->gateway = ipv4;
    }
    if(json_unpack(network_interface, "{s:s}", "address-ipv6", &s) == 0) {
        if(!scan_ipv6_prefix(s, &network_config->ip6)) {
            fprintf(stderr, "JSON config error: Invalid value for network->address-ipv6\n");
            return false;
        }
    }
    if(json_unpack(network_interface, "{s:s}", "gateway-ipv6", &s) == 0) {
        if(!inet_pton(AF_INET6, s, &network_config->gateway6)) {
            fprintf(stderr, "JSON config error: Invalid value for network->gateway-ipv6\n");
            return false;
        }
    }
    if(json_unpack(network_interface, "{s:s}", "gateway-mac", &s) == 0) {
        if(sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &network_config->gateway_mac[0],
                &network_config->gateway_mac[1],
                &network_config->gateway_mac[2],
                &network_config->gateway_mac[3],
                &network_config->gateway_mac[4],
                &network_config->gateway_mac[5]) < 6)
        {
            fprintf(stderr, "JSON config error: Invalid value for network->gateway-mac\n");
            return false;
        }
    }
    value = json_object_get(network_interface, "vlan");
    if(json_is_number(value)) {
        network_config->vlan = json_number_value(value);
        network_config->vlan &= 4095;
    }

    value = json_object_get(network_interface, "mtu");
    if(json_is_number(value)) {
        network_config->mtu = json_number_value(value);
    } else {
        network_config->mtu = 1500;
    }

    if(network_config->mtu < 64 || network_config->mtu > 9000) {
        fprintf(stderr, "JSON config error: Invalid value for network->mtu\n");
        return false;
    }

    value = json_object_get(network_interface, "gateway-resolve-wait");
    if(json_is_boolean(value)) {
        network_config->gateway_resolve_wait = json_boolean_value(value);
    } else {
        network_config->gateway_resolve_wait = true;
    }

    /* IS-IS interface configuration */
    value = json_object_get(network_interface, "isis-instance-id");
    if(json_is_number(value)) {
        network_config->isis_instance_id = json_number_value(value);
        network_config->isis_level = 3;
        value = json_object_get(network_interface, "isis-level");
        if(json_is_number(value)) {
            network_config->isis_level = json_number_value(value);
            if(network_config->isis_level == 0 || 
               network_config->isis_level > 3) {
                fprintf(stderr, "JSON config error: Invalid value for network->isis-level (1-3)\n");
            }
        }
        network_config->isis_p2p = true;
        value = json_object_get(network_interface, "isis-p2p");
        if(json_is_boolean(value)) {
            network_config->isis_p2p = json_boolean_value(value);
        }
        value = json_object_get(network_interface, "isis-l1-metric");
        if(json_is_number(value)) {
            network_config->isis_l1_metric = json_number_value(value);
        } else {
            network_config->isis_l1_metric = 10;
        }
        value = json_object_get(network_interface, "isis-l2-metric");
        if(json_is_number(value)) {
            network_config->isis_l2_metric = json_number_value(value);
        } else {
            network_config->isis_l2_metric = 10;
        }
    }

    /* LDP interface configuration */
    value = json_object_get(network_interface, "ldp-instance-id");
    if(json_is_number(value)) {
        network_config->ldp_instance_id = json_number_value(value);
    }

    return true;
}

static bool
json_parse_access_interface(json_t *access_interface, bbl_access_config_s *access_config)
{
    json_t *value = NULL;
    const char *s = NULL;
    uint32_t ipv4;
    double number;

    access_config->ipv4_enable = true;
    access_config->ipv6_enable = true;

    if(json_unpack(access_interface, "{s:s}", "interface", &s) == 0) {
        access_config->interface = strdup(s);
        link_add(access_config->interface);
    } else {
        fprintf(stderr, "JSON config error: Missing value for interface->interface\n");
        return false;
    }
    if(json_unpack(access_interface, "{s:s}", "network-interface", &s) == 0) {
        access_config->network_interface = strdup(s);
    }
    if(json_unpack(access_interface, "{s:s}", "a10nsp-interface", &s) == 0) {
        if(access_config->network_interface) {
            fprintf(stderr, "JSON config error: You can't define access->network-interface and access->a10nsp-interface\n");
            return false;
        }
        access_config->a10nsp_interface = strdup(s);
    }

    value = json_object_get(access_interface, "i1-start");
    if(value) {
        access_config->i1 = json_number_value(value);
    } else {
        access_config->i1 = 1;
    }
    value = json_object_get(access_interface, "i1-step");
    if(value) {
        access_config->i1_step = json_number_value(value);
    } else {
        access_config->i1_step = 1;
    }
    value = json_object_get(access_interface, "i2-start");
    if(value) {
        access_config->i2 = json_number_value(value);
    } else {
        access_config->i2 = 1;
    }
    value = json_object_get(access_interface, "i2-step");
    if(value) {
        access_config->i2_step = json_number_value(value);
    } else {
        access_config->i2_step = 1;
    }

    if(json_unpack(access_interface, "{s:s}", "type", &s) == 0) {
        if(strcmp(s, "pppoe") == 0) {
            access_config->access_type = ACCESS_TYPE_PPPOE;
        } else if(strcmp(s, "ipoe") == 0) {
            access_config->access_type = ACCESS_TYPE_IPOE;
            access_config->ipv4_enable = g_ctx->config.ipoe_ipv4_enable;
            access_config->ipv6_enable = g_ctx->config.ipoe_ipv6_enable;
        } else {
            fprintf(stderr, "JSON config error: Invalid value for access->type\n");
            return false;
        }
    }

    if(json_unpack(access_interface, "{s:s}", "vlan-mode", &s) == 0) {
        if(strcmp(s, "1:1") == 0) {
            access_config->vlan_mode = VLAN_MODE_11;
        } else if(strcmp(s, "N:1") == 0) {
            access_config->vlan_mode = VLAN_MODE_N1;
        } else {
            fprintf(stderr, "JSON config error: Invalid value for access->vlan-mode\n");
            return false;
        }
    }

    value = json_object_get(access_interface, "monkey");
    if(json_is_boolean(value)) {
        access_config->monkey = json_boolean_value(value);
    }

    value = json_object_get(access_interface, "qinq");
    if(json_is_boolean(value)) {
        access_config->qinq = json_boolean_value(value);
    }
    value = json_object_get(access_interface, "outer-vlan");
    if(json_is_number(value)) {
        access_config->access_outer_vlan_min = json_number_value(value);
        access_config->access_outer_vlan_min &= 4095;
        access_config->access_outer_vlan_max = access_config->access_outer_vlan_min;
    } else {
        value = json_object_get(access_interface, "outer-vlan-min");
        if(json_is_number(value)) {
            access_config->access_outer_vlan_min = json_number_value(value);
            access_config->access_outer_vlan_min &= 4095;
        }
        value = json_object_get(access_interface, "outer-vlan-max");
        if(value) {
            access_config->access_outer_vlan_max = json_number_value(value);
            access_config->access_outer_vlan_max &= 4095;
        }
        value = json_object_get(access_interface, "outer-vlan-step");
        if(value) {
            access_config->access_outer_vlan_step = json_number_value(value);
        } else {
            access_config->access_outer_vlan_step = 1;
        }
    }
    value = json_object_get(access_interface, "inner-vlan");
    if(json_is_number(value)) {
        access_config->access_inner_vlan_min = json_number_value(value);
        access_config->access_inner_vlan_min &= 4095;
        access_config->access_inner_vlan_max = access_config->access_inner_vlan_min;
    } else {
        value = json_object_get(access_interface, "inner-vlan-min");
        if(value) {
            access_config->access_inner_vlan_min = json_number_value(value);
            access_config->access_inner_vlan_min &= 4095;
        }
        value = json_object_get(access_interface, "inner-vlan-max");
        if(value) {
            access_config->access_inner_vlan_max = json_number_value(value);
            access_config->access_inner_vlan_max &= 4095;
        }
        value = json_object_get(access_interface, "inner-vlan-step");
        if(value) {
            access_config->access_inner_vlan_step = json_number_value(value);
        } else {
            access_config->access_inner_vlan_step = 1;
        }
    }
    if(access_config->access_outer_vlan_min > access_config->access_outer_vlan_max ||
       access_config->access_inner_vlan_min > access_config->access_inner_vlan_max) {
        fprintf(stderr, "JSON config error: Invalid value for access VLAN range (min > max)\n");
        return false;
    }
    value = json_object_get(access_interface, "third-vlan");
    if(value) {
        access_config->access_third_vlan = json_number_value(value);
        access_config->access_third_vlan &= 4095;
    }

    value = json_object_get(access_interface, "ppp-mru");
    if(value) {
        access_config->ppp_mru = json_number_value(value);
    } else {
        access_config->ppp_mru = g_ctx->config.ppp_mru;
    }

    if(json_unpack(access_interface, "{s:s}", "address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4)) {
            fprintf(stderr, "JSON config error: Invalid value for access->address\n");
            return false;
        }
        access_config->static_ip = ipv4;
    }
    if(json_unpack(access_interface, "{s:s}", "address-iter", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4)) {
            fprintf(stderr, "JSON config error: Invalid value for access->address-iter\n");
            return false;
        }
        access_config->static_ip_iter = ipv4;
    }
    if(json_unpack(access_interface, "{s:s}", "gateway", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4)) {
            fprintf(stderr, "JSON config error: Invalid value for access->gateway\n");
            return false;
        }
        access_config->static_gateway = ipv4;
    }
    if(json_unpack(access_interface, "{s:s}", "gateway-iter", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ipv4)) {
            fprintf(stderr, "JSON config error: Invalid value for access->gateway-iter\n");
            return false;
        }
        access_config->static_gateway_iter = ipv4;
    }

    /* Optionally overload some settings per range */
    if(json_unpack(access_interface, "{s:s}", "username", &s) == 0) {
        access_config->username = strdup(s);
    } else {
        access_config->username = strdup(g_ctx->config.username);
    }

    if(json_unpack(access_interface, "{s:s}", "password", &s) == 0) {
        access_config->password = strdup(s);
    } else {
        access_config->password = strdup(g_ctx->config.password);
    }

    if(json_unpack(access_interface, "{s:s}", "authentication-protocol", &s) == 0) {
        if(strcmp(s, "PAP") == 0) {
            access_config->authentication_protocol = PROTOCOL_PAP;
        } else if(strcmp(s, "CHAP") == 0) {
            access_config->authentication_protocol = PROTOCOL_CHAP;
        } else {
            fprintf(stderr, "Config error: Invalid value for access->authentication-protocol\n");
            return false;
        }
    } else {
        access_config->authentication_protocol = g_ctx->config.authentication_protocol;
    }

    /* Access Line */
    if(json_unpack(access_interface, "{s:s}", "agent-circuit-id", &s) == 0) {
        access_config->agent_circuit_id = strdup(s);
    } else {
        if(g_ctx->config.agent_circuit_id) {
            access_config->agent_circuit_id = strdup(g_ctx->config.agent_circuit_id);
        }
    }

    if(json_unpack(access_interface, "{s:s}", "agent-remote-id", &s) == 0) {
        access_config->agent_remote_id = strdup(s);
    } else {
        if(g_ctx->config.agent_remote_id) {
            access_config->agent_remote_id = strdup(g_ctx->config.agent_remote_id);
        }
    }

    value = json_object_get(access_interface, "rate-up");
    if(value) {
        access_config->rate_up = json_number_value(value);
    } else {
        access_config->rate_up = g_ctx->config.rate_up;
    }

    value = json_object_get(access_interface, "rate-down");
    if(value) {
        access_config->rate_down = json_number_value(value);
    } else {
        access_config->rate_down = g_ctx->config.rate_down;
    }

    value = json_object_get(access_interface, "dsl-type");
    if(value) {
        access_config->dsl_type = json_number_value(value);
    } else {
        access_config->dsl_type = g_ctx->config.dsl_type;
    }

    value = json_object_get(access_interface, "access-line-profile-id");
    if(value) {
        access_config->access_line_profile_id = json_number_value(value);
    }

    /* IPv4 settings */
    value = json_object_get(access_interface, "ipcp");
    if(json_is_boolean(value)) {
        access_config->ipcp_enable = json_boolean_value(value);
    } else {
        access_config->ipcp_enable = g_ctx->config.ipcp_enable;
    }
    value = json_object_get(access_interface, "dhcp");
    if(json_is_boolean(value)) {
        access_config->dhcp_enable = json_boolean_value(value);
    } else {
        access_config->dhcp_enable = g_ctx->config.dhcp_enable;
    }
    value = json_object_get(access_interface, "ipv4");
    if(json_is_boolean(value)) {
        access_config->ipv4_enable = json_boolean_value(value);
    }

    /* IPv6 settings */
    value = json_object_get(access_interface, "ip6cp");
    if(json_is_boolean(value)) {
        access_config->ip6cp_enable = json_boolean_value(value);
    } else {
        access_config->ip6cp_enable = g_ctx->config.ip6cp_enable;
    }
    value = json_object_get(access_interface, "dhcpv6");
    if(json_is_boolean(value)) {
        access_config->dhcpv6_enable = json_boolean_value(value);
    } else {
        access_config->dhcpv6_enable = g_ctx->config.dhcpv6_enable;
    }
    value = json_object_get(access_interface, "ipv6");
    if(json_is_boolean(value)) {
        access_config->ipv6_enable = json_boolean_value(value);
    }

    value = json_object_get(access_interface, "igmp-autostart");
    if(json_is_boolean(value)) {
        access_config->igmp_autostart = json_boolean_value(value);
    } else {
        access_config->igmp_autostart = g_ctx->config.igmp_autostart;
    }
    value = json_object_get(access_interface, "igmp-version");
    if(json_is_number(value)) {
        access_config->igmp_version = json_number_value(value);
        if(access_config->igmp_version < 1 || access_config->igmp_version > 3) {
            fprintf(stderr, "JSON config error: Invalid value for access->igmp-version\n");
            return false;
        }
    } else {
        access_config->igmp_version = g_ctx->config.igmp_version;
    }
    value = json_object_get(access_interface, "session-traffic-autostart");
    if(json_is_boolean(value)) {
        access_config->session_traffic_autostart = json_boolean_value(value);
    } else {
        access_config->session_traffic_autostart = g_ctx->config.session_traffic_autostart;
    }

    value = json_object_get(access_interface, "stream-group-id");
    if(value) {
        number = json_number_value(value);
        if(number >= UINT16_MAX) {
            fprintf(stderr, "JSON config error: Invalid value for access->stream-group-id\n");
        }
        access_config->stream_group_id = number;
    }

    value = json_object_get(access_interface, "cfm-cc");
    if(json_is_boolean(value)) {
        access_config->cfm_cc = json_boolean_value(value);
    }
    value = json_object_get(access_interface, "cfm-level");
    if(value) {
        access_config->cfm_level = json_number_value(value);
        if(access_config->cfm_level > 7) {
            fprintf(stderr, "JSON config error: Invalid value for access->cfm-level\n");
            return false;
        }
    }
    value = json_object_get(access_interface, "cfm-ma-id");
    if(value) {
        access_config->cfm_ma_id = json_number_value(value);
    }
    if(json_unpack(access_interface, "{s:s}", "cfm-ma-name", &s) == 0) {
        access_config->cfm_ma_name = strdup(s);
    } else if(access_config->cfm_cc) {
        fprintf(stderr, "JSON config error: Missing access->cfm-ma-name\n");
        return false;
    }

    if(access_config->access_type == ACCESS_TYPE_PPPOE) {
        /* Disable IPv4 on PPPoE if IPCP is disabled. */
        if(!access_config->ipcp_enable) {
            access_config->ipv4_enable = false;
        }
        /* Disable IPv6 on PPPoE if IP6CP is disabled. */
        if(!access_config->ip6cp_enable) {
            access_config->ipv6_enable = false;
            access_config->dhcpv6_enable = false;
        }
    } else {
        /* Disable IPv4 on IPoE if neither DHCP is enabled or
         * a static IPv4 address is configured. */
        if(!(access_config->dhcp_enable ||
            (access_config->static_ip && access_config->static_gateway))) {
            access_config->ipv4_enable = false;
        }
    }

    return true;
}

static bool
json_parse_a10nsp_interface(json_t *a10nsp_interface, bbl_a10nsp_config_s *a10nsp_config)
{
    const char *s = NULL;
    json_t *value = NULL;

    if(json_unpack(a10nsp_interface, "{s:s}", "interface", &s) == 0) {
        a10nsp_config->interface = strdup(s);
        link_add(a10nsp_config->interface);
    } else {
        fprintf(stderr, "JSON config error: Missing value for a10nsp->interface\n");
        return false;
    }

    value = json_object_get(a10nsp_interface, "qinq");
    if(json_is_boolean(value)) {
        a10nsp_config->qinq = json_boolean_value(value);
    }

    if(json_unpack(a10nsp_interface, "{s:s}", "mac", &s) == 0) {
        if(sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &a10nsp_config->mac[0],
                &a10nsp_config->mac[1],
                &a10nsp_config->mac[2],
                &a10nsp_config->mac[3],
                &a10nsp_config->mac[4],
                &a10nsp_config->mac[5]) < 6)
        {
            fprintf(stderr, "JSON config error: Invalid value for a10nsp->mac\n");
            return false;
        }
    }

    return true;
}

static bool
json_parse_bgp_config(json_t *bgp, bgp_config_s *bgp_config)
{
    json_t *value = NULL;
    const char *s = NULL;    
    
    g_ctx->tcp = true;

    if(json_unpack(bgp, "{s:s}", "network-interface", &s) == 0) {
        bgp_config->network_interface = strdup(s);
    }

    if(json_unpack(bgp, "{s:s}", "local-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &bgp_config->ipv4_local_address)) {
            fprintf(stderr, "JSON config error: Invalid value for bgp->local-ipv4-address\n");
            return false;
        }
        add_secondary_ipv4(bgp_config->ipv4_local_address);
    }

    if(json_unpack(bgp, "{s:s}", "peer-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &bgp_config->ipv4_peer_address)) {
            fprintf(stderr, "JSON config error: Invalid value for bgp->peer-ipv4-address\n");
            return false;
        }
    } else {
        fprintf(stderr, "JSON config error: Missing value for bgp->peer-ipv4-address\n");
        return false;   
    }

    value = json_object_get(bgp, "local-as");
    if(value) {
        bgp_config->local_as = json_number_value(value);
    } else {
        bgp_config->local_as = BGP_DEFAULT_AS;
    }

    value = json_object_get(bgp, "peer-as");
    if(value) {
        bgp_config->peer_as = json_number_value(value);
    } else {
        bgp_config->peer_as = bgp_config->local_as;
    }

    value = json_object_get(bgp, "hold-time");
    if(value) {
        bgp_config->hold_time = json_number_value(value);
    } else {
        bgp_config->hold_time = BGP_DEFAULT_HOLD_TIME;
    }

    bgp_config->id = htobe32(0x01020304);
    if(json_unpack(bgp, "{s:s}", "id", &s) == 0) {
        if(!inet_pton(AF_INET, s, &bgp_config->id)) {
            fprintf(stderr, "JSON config error: Invalid value for bgp->id\n");
            return false;
        }
    } 

    value = json_object_get(bgp, "reconnect");
    if(json_is_boolean(value)) {
        bgp_config->reconnect = json_boolean_value(value);
    } else {
        bgp_config->reconnect = true;
    }

    value = json_object_get(bgp, "start-traffic");
    if(json_is_boolean(value)) {
        bgp_config->start_traffic = json_boolean_value(value);
    } else {
        bgp_config->start_traffic = false;
    }

    value = json_object_get(bgp, "teardown-time");
    if(json_is_number(value)) {
        bgp_config->teardown_time = json_number_value(value);
    } else {
        bgp_config->teardown_time = BGP_DEFAULT_TEARDOWN_TIME;
    }

    if(json_unpack(bgp, "{s:s}", "raw-update-file", &s) == 0) {
        bgp_config->raw_update_file = strdup(s);
        if(!bgp_raw_update_load(bgp_config->raw_update_file, true)) {
            return false;
        }
    }
    return true;
}

static bool
json_parse_isis_config(json_t *isis, isis_config_s *isis_config)
{
    json_t *sub, *con, *c, *value = NULL;
    const char *s = NULL;
    int i, size;
    
    isis_external_connection_s *connection = NULL;

    value = json_object_get(isis, "instance-id");
    if(value) {
        isis_config->id = json_number_value(value);
    } else {
        fprintf(stderr, "JSON config error: Missing value for isis->instance-id\n");
        return false;
    }

    value = json_object_get(isis, "level");
    if(json_is_number(value)) {
        isis_config->level = json_number_value(value);
    } else {
        isis_config->level = 3;
    }
    if(isis_config->level == 0 || isis_config->level > 3) {
        fprintf(stderr, "JSON config error: Invalid value for isis->level\n");
    }

    value = json_object_get(isis, "overload");
    if(json_is_boolean(value)) {
        isis_config->overload  = json_boolean_value(value);
    }

    value = json_object_get(isis, "protocol-ipv4");
    if(json_is_boolean(value)) {
        isis_config->protocol_ipv4  = json_boolean_value(value);
    } else {
        isis_config->protocol_ipv4  = true;
    }

    value = json_object_get(isis, "protocol-ipv6");
    if(json_is_boolean(value)) {
        isis_config->protocol_ipv6  = json_boolean_value(value);
    } else {
        isis_config->protocol_ipv6  = true;
    }

    if(json_unpack(isis, "{s:s}", "level1-auth-key", &s) == 0) {
        isis_config->level1_key = strdup(s);
        isis_config->level1_auth = ISIS_AUTH_CLEARTEXT;
        if(json_unpack(isis, "{s:s}", "level1-auth-type", &s) == 0) {
            if(strcmp(s, "md5") == 0) {
                isis_config->level1_auth = ISIS_AUTH_HMAC_MD5;
            }
        }
    }

    if(json_unpack(isis, "{s:s}", "level2-auth-key", &s) == 0) {
        isis_config->level2_key = strdup(s);
        isis_config->level2_auth = ISIS_AUTH_CLEARTEXT;
        if(json_unpack(isis, "{s:s}", "level2-auth-type", &s) == 0) {
            if(strcmp(s, "md5") == 0) {
                isis_config->level2_auth = ISIS_AUTH_HMAC_MD5;
            }
        }
    }

    value = json_object_get(isis, "hello-interval");
    if(json_is_number(value)) {
        isis_config->hello_interval = json_number_value(value);
    } else {
        isis_config->hello_interval = ISIS_DEFAULT_HELLO_INTERVAL;
    }

    value = json_object_get(isis, "hello-padding");
    if(json_is_boolean(value)) {
        isis_config->hello_padding  = json_boolean_value(value);
    }

    value = json_object_get(isis, "hold-time");
    if(json_is_number(value)) {
        isis_config->hold_time = json_number_value(value);
    } else {
        isis_config->hold_time = ISIS_DEFAULT_HOLD_TIME;
    }

    value = json_object_get(isis, "lsp-lifetime");
    if(json_is_number(value)) {
        isis_config->lsp_lifetime = json_number_value(value);
    } else {
        isis_config->lsp_lifetime = ISIS_DEFAULT_LSP_LIFETIME;
    }

    value = json_object_get(isis, "lsp-refresh-interval");
    if(json_is_number(value)) {
        isis_config->lsp_refresh_interval = json_number_value(value);
    } else {
        isis_config->lsp_refresh_interval = ISIS_DEFAULT_LSP_REFRESH_IVL;
    }

    value = json_object_get(isis, "lsp-retry-interval");
    if(json_is_number(value)) {
        isis_config->lsp_retry_interval = json_number_value(value);
    } else {
        isis_config->lsp_retry_interval = ISIS_DEFAULT_LSP_RETRY_IVL;
    }

    value = json_object_get(isis, "lsp-tx-interval");
    if(json_is_number(value)) {
        isis_config->lsp_tx_interval = json_number_value(value);
    } else {
        isis_config->lsp_tx_interval = ISIS_DEFAULT_LSP_TX_IVL_MS;
    }

    value = json_object_get(isis, "lsp-tx-window-size");
    if(json_is_number(value)) {
        isis_config->lsp_tx_window_size = json_number_value(value);
    } else {
        isis_config->lsp_tx_window_size = ISIS_DEFAULT_LSP_WINDOWS_SIZE;
    }

    value = json_object_get(isis, "csnp-interval");
    if(json_is_number(value)) {
        isis_config->csnp_interval = json_number_value(value);
    } else {
        isis_config->csnp_interval = ISIS_DEFAULT_CSNP_INTERVAL;
    }

    if(json_unpack(isis, "{s:s}", "hostname", &s) == 0) {
        isis_config->hostname = strdup(s);
    } else {
        isis_config->hostname = g_default_hostname;
    }

    if(json_unpack(isis, "{s:s}", "router-id", &s) == 0) {
        isis_config->router_id_str = strdup(s);
    } else {
        isis_config->router_id_str = g_default_router_id;
    }
    if(!inet_pton(AF_INET, isis_config->router_id_str, &isis_config->router_id)) {
        fprintf(stderr, "JSON config error: Invalid value for isis->router-id\n");
        return false;
    }

    if(json_unpack(isis, "{s:s}", "system-id", &s) == 0) {
        isis_config->system_id_str = strdup(s);
    } else {
        isis_config->system_id_str = g_default_system_id;
    }
    if(!isis_str_to_system_id(isis_config->system_id_str, isis_config->system_id)) {
        fprintf(stderr, "JSON config error: Invalid value for isis->system-id\n");
        return false;
    }

    value = json_object_get(isis, "area");
    if(json_is_array(value)) {
        isis_config->area_count = json_array_size(value);
        isis_config->area = calloc(isis_config->area_count, sizeof(isis_area_s));
        for(i = 0; i < isis_config->area_count; i++) {
            if(!isis_str_to_area(json_string_value(json_array_get(value, i)), &isis_config->area[i])) {
                fprintf(stderr, "JSON config error: Invalid value for isis->area\n");
                return false;
            }
        }
    } else if(json_is_string(value)) {
        isis_config->area = calloc(1, sizeof(isis_area_s));
        isis_config->area_count = 1;
        if(!isis_str_to_area(json_string_value(value), isis_config->area)) {
            fprintf(stderr, "JSON config error: Invalid value for isis->area\n");
            return false;
        }
    } else {
        isis_config->area = calloc(1, sizeof(isis_area_s));
        isis_config->area_count = 1;
        if(!isis_str_to_area(g_default_area, isis_config->area)) {
            fprintf(stderr, "JSON config error: Invalid value for isis->area\n");
            return false;
        }
    }

    value = json_object_get(isis, "sr-base");
    if(json_is_number(value)) {
        isis_config->sr_base = json_number_value(value);
    }

    value = json_object_get(isis, "sr-range");
    if(json_is_number(value)) {
        isis_config->sr_range = json_number_value(value);
    }

    value = json_object_get(isis, "sr-node-sid");
    if(json_is_number(value)) {
        isis_config->sr_node_sid = json_number_value(value);
    }

    value = json_object_get(isis, "teardown-time");
    if(json_is_number(value)) {
        isis_config->teardown_time = json_number_value(value);
    } else {
        isis_config->teardown_time = ISIS_DEFAULT_TEARDOWN_TIME;
    }

    sub = json_object_get(isis, "external");
    if(json_is_object(sub)) {
        if(json_unpack(sub, "{s:s}", "mrt-file", &s) == 0) {
            isis_config->external_mrt_file = strdup(s);
        }
        con = json_object_get(sub, "connections");
        if(json_is_array(con)) {
            size = json_array_size(con);
            for(i = 0; i < size; i++) {
                if(connection) {
                    connection->next = calloc(1, sizeof(isis_external_connection_s));
                    connection = connection->next;
                } else {
                    connection = calloc(1, sizeof(isis_external_connection_s));
                    isis_config->external_connection = connection;
                }
                c = json_array_get(con, i);
                if(json_unpack(c, "{s:s}", "system-id", &s) == 0) {
                    if(!isis_str_to_system_id(s, connection->system_id)) {
                        fprintf(stderr, "JSON config error: Invalid value for isis->external->connections->system-id\n");
                        return false;
                    }
                } else {
                    fprintf(stderr, "JSON config error: Missing value for isis->external->connections->system-id\n");
                    return false;
                }
                value = json_object_get(c, "l1-metric");
                if(json_is_number(value)) {
                    connection->level[ISIS_LEVEL_1_IDX].metric = json_number_value(value);
                } else {
                    connection->level[ISIS_LEVEL_1_IDX].metric = 10;
                }
                value = json_object_get(c, "l2-metric");
                if(json_is_number(value)) {
                    connection->level[ISIS_LEVEL_2_IDX].metric = json_number_value(value);
                } else {
                    connection->level[ISIS_LEVEL_2_IDX].metric = 10;
                }
            }
        }
    }
    return true;
}

static bool
json_parse_ldp_config(json_t *ldp, ldp_config_s *ldp_config)
{
    json_t *value = NULL;
    const char *s = NULL;
    
    g_ctx->tcp = true;

    value = json_object_get(ldp, "instance-id");
    if(value) {
        ldp_config->id = json_number_value(value);
    } else {
        fprintf(stderr, "JSON config error: Missing value for ldp->instance-id\n");
        return false;
    }

    value = json_object_get(ldp, "keepalive-time");
    if(json_is_number(value)) {
        ldp_config->keepalive_time = json_number_value(value);
    } else {
        ldp_config->keepalive_time = LDP_DEFAULT_KEEPALIVE_TIME;
    }

    value = json_object_get(ldp, "hold-time");
    if(json_is_number(value)) {
        ldp_config->hold_time = json_number_value(value);
    } else {
        ldp_config->hold_time = LDP_DEFAULT_HOLD_TIME;
    }

    value = json_object_get(ldp, "teardown-time");
    if(json_is_number(value)) {
        ldp_config->teardown_time = json_number_value(value);
    } else {
        ldp_config->teardown_time = LDP_DEFAULT_TEARDOWN_TIME;
    }

    if(json_unpack(ldp, "{s:s}", "hostname", &s) == 0) {
        ldp_config->hostname = strdup(s);
    } else {
        ldp_config->hostname = g_default_hostname;
    }

    if(json_unpack(ldp, "{s:s}", "lsr-id", &s) == 0) {
        ldp_config->lsr_id_str = strdup(s);
    } else {
        ldp_config->lsr_id_str = g_default_router_id;
    }
    if(!inet_pton(AF_INET, ldp_config->lsr_id_str, &ldp_config->lsr_id)) {
        fprintf(stderr, "JSON config error: Invalid value for ldp->lsr-id\n");
        return false;
    }
    if(json_unpack(ldp, "{s:s}", "ipv4-transport-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &ldp_config->ipv4_transport_address)) {
            fprintf(stderr, "JSON config error: Invalid value for ldp->ipv4-transport-address\n");
            return false;
        }
    } else {
        ldp_config->ipv4_transport_address = ldp_config->lsr_id;
    }

    if(json_unpack(ldp, "{s:s}", "raw-update-file", &s) == 0) {
        ldp_config->raw_update_file = strdup(s);
        if(!ldp_raw_update_load(ldp_config->raw_update_file, true)) {
            return false;
        }
    }
    return true;
}

static bool
json_parse_stream(json_t *stream, bbl_stream_config_s *stream_config)
{
    json_t *value = NULL;
    const char *s = NULL;
    double bps;
    double number;

    if(json_unpack(stream, "{s:s}", "name", &s) == 0) {
        stream_config->name = strdup(s);
    } else {
        fprintf(stderr, "JSON config error: Missing value for stream->name\n");
        return false;
    }

    value = json_object_get(stream, "stream-group-id");
    if(value) {
        number = json_number_value(value);
        if(number >= UINT16_MAX) {
            fprintf(stderr, "JSON config error: Invalid value for stream->stream-group-id\n");
        }
        stream_config->stream_group_id = number;
    }

    if(json_unpack(stream, "{s:s}", "type", &s) == 0) {
        if(strcmp(s, "ipv4") == 0) {
            stream_config->type = BBL_SUB_TYPE_IPV4;
        } else if(strcmp(s, "ipv6") == 0) {
            stream_config->type = BBL_SUB_TYPE_IPV6;
        } else if(strcmp(s, "ipv6pd") == 0) {
            stream_config->type = BBL_SUB_TYPE_IPV6PD;
        } else {
            fprintf(stderr, "JSON config error: Invalid value for stream->type\n");
            return false;
        }
    } else {
        fprintf(stderr, "JSON config error: Missing value for stream->type\n");
        return false;
    }

    if(json_unpack(stream, "{s:s}", "direction", &s) == 0) {
        if(strcmp(s, "upstream") == 0) {
            stream_config->direction = BBL_DIRECTION_UP;
        } else if(strcmp(s, "downstream") == 0) {
            stream_config->direction = BBL_DIRECTION_DOWN;
        } else if(strcmp(s, "both") == 0) {
            stream_config->direction = BBL_DIRECTION_BOTH;
        } else {
            fprintf(stderr, "JSON config error: Invalid value for stream->direction\n");
            return false;
        }
    } else {
        if(stream_config->stream_group_id) {
            stream_config->direction = BBL_DIRECTION_BOTH;
        } else {
            stream_config->direction = BBL_DIRECTION_DOWN;
        }
    }

    if(stream_config->stream_group_id == 0 && 
       stream_config->direction != BBL_DIRECTION_DOWN) {
        fprintf(stderr, "JSON config error: Invalid value for stream->direction (must be downstream for RAW streams)\n");
        return false;
    }

    if(json_unpack(stream, "{s:s}", "network-interface", &s) == 0) {
        stream_config->network_interface = strdup(s);
    }
    if(json_unpack(stream, "{s:s}", "a10nsp-interface", &s) == 0) {
        stream_config->a10nsp_interface = strdup(s);
    }
    if(stream_config->network_interface && stream_config->a10nsp_interface) {
        fprintf(stderr, "JSON config error: Not allowed to set stream->network-interface and stream->a10nsp-interface\n");
        return false;
    }

    value = json_object_get(stream, "source-port");
    if(value) {
        stream_config->src_port = json_number_value(value);
    } else {
        stream_config->src_port = BBL_UDP_PORT;
    }

    value = json_object_get(stream, "destination-port");
    if(value) {
        stream_config->dst_port = json_number_value(value);
    } else {
        stream_config->dst_port = BBL_UDP_PORT;
    }

    value = json_object_get(stream, "length");
    if(value) {
        stream_config->length = json_number_value(value);
        if(stream_config->length < 76 || stream_config->length > 9000) {
            fprintf(stderr, "JSON config error: Invalid value for stream->length\n");
            return false;
        }
    } else {
        stream_config->length = 128;
    }

    value = json_object_get(stream, "priority");
    if(value) {
        stream_config->priority = json_number_value(value);
    }

    value = json_object_get(stream, "vlan-priority");
    if(value) {
        stream_config->vlan_priority = json_number_value(value);
    }

    value = json_object_get(stream, "pps");
    if(value) {
        stream_config->pps = json_number_value(value);
        if(stream_config->pps <= 0) {
            fprintf(stderr, "JSON config error: Invalid value for stream->pps\n");
            return false;
        }
    } else {
        /* pps config has priority over bps */
        value = json_object_get(stream, "bps");
        if(value) {
            bps = json_number_value(value);
            if(!bps) {
                fprintf(stderr, "JSON config error: Invalid value for stream->bps\n");
                return false;
            }
            stream_config->pps = bps / (stream_config->length * 8);
        }
    }
    if(!stream_config->pps) stream_config->pps = 1;

    value = json_object_get(stream, "max-packets");
    if(value) {
        stream_config->max_packets = json_number_value(value);
    }

    value = json_object_get(stream, "start-delay");
    if(value) {
        stream_config->start_delay = json_number_value(value);
    }

    if(json_unpack(stream, "{s:s}", "ldp-ipv4-lookup-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &stream_config->ipv4_ldp_lookup_address)) {
            fprintf(stderr, "JSON config error: Invalid value for stream->ldp-ipv4-lookup-address\n");
            return false;
        }
    }

    if(json_unpack(stream, "{s:s}", "access-ipv4-source-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &stream_config->ipv4_access_src_address)) {
            fprintf(stderr, "JSON config error: Invalid value for stream->access-ipv4-source-address\n");
            return false;
        }
    }

    if(json_unpack(stream, "{s:s}", "access-ipv6-source-address", &s) == 0) {
        if(!inet_pton(AF_INET6, s, &stream_config->ipv6_access_src_address)) {
            fprintf(stderr, "JSON config error: Invalid value for stream->access-ipv6-source-address\n");
            return false;
        }
    }

    if(json_unpack(stream, "{s:s}", "network-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &stream_config->ipv4_network_address)) {
            fprintf(stderr, "JSON config error: Invalid value for stream->network-ipv4-address\n");
            return false;
        }
        add_secondary_ipv4(stream_config->ipv4_network_address);
    }

    if(json_unpack(stream, "{s:s}", "network-ipv6-address", &s) == 0) {
        if(!inet_pton(AF_INET6, s, &stream_config->ipv6_network_address)) {
            fprintf(stderr, "JSON config error: Invalid value for stream->network-ipv6-address\n");
            return false;
        }
        add_secondary_ipv6(stream_config->ipv6_network_address);
    }

    if(json_unpack(stream, "{s:s}", "destination-ipv4-address", &s) == 0) {
        if(!inet_pton(AF_INET, s, &stream_config->ipv4_destination_address)) {
            fprintf(stderr, "JSON config error: Invalid value for stream->destination-ipv4-address\n");
            return false;
        }
    }

    if(json_unpack(stream, "{s:s}", "destination-ipv6-address", &s) == 0) {
        if(!inet_pton(AF_INET6, s, &stream_config->ipv6_destination_address)) {
            fprintf(stderr, "JSON config error: Invalid value for stream->destination-ipv6-address\n");
            return false;
        }
    }

    /* Set DF bit for IPv4 traffic (default true) */
    value = json_object_get(stream, "ipv4-df");
    if(json_is_boolean(value)) {
        stream_config->ipv4_df = json_boolean_value(value);
    } else {
        stream_config->ipv4_df = true;
    }

    /* MPLS labels */
    value = json_object_get(stream, "tx-label1");
    if(value) {
        stream_config->tx_mpls1 = true;
        stream_config->tx_mpls1_label = json_number_value(value);
    }
    value = json_object_get(stream, "tx-label1-exp");
    if(value) {
        stream_config->tx_mpls1_exp = json_number_value(value);
    }
    value = json_object_get(stream, "tx-label1-ttl");
    if(value) {
        stream_config->tx_mpls1_ttl = json_number_value(value);
    } else {
        stream_config->tx_mpls1_ttl = 255;
    }
    value = json_object_get(stream, "tx-label2");
    if(value) {
        stream_config->tx_mpls2 = true;
        stream_config->tx_mpls2_label = json_number_value(value);
    }
    value = json_object_get(stream, "tx-label2-exp");
    if(value) {
        stream_config->tx_mpls2_exp = json_number_value(value);
    }
    value = json_object_get(stream, "tx-label2-ttl");
    if(value) {
        stream_config->tx_mpls2_ttl = json_number_value(value);
    } else {
        stream_config->tx_mpls2_ttl = 255;
    }

    value = json_object_get(stream, "rx-label1");
    if(value) {
        stream_config->rx_mpls1 = true;
        stream_config->rx_mpls1_label = json_number_value(value);
    }
    value = json_object_get(stream, "rx-label2");
    if(value) {
        stream_config->rx_mpls2 = true;
        stream_config->rx_mpls2_label = json_number_value(value);
    }

    /* Validate configuration */
    if(stream_config->stream_group_id == 0) {
        /* RAW stream */
        if(stream_config->type == BBL_SUB_TYPE_IPV4) {
            if(!stream_config->ipv4_destination_address) {
                fprintf(stderr, "JSON config error: Missing destination-ipv4-address for RAW stream %s\n", stream_config->name);
                return false;
            }
        }
        if(stream_config->type == BBL_SUB_TYPE_IPV6) {
            if(!*(uint64_t*)stream_config->ipv6_destination_address) {
                fprintf(stderr, "JSON config error: Missing destination-ipv6-address for RAW stream %s\n", stream_config->name);
                return false;
            }
        }
        if(stream_config->type == BBL_SUB_TYPE_IPV6PD) {
            fprintf(stderr, "JSON config error: Invalid type for RAW stream %s\n", stream_config->name);
            return false;
        }
        if(stream_config->direction != BBL_DIRECTION_DOWN) {
            fprintf(stderr, "JSON config error: Invalid direction for RAW stream %s\n", stream_config->name);
            return false;
        }
    }
    return true;
}

static bool
json_parse_config_streams(json_t *root)
{

    json_t *section = NULL;
    int i, size;

    bbl_stream_config_s *stream_config = g_ctx->config.stream_config;

    if(json_typeof(root) != JSON_OBJECT) {
        fprintf(stderr, "JSON config error: Configuration root element must object\n");
        return false;
    }

    section = json_object_get(root, "streams");
    if(json_is_array(section)) {
        /* Get tail end of stream-config list. */
        if(stream_config) {
            while(stream_config->next) {
                stream_config = stream_config->next;
            }
        }
        /* Config is provided as array (multiple streams) */
        size = json_array_size(section);
        for(i = 0; i < size; i++) {
            if(!stream_config) {
                g_ctx->config.stream_config = calloc(1, sizeof(bbl_stream_config_s));
                stream_config = g_ctx->config.stream_config;
            } else {
                stream_config->next = calloc(1, sizeof(bbl_stream_config_s));
                stream_config = stream_config->next;
            }
            if(!json_parse_stream(json_array_get(section, i), stream_config)) {
                return false;
            }
        }
    }
    return true;
}

static bool
json_parse_config(json_t *root)
{
    json_t *section, *sub, *value = NULL;
    const char *s;
    uint32_t ipv4;
    int i, size;
    double number;

    bbl_access_line_profile_s   *access_line_profile    = NULL;
    bbl_l2tp_server_s           *l2tp_server            = NULL;

    bbl_lag_config_s            *lag_config             = NULL;
    bbl_link_config_s           *link_config            = NULL;
    bbl_network_config_s        *network_config         = NULL;
    bbl_access_config_s         *access_config          = NULL;
    bbl_a10nsp_config_s         *a10nsp_config          = NULL;

    bgp_config_s                *bgp_config             = NULL;
    isis_config_s               *isis_config            = NULL;
    ldp_config_s                *ldp_config             = NULL;

    if(json_typeof(root) != JSON_OBJECT) {
        fprintf(stderr, "JSON config error: Configuration root element must object\n");
        return false;
    }

    /* Sessions Configuration */
    section = json_object_get(root, "sessions");
    if(json_is_object(section)) {
        value = json_object_get(section, "count");
        if(json_is_number(value)) {
            g_ctx->config.sessions = json_number_value(value);
        }
        value = json_object_get(section, "max-outstanding");
        if(json_is_number(value)) {
            g_ctx->config.sessions_max_outstanding = json_number_value(value);
        }
        value = json_object_get(section, "start-rate");
        if(json_is_number(value)) {
            g_ctx->config.sessions_start_rate = json_number_value(value);
        }
        value = json_object_get(section, "stop-rate");
        if(json_is_number(value)) {
            g_ctx->config.sessions_stop_rate = json_number_value(value);
        }
        value = json_object_get(section, "iterate-vlan-outer");
        if(json_is_boolean(value)) {
            g_ctx->config.iterate_outer_vlan = json_boolean_value(value);
        }
        value = json_object_get(section, "start-delay");
        if(json_is_number(value)) {
            g_ctx->config.sessions_start_delay = json_number_value(value);
        }
        value = json_object_get(section, "autostart");
        if(json_is_boolean(value)) {
            g_ctx->config.sessions_autostart = json_boolean_value(value);
        }
        value = json_object_get(section, "reconnect");
        if(json_is_boolean(value)) {
            g_ctx->config.sessions_reconnect = json_boolean_value(value);
        }
        value = json_object_get(section, "monkey-autostart");
        if(json_is_boolean(value)) {
            g_ctx->config.monkey_autostart = json_boolean_value(value);
        }
    }

    /* IPoE Configuration */
    section = json_object_get(root, "ipoe");
    if(json_is_object(section)) {
        value = json_object_get(section, "ipv6");
        if(json_is_boolean(value)) {
            g_ctx->config.ipoe_ipv6_enable = json_boolean_value(value);
        }
        value = json_object_get(section, "ipv4");
        if(json_is_boolean(value)) {
            g_ctx->config.ipoe_ipv4_enable = json_boolean_value(value);
        }
        value = json_object_get(section, "arp-timeout");
        if(json_is_number(value)) {
            g_ctx->config.arp_timeout = json_number_value(value);
        }
        value = json_object_get(section, "arp-interval");
        if(json_is_number(value)) {
            g_ctx->config.arp_interval = json_number_value(value);
        }
    }

    /* PPPoE Configuration */
    section = json_object_get(root, "pppoe");
    if(json_is_object(section)) {
        /* Deprecated ...
         * PPPoE sessions, max-outstanding, start
         * and stop rate was moved to section session
         * as all those values apply to PPPoE and IPoE
         * but for compatibility they are still supported
         * here as well for some time.
         */
        value = json_object_get(section, "sessions");
        if(json_is_number(value)) {
            g_ctx->config.sessions = json_number_value(value);
        }
        value = json_object_get(section, "max-outstanding");
        if(json_is_number(value)) {
            g_ctx->config.sessions_max_outstanding = json_number_value(value);
        }
        value = json_object_get(section, "start-rate");
        if(json_is_number(value)) {
            g_ctx->config.sessions_start_rate = json_number_value(value);
        }
        value = json_object_get(section, "stop-rate");
        if(json_is_number(value)) {
            g_ctx->config.sessions_stop_rate = json_number_value(value);
        }
        /* ... Deprecated */
        value = json_object_get(section, "session-time");
        if(json_is_number(value)) {
            g_ctx->config.pppoe_session_time = json_number_value(value);
        }
        value = json_object_get(section, "reconnect");
        if(json_is_boolean(value)) {
            g_ctx->config.pppoe_reconnect = json_boolean_value(value);
        } else {
            g_ctx->config.pppoe_reconnect = g_ctx->config.sessions_reconnect;
        }
        value = json_object_get(section, "discovery-timeout");
        if(json_is_number(value)) {
            g_ctx->config.pppoe_discovery_timeout = json_number_value(value);
        }
        value = json_object_get(section, "discovery-retry");
        if(json_is_number(value)) {
            g_ctx->config.pppoe_discovery_retry = json_number_value(value);
        }
        if(json_unpack(section, "{s:s}", "service-name", &s) == 0) {
            g_ctx->config.pppoe_service_name = strdup(s);
        }
        value = json_object_get(section, "host-uniq");
        if(json_is_boolean(value)) {
            g_ctx->config.pppoe_host_uniq = json_boolean_value(value);
        }
        value = json_object_get(section, "vlan-priority");
        if(json_is_number(value)) {
            g_ctx->config.pppoe_vlan_priority = json_number_value(value);
            if(g_ctx->config.pppoe_vlan_priority > 7) {
                fprintf(stderr, "JSON config error: Invalid value for pppoe->vlan-priority\n");
                return false;
            }
        }
    }

    /* PPP Configuration */
    section = json_object_get(root, "ppp");
    if(json_is_object(section)) {
        value = json_object_get(section, "mru");
        if(json_is_number(value)) {
            g_ctx->config.ppp_mru = json_number_value(value);
        }
        sub = json_object_get(section, "authentication");
        if(json_is_object(sub)) {
            if(json_unpack(sub, "{s:s}", "username", &s) == 0) {
                g_ctx->config.username = strdup(s);
            }
            if(json_unpack(sub, "{s:s}", "password", &s) == 0) {
                g_ctx->config.password = strdup(s);
            }
            value = json_object_get(sub, "timeout");
            if(json_is_number(value)) {
                g_ctx->config.authentication_timeout = json_number_value(value);
            }
            value = json_object_get(sub, "retry");
            if(json_is_number(value)) {
                g_ctx->config.authentication_retry = json_number_value(value);
            }
            if(json_unpack(sub, "{s:s}", "protocol", &s) == 0) {
                if(strcmp(s, "PAP") == 0) {
                    g_ctx->config.authentication_protocol = PROTOCOL_PAP;
                } else if(strcmp(s, "CHAP") == 0) {
                    g_ctx->config.authentication_protocol = PROTOCOL_CHAP;
                } else {
                    fprintf(stderr, "JSON config error: Invalid value for ppp->authentication->protocol\n");
                    return false;
                }
            }
        }
        sub = json_object_get(section, "lcp");
        if(json_is_object(sub)) {
            value = json_object_get(sub, "conf-request-timeout");
            if(json_is_number(value)) {
                g_ctx->config.lcp_conf_request_timeout = json_number_value(value);
            }
            value = json_object_get(sub, "conf-request-retry");
            if(json_is_number(value)) {
                g_ctx->config.lcp_conf_request_retry = json_number_value(value);
            }
            value = json_object_get(sub, "keepalive-interval");
            if(json_is_number(value)) {
                g_ctx->config.lcp_keepalive_interval = json_number_value(value);
            }
            value = json_object_get(sub, "keepalive-retry");
            if(json_is_number(value)) {
                g_ctx->config.lcp_keepalive_retry = json_number_value(value);
            }
            value = json_object_get(sub, "start-delay");
            if(json_is_number(value)) {
                g_ctx->config.lcp_start_delay = json_number_value(value);
                if(g_ctx->config.lcp_start_delay >= 1000) {
                    fprintf(stderr, "JSON config error: ppp->lcp->start-delay must be < 1000\n");
                    return false;
                }
            }
            value = json_object_get(sub, "ignore-vendor-specific");
            if(json_is_boolean(value)) {
                g_ctx->config.lcp_vendor_ignore = json_boolean_value(value);
            }
            value = json_object_get(sub, "connection-status-message");
            if(json_is_boolean(value)) {
                g_ctx->config.lcp_connection_status_message = json_boolean_value(value);
            }
        }
        sub = json_object_get(section, "ipcp");
        if(json_is_object(sub)) {
            value = json_object_get(sub, "enable");
            if(json_is_boolean(value)) {
                g_ctx->config.ipcp_enable = json_boolean_value(value);
            }
            value = json_object_get(sub, "request-ip");
            if(json_is_boolean(value)) {
                g_ctx->config.ipcp_request_ip = json_boolean_value(value);
            }
            value = json_object_get(sub, "request-dns1");
            if(json_is_boolean(value)) {
                g_ctx->config.ipcp_request_dns1 = json_boolean_value(value);
            }
            value = json_object_get(sub, "request-dns2");
            if(json_is_boolean(value)) {
                g_ctx->config.ipcp_request_dns2 = json_boolean_value(value);
            }
            value = json_object_get(sub, "conf-request-timeout");
            if(json_is_number(value)) {
                g_ctx->config.ipcp_conf_request_timeout = json_number_value(value);
            }
            value = json_object_get(sub, "conf-request-retry");
            if(json_is_number(value)) {
                g_ctx->config.ipcp_conf_request_retry = json_number_value(value);
            }
        }
        sub = json_object_get(section, "ip6cp");
        if(json_is_object(sub)) {
            value = json_object_get(sub, "enable");
            if(json_is_boolean(value)) {
                g_ctx->config.ip6cp_enable = json_boolean_value(value);
            }
            value = json_object_get(sub, "conf-request-timeout");
            if(json_is_number(value)) {
                g_ctx->config.ip6cp_conf_request_timeout = json_number_value(value);
            }
            value = json_object_get(sub, "conf-request-retry");
            if(json_is_number(value)) {
                g_ctx->config.ip6cp_conf_request_retry = json_number_value(value);
            }
        }
    }

    /* DHCP Configuration */
    section = json_object_get(root, "dhcp");
    if(json_is_object(section)) {
        value = json_object_get(section, "enable");
        if(json_is_boolean(value)) {
            g_ctx->config.dhcp_enable = json_boolean_value(value);
        }
        value = json_object_get(section, "broadcast");
        if(json_is_boolean(value)) {
            g_ctx->config.dhcp_broadcast = json_boolean_value(value);
        }
        value = json_object_get(section, "timeout");
        if(json_is_number(value)) {
            g_ctx->config.dhcp_timeout = json_number_value(value);
        }
        value = json_object_get(section, "retry");
        if(json_is_number(value)) {
            g_ctx->config.dhcp_retry = json_number_value(value);
        }
        value = json_object_get(section, "release-interval");
        if(json_is_number(value)) {
            g_ctx->config.dhcp_release_interval = json_number_value(value);
        }
        value = json_object_get(section, "release-retry");
        if(json_is_number(value)) {
            g_ctx->config.dhcp_release_retry = json_number_value(value);
        }
        value = json_object_get(section, "tos");
        if(json_is_number(value)) {
            g_ctx->config.dhcp_tos = json_number_value(value);
        }
        value = json_object_get(section, "vlan-priority");
        if(json_is_number(value)) {
            g_ctx->config.dhcp_vlan_priority = json_number_value(value);
            if(g_ctx->config.dhcp_vlan_priority > 7) {
                fprintf(stderr, "JSON config error: Invalid value for dhcp->vlan-priority\n");
                return false;
            }
        }
        value = json_object_get(section, "access-line");
        if(json_is_boolean(value)) {
            g_ctx->config.dhcp_access_line = json_boolean_value(value);
        }
    }

    /* DHCPv6 Configuration */
    section = json_object_get(root, "dhcpv6");
    if(json_is_object(section)) {
        value = json_object_get(section, "enable");
        if(json_is_boolean(value)) {
            g_ctx->config.dhcpv6_enable = json_boolean_value(value);
        }
        value = json_object_get(section, "ia-na");
        if(json_is_boolean(value)) {
            g_ctx->config.dhcpv6_ia_na = json_boolean_value(value);
        }
        value = json_object_get(section, "ia-pd");
        if(json_is_boolean(value)) {
            g_ctx->config.dhcpv6_ia_pd = json_boolean_value(value);
        }
        value = json_object_get(section, "rapid-commit");
        if(json_is_boolean(value)) {
            g_ctx->config.dhcpv6_rapid_commit = json_boolean_value(value);
        }
        value = json_object_get(section, "timeout");
        if(json_is_number(value)) {
            g_ctx->config.dhcpv6_timeout = json_number_value(value);
        }
        value = json_object_get(section, "retry");
        if(json_is_number(value)) {
            g_ctx->config.dhcpv6_retry = json_number_value(value);
        }
        value = json_object_get(section, "access-line");
        if(json_is_boolean(value)) {
            g_ctx->config.dhcpv6_access_line = json_boolean_value(value);
        }
    }

    /* IGMP Configuration */
    section = json_object_get(root, "igmp");
    if(json_is_object(section)) {
        value = json_object_get(section, "version");
        if(json_is_number(value)) {
            g_ctx->config.igmp_version = json_number_value(value);
            if(g_ctx->config.igmp_version < 1 || g_ctx->config.igmp_version > 3) {
                fprintf(stderr, "JSON config error: Invalid value for igmp->version\n");
                return false;
            }
        }
        value = json_object_get(section, "combined-leave-join");
        if(json_is_boolean(value)) {
            g_ctx->config.igmp_combined_leave_join = json_boolean_value(value);
        }
        value = json_object_get(section, "autostart");
        if(json_is_boolean(value)) {
            g_ctx->config.igmp_autostart = json_boolean_value(value);
        }
        value = json_object_get(section, "start-delay");
        if(json_is_number(value)) {
            number = json_number_value(value);
            if(number < 1 || number > UINT16_MAX) {
                fprintf(stderr, "JSON config error: Invalid value for igmp->start-delay\n");
                return false;
            }
            g_ctx->config.igmp_start_delay = json_number_value(value);
        }
        if(json_unpack(section, "{s:s}", "group", &s) == 0) {
            if(!inet_pton(AF_INET, s, &ipv4)) {
                fprintf(stderr, "JSON config error: Invalid value for igmp->group\n");
                return false;
            }
            g_ctx->config.igmp_group = ipv4;
        }
        if(json_unpack(section, "{s:s}", "group-iter", &s) == 0) {
            if(!inet_pton(AF_INET, s, &ipv4)) {
                fprintf(stderr, "JSON config error: Invalid value for igmp->group-iter\n");
                return false;
            }
            g_ctx->config.igmp_group_iter = ipv4;
        }
        if(json_unpack(section, "{s:s}", "source", &s) == 0) {
            if(!inet_pton(AF_INET, s, &ipv4)) {
                fprintf(stderr, "JSON config error: Invalid value for igmp->source\n");
                return false;
            }
            g_ctx->config.igmp_source = ipv4;
        }
        value = json_object_get(section, "group-count");
        if(json_is_number(value)) {
            g_ctx->config.igmp_group_count = json_number_value(value);
        }
        value = json_object_get(section, "zapping-interval");
        if(json_is_number(value)) {
            g_ctx->config.igmp_zap_interval = json_number_value(value);
        }
        value = json_object_get(section, "zapping-view-duration");
        if(json_is_number(value)) {
            g_ctx->config.igmp_zap_view_duration = json_number_value(value);
        }
        value = json_object_get(section, "zapping-count");
        if(json_is_number(value)) {
            g_ctx->config.igmp_zap_count = json_number_value(value);
        }
        value = json_object_get(section, "zapping-wait");
        if(json_is_boolean(value)) {
            g_ctx->config.igmp_zap_wait = json_boolean_value(value);
        }
        value = json_object_get(section, "send-multicast-traffic");
        if(json_is_boolean(value)) {
            g_ctx->config.send_multicast_traffic = json_boolean_value(value);
        }
        value = json_object_get(section, "multicast-traffic-autostart");
        if(json_is_boolean(value)) {
            g_ctx->config.multicast_traffic_autostart = json_boolean_value(value);
        }
        value = json_object_get(section, "multicast-traffic-length");
        if(json_is_number(value)) {
            g_ctx->config.multicast_traffic_len = json_number_value(value);
            if(g_ctx->config.multicast_traffic_len > 1500) {
                fprintf(stderr, "JSON config error: Invalid value for igmp->multicast-traffic-length (max 1500)\n");
            }
        }
        value = json_object_get(section, "multicast-traffic-tos");
        if(json_is_number(value)) {
            g_ctx->config.multicast_traffic_tos = json_number_value(value);
        }
        value = json_object_get(section, "multicast-traffic-pps");
        if(json_is_number(value)) {
            g_ctx->config.multicast_traffic_pps = json_number_value(value);
        }
        if(json_unpack(section, "{s:s}", "network-interface", &s) == 0) {
            g_ctx->config.multicast_traffic_network_interface = strdup(s);
        }
        value = json_object_get(section, "max-join-delay");
        if(json_is_number(value)) {
            g_ctx->config.igmp_max_join_delay = json_number_value(value);
        }
        value = json_object_get(section, "robustness-interval");
        if(json_is_number(value)) {
            g_ctx->config.igmp_robustness_interval = json_number_value(value);
        }
    }

    /* Access Line Configuration */
    section = json_object_get(root, "access-line");
    if(json_is_object(section)) {
        if(json_unpack(section, "{s:s}", "agent-circuit-id", &s) == 0) {
            g_ctx->config.agent_circuit_id = strdup(s);
        }
        if(json_unpack(section, "{s:s}", "agent-remote-id", &s) == 0) {
            g_ctx->config.agent_remote_id = strdup(s);
        }
        value = json_object_get(section, "rate-up");
        if(json_is_number(value)) {
            g_ctx->config.rate_up = json_number_value(value);
        }
        value = json_object_get(section, "rate-down");
        if(json_is_number(value)) {
            g_ctx->config.rate_down = json_number_value(value);
        }
        value = json_object_get(section, "dsl-type");
        if(json_is_number(value)) {
            g_ctx->config.dsl_type = json_number_value(value);
        }
    }

    /* Access Line Profiles Configuration */
    section = json_object_get(root, "access-line-profiles");
    if(json_is_array(section)) {
        /* Config is provided as array (multiple access-line-profiles) */
        size = json_array_size(section);
        for(i = 0; i < size; i++) {
            if(!access_line_profile) {
                g_ctx->config.access_line_profile = calloc(1, sizeof(bbl_access_line_profile_s));
                access_line_profile = g_ctx->config.access_line_profile;
            } else {
                access_line_profile->next = calloc(1, sizeof(bbl_access_line_profile_s));
                access_line_profile = access_line_profile->next;
            }
            if(!json_parse_access_line_profile(json_array_get(section, i), access_line_profile)) {
                return false;
            }
        }
    }

    /* Global Traffic Configuration */
    section = json_object_get(root, "traffic");
    if(json_is_object(section)) {
        value = json_object_get(section, "autostart");
        if(json_is_boolean(value)) {
            g_ctx->config.traffic_autostart = json_boolean_value(value);
        }
        value = json_object_get(section, "stop-verified");
        if(json_is_boolean(value)) {
            g_ctx->config.traffic_stop_verified = json_boolean_value(value);
        }
        value = json_object_get(section, "max-burst");
        if(json_is_number(value)) {
            number = json_number_value(value);
            if(number < 1 || number > UINT8_MAX) {
                fprintf(stderr, "JSON config error: Invalid value for traffic->max-burst\n");
                return false;
            }
            g_ctx->config.stream_max_burst = number;
        }
        value = json_object_get(section, "stream-rate-calculation");
        if(json_is_boolean(value)) {
            g_ctx->config.stream_rate_calc = json_boolean_value(value);
        }
    }

    /* Session Traffic Configuration */
    section = json_object_get(root, "session-traffic");
    if(json_is_object(section)) {
        value = json_object_get(section, "autostart");
        if(json_is_boolean(value)) {
            g_ctx->config.session_traffic_autostart = json_boolean_value(value);
        }
        value = json_object_get(section, "ipv4-pps");
        if(json_is_number(value)) {
            g_ctx->config.session_traffic_ipv4_pps = json_number_value(value);
        }
        value = json_object_get(section, "ipv6-pps");
        if(json_is_number(value)) {
            g_ctx->config.session_traffic_ipv6_pps = json_number_value(value);
        }
        value = json_object_get(section, "ipv6pd-pps");
        if(json_is_number(value)) {
            g_ctx->config.session_traffic_ipv6pd_pps = json_number_value(value);
        }
        value = json_object_get(section, "ipv4-label");
        if(json_is_number(value)) {
            g_ctx->config.session_traffic_ipv4_label = json_number_value(value);
        }
        if(json_unpack(section, "{s:s}", "ipv4-address", &s) == 0) {
            if(!inet_pton(AF_INET, s, &ipv4)) {
                fprintf(stderr, "JSON config error: Invalid value for session-traffic->ipv4-address\n");
                return false;
            }
            g_ctx->config.session_traffic_ipv4_address = ipv4;
        }
        value = json_object_get(section, "ipv6-label");
        if(json_is_number(value)) {
            g_ctx->config.session_traffic_ipv6_label = json_number_value(value);
        }
        if(json_unpack(section, "{s:s}", "ipv6-address", &s) == 0) {
            if(!inet_pton(AF_INET6, s, &g_ctx->config.session_traffic_ipv6_address)) {
                fprintf(stderr, "JSON config error: Invalid value for session-traffic->ipv6-address\n");
                return false;
            }
        }
    }

    /* BGP Configuration */
    sub = json_object_get(root, "bgp");
    if(json_is_array(sub)) {
        /* Config is provided as array (multiple BGP sessions) */
        size = json_array_size(sub);
        for(i = 0; i < size; i++) {
            if(!bgp_config) {
                g_ctx->config.bgp_config = calloc(1, sizeof(bgp_config_s));
                bgp_config = g_ctx->config.bgp_config;
            } else {
                bgp_config->next = calloc(1, sizeof(bgp_config_s));
                bgp_config = bgp_config->next;
            }
            if(!json_parse_bgp_config(json_array_get(sub, i), bgp_config)) {
                return false;
            }
        }
    } else if(json_is_object(sub)) {
        /* Config is provided as object (single BGP session) */
        bgp_config = calloc(1, sizeof(bgp_config_s));
        if(!g_ctx->config.bgp_config) {
            g_ctx->config.bgp_config = bgp_config;
        }
        if(!json_parse_bgp_config(sub, bgp_config)) {
            return false;
        }
    }

    /* Pre-Load BGP RAW update files */
    sub = json_object_get(root, "bgp-raw-update-files");
    if(json_is_array(sub)) {
        size = json_array_size(sub);
        for(i = 0; i < size; i++) {
            s = json_string_value(json_array_get(sub, i));
            if(s) {
                if(!bgp_raw_update_load(s, true)) {
                    return false;
                }
            }
        }
    }

    /* IS-IS Configuration */
    sub = json_object_get(root, "isis");
    if(json_is_array(sub)) {
        /* Config is provided as array (multiple IS-IS instances) */
        size = json_array_size(sub);
        for(i = 0; i < size; i++) {
            if(!isis_config) {
                g_ctx->config.isis_config = calloc(1, sizeof(isis_config_s));
                isis_config = g_ctx->config.isis_config;
            } else {
                isis_config->next = calloc(1, sizeof(isis_config_s));
                isis_config = isis_config->next;
            }
            if(!json_parse_isis_config(json_array_get(sub, i), isis_config)) {
                return false;
            }
        }
    } else if(json_is_object(sub)) {
        /* Config is provided as object (single IS-IS instance) */
        isis_config = calloc(1, sizeof(isis_config_s));
        if(!g_ctx->config.isis_config) {
            g_ctx->config.isis_config = isis_config;
        }
        if(!json_parse_isis_config(sub, isis_config)) {
            return false;
        }
    }

    /* LDP Configuration */
    sub = json_object_get(root, "ldp");
    if(json_is_array(sub)) {
        /* Config is provided as array (multiple LDP instances) */
        size = json_array_size(sub);
        for(i = 0; i < size; i++) {
            if(!ldp_config) {
                g_ctx->config.ldp_config = calloc(1, sizeof(ldp_config_s));
                ldp_config = g_ctx->config.ldp_config;
            } else {
                ldp_config->next = calloc(1, sizeof(ldp_config_s));
                ldp_config = ldp_config->next;
            }
            if(!json_parse_ldp_config(json_array_get(sub, i), ldp_config)) {
                return false;
            }
        }
    } else if(json_is_object(sub)) {
        /* Config is provided as object (single LDP instance) */
        ldp_config = calloc(1, sizeof(ldp_config_s));
        if(!g_ctx->config.ldp_config) {
            g_ctx->config.ldp_config = ldp_config;
        }
        if(!json_parse_ldp_config(sub, ldp_config)) {
            return false;
        }
    }

    /* Pre-Load LDP RAW update files */
    sub = json_object_get(root, "ldp-raw-update-files");
    if(json_is_array(sub)) {
        size = json_array_size(sub);
        for(i = 0; i < size; i++) {
            s = json_string_value(json_array_get(sub, i));
            if(s) {
                if(!ldp_raw_update_load(s, true)) {
                    return false;
                }
            }
        }
    }

    /* Interface Configuration */
    section = json_object_get(root, "interfaces");
    if(json_is_object(section)) {
        if(json_unpack(section, "{s:s}", "io-mode", &s) == 0) {
            if(strcmp(s, "packet_mmap_raw") == 0) {
                g_ctx->config.io_mode = IO_MODE_PACKET_MMAP_RAW;
            } else if(strcmp(s, "packet_mmap") == 0) {
                g_ctx->config.io_mode = IO_MODE_PACKET_MMAP;
            } else if(strcmp(s, "raw") == 0) {
                g_ctx->config.io_mode = IO_MODE_RAW;
#if BNGBLASTER_DPDK
            } else if(strcmp(s, "dpdk") == 0) {
                g_ctx->config.io_mode = IO_MODE_DPDK;
                g_ctx->dpdk = true;
#endif
            } else {
                fprintf(stderr, "Config error: Invalid value for interfaces->io-mode\n");
                return false;
            }
        } else {
            g_ctx->config.io_mode = IO_MODE_PACKET_MMAP_RAW;
        }
        value = json_object_get(section, "io-slots");
        if(json_is_number(value)) {
            g_ctx->config.io_slots = json_number_value(value);
        }

        value = json_object_get(section, "qdisc-bypass");
        if(json_is_boolean(value)) {
            g_ctx->config.qdisc_bypass = json_boolean_value(value);
        }
        value = json_object_get(section, "tx-interval");
        if(json_is_number(value)) {
            g_ctx->config.tx_interval = json_number_value(value) * MSEC;
        }
        value = json_object_get(section, "rx-interval");
        if(json_is_number(value)) {
            g_ctx->config.rx_interval = json_number_value(value) * MSEC;
        }
        value = json_object_get(section, "tx-threads");
        if(value) {
            g_ctx->config.tx_threads = json_number_value(value);
        }
        value = json_object_get(section, "rx-threads");
        if(value) {
            g_ctx->config.rx_threads = json_number_value(value);
        }
        value = json_object_get(section, "capture-include-streams");
        if(json_is_boolean(value)) {
            g_ctx->pcap.include_streams = json_boolean_value(value);
        }
        value = json_object_get(section, "mac-modifier");
        if(json_is_number(value)) {
            if(json_number_value(value) < 0 || json_number_value(value) > UINT8_MAX) {
                fprintf(stderr, "Config error: Invalid value for interfaces->mac-modifier\n");
                return false;
            }
            g_ctx->config.mac_modifier = json_number_value(value);
        }

        /* LAG Configuration Section */
        sub = json_object_get(section, "lag");
        if(json_is_array(sub)) {
            /* Config is provided as array (multiple LAG) */
            size = json_array_size(sub);
            for(i = 0; i < size; i++) {
                if(!lag_config) {
                    g_ctx->config.lag_config = calloc(1, sizeof(bbl_lag_config_s));
                    lag_config = g_ctx->config.lag_config;
                } else {
                    lag_config->next = calloc(1, sizeof(bbl_lag_config_s));
                    lag_config = lag_config->next;
                }
                if(!json_parse_lag(json_array_get(sub, i), lag_config)) {
                    return false;
                }
            }
        } else if(json_is_object(sub)) {
            /* Config is provided as object (single LAG) */
            lag_config = calloc(1, sizeof(bbl_lag_config_s));
            if(!g_ctx->config.lag_config) {
                g_ctx->config.lag_config = lag_config;
            }
            if(!json_parse_lag(sub, lag_config)) {
                return false;
            }
        }

        /* Links Configuration Section */
        sub = json_object_get(section, "links");
        if(json_is_array(sub)) {
            /* Config is provided as array (multiple links) */
            size = json_array_size(sub);
            for(i = 0; i < size; i++) {
                if(!link_config) {
                    g_ctx->config.link_config = calloc(1, sizeof(bbl_link_config_s));
                    link_config = g_ctx->config.link_config;
                } else {
                    link_config->next = calloc(1, sizeof(bbl_link_config_s));
                    link_config = link_config->next;
                }
                if(!json_parse_link(json_array_get(sub, i), link_config)) {
                    return false;
                }
            }
        } else if(json_is_object(sub)) {
            /* Config is provided as object (single network interface) */
            link_config = calloc(1, sizeof(bbl_link_config_s));
            if(!g_ctx->config.link_config) {
                g_ctx->config.link_config = link_config;
            }
            if(!json_parse_link(sub, link_config)) {
                return false;
            }
        }

        /* Network Interface Configuration Section */
        sub = json_object_get(section, "network");
        if(json_is_array(sub)) {
            /* Config is provided as array (multiple network interfaces) */
            size = json_array_size(sub);
            for(i = 0; i < size; i++) {
                if(!network_config) {
                    g_ctx->config.network_config = calloc(1, sizeof(bbl_network_config_s));
                    network_config = g_ctx->config.network_config;
                } else {
                    network_config->next = calloc(1, sizeof(bbl_network_config_s));
                    network_config = network_config->next;
                }
                if(!json_parse_network_interface(json_array_get(sub, i), network_config)) {
                    return false;
                }
            }
        } else if(json_is_object(sub)) {
            /* Config is provided as object (single network interface) */
            network_config = calloc(1, sizeof(bbl_network_config_s));
            if(!g_ctx->config.network_config) {
                g_ctx->config.network_config = network_config;
            }
            if(!json_parse_network_interface(sub, network_config)) {
                return false;
            }
        }

        /* Access Interface Configuration Section */
        sub = json_object_get(section, "access");
        if(json_is_array(sub)) {
            /* Config is provided as array (multiple access ranges) */
            size = json_array_size(sub);
            for(i = 0; i < size; i++) {
                if(!access_config) {
                    g_ctx->config.access_config = calloc(1, sizeof(bbl_access_config_s));
                    access_config = g_ctx->config.access_config;
                } else {
                    access_config->next = calloc(1, sizeof(bbl_access_config_s));
                    access_config = access_config->next;
                }
                if(!json_parse_access_interface(json_array_get(sub, i), access_config)) {
                    return false;
                }
            }
        } else if(json_is_object(sub)) {
            /* Config is provided as object (single access range) */
            access_config = calloc(1, sizeof(bbl_access_config_s));
            if(!g_ctx->config.access_config) {
                g_ctx->config.access_config = access_config;
            }
            if(!json_parse_access_interface(sub, access_config)) {
                return false;
            }
        }

        /* A10NSP Interface Configuration Section */
        sub = json_object_get(section, "a10nsp");
        if(json_is_array(sub)) {
            /* Config is provided as array (multiple a10nsp interfaces) */
            size = json_array_size(sub);
            for(i = 0; i < size; i++) {
                if(!a10nsp_config) {
                    g_ctx->config.a10nsp_config = calloc(1, sizeof(bbl_a10nsp_config_s));
                    a10nsp_config = g_ctx->config.a10nsp_config;
                } else {
                    a10nsp_config->next = calloc(1, sizeof(bbl_a10nsp_config_s));
                    a10nsp_config = a10nsp_config->next;
                }
                if(!json_parse_a10nsp_interface(json_array_get(sub, i), a10nsp_config)) {
                    return false;
                }
            }
        } else if(json_is_object(sub)) {
            /* Config is provided as object (single a10nsp interface) */
            a10nsp_config = calloc(1, sizeof(bbl_a10nsp_config_s));
            if(!g_ctx->config.a10nsp_config) {
                g_ctx->config.a10nsp_config = a10nsp_config;
            }
            if(!json_parse_a10nsp_interface(sub, a10nsp_config)) {
                return false;
            }
        }
    } else {
        fprintf(stderr, "JSON config error: Missing interfaces section\n");
        return false;
    }

    /* L2TP Server Configuration (LNS) */
    section = json_object_get(root, "l2tp-server");
    if(json_is_array(section)) {
        if(!g_ctx->config.network_config) {
            fprintf(stderr, "JSON config error: Failed to add L2TP server because of missing or incomplete network interface config\n");
            return false;
        }
        size = json_array_size(section);
        for(i = 0; i < size; i++) {
            sub = json_array_get(section, i);
            if(!l2tp_server) {
                g_ctx->config.l2tp_server = calloc(1, sizeof(bbl_l2tp_server_s));
                l2tp_server = g_ctx->config.l2tp_server;
            } else {
                l2tp_server->next = calloc(1, sizeof(bbl_l2tp_server_s));
                l2tp_server = l2tp_server->next;
            }
            if(json_unpack(sub, "{s:s}", "name", &s) == 0) {
                l2tp_server->host_name = strdup(s);
            } else {
                fprintf(stderr, "JSON config error: Missing value for l2tp-server->name\n");
                return false;
            }
            if(json_unpack(sub, "{s:s}", "secret", &s) == 0) {
                l2tp_server->secret = strdup(s);
            }
            if(json_unpack(sub, "{s:s}", "address", &s) == 0) {
                if(!inet_pton(AF_INET, s, &ipv4)) {
                    fprintf(stderr, "JSON config error: Invalid value for l2tp-server->address\n");
                    return false;
                }
                l2tp_server->ip = ipv4;
                CIRCLEQ_INIT(&l2tp_server->tunnel_qhead);
                add_secondary_ipv4(ipv4);
            } else {
                fprintf(stderr, "JSON config error: Missing value for l2tp-server->address\n");
            }
            value = json_object_get(sub, "receive-window-size");
            if(json_is_number(value)) {
                number = json_number_value(value);
                if(number < 1 || number > UINT16_MAX) {
                    fprintf(stderr, "JSON config error: Invalid value for l2tp-server->receive-window-size\n");
                    return false;
                }
                l2tp_server->receive_window = number;
            } else {
                l2tp_server->receive_window = 16;
            }
            value = json_object_get(sub, "max-retry");
            if(json_is_number(value)) {
                number = json_number_value(value);
                if(number < 1 || number > UINT16_MAX) {
                    fprintf(stderr, "JSON config error: Invalid value for l2tp-server->max-retry\n");
                    return false;
                }
                l2tp_server->max_retry = number;
            } else {
                l2tp_server->max_retry = 5;
            }
            if(json_unpack(sub, "{s:s}", "congestion-mode", &s) == 0) {
                if(strcmp(s, "default") == 0) {
                    l2tp_server->congestion_mode = BBL_L2TP_CONGESTION_DEFAULT;
                } else if(strcmp(s, "slow") == 0) {
                    l2tp_server->congestion_mode = BBL_L2TP_CONGESTION_SLOW;
                } else if(strcmp(s, "aggressive") == 0) {
                    l2tp_server->congestion_mode = BBL_L2TP_CONGESTION_AGGRESSIVE;
                } else {
                    fprintf(stderr, "Config error: Invalid value for l2tp-server->congestion-mode\n");
                    return false;
                }
            } else {
                l2tp_server->congestion_mode = BBL_L2TP_CONGESTION_DEFAULT;
            }
            value = json_object_get(sub, "data-control-priority");
            if(json_is_boolean(value)) {
                l2tp_server->data_control_priority = json_boolean_value(value);
            }
            value = json_object_get(sub, "data-length");
            if(json_is_boolean(value)) {
                l2tp_server->data_length = json_boolean_value(value);
            }
            value = json_object_get(sub, "data-offset");
            if(json_is_boolean(value)) {
                l2tp_server->data_offset = json_boolean_value(value);
            }
            value = json_object_get(sub, "control-tos");
            if(json_is_number(value)) {
                number = json_number_value(value);
                if(number < 0 || number > UINT8_MAX) {
                    fprintf(stderr, "JSON config error: Invalid value for l2tp-server->control-tos\n");
                    return false;
                }
                l2tp_server->control_tos = number;
            }
            value = json_object_get(sub, "data-control-tos");
            if(json_is_number(value)) {
                number = json_number_value(value);
                if(number < 0 || number > UINT8_MAX) {
                    fprintf(stderr, "JSON config error: Invalid value for l2tp-server->data-control-tos\n");
                    return false;
                }
                l2tp_server->data_control_tos = number;
            }
            value = json_object_get(sub, "hello-interval");
            if(json_is_number(value)) {
                number = json_number_value(value);
                if(number < 0 || number > UINT16_MAX) {
                    fprintf(stderr, "JSON config error: Invalid value for l2tp-server->hello-interval\n");
                    return false;
                }
                l2tp_server->hello_interval = number;
            } else {
                l2tp_server->hello_interval = 30;
            }
            value = json_object_get(sub, "lcp-padding");
            if(json_is_number(value)) {
                l2tp_server->lcp_padding = json_number_value(value);;
            }
        }
    } else if(json_is_object(section)) {
        fprintf(stderr, "JSON config error: List expected in L2TP server configuration but dictionary found\n");
    }

    /* Traffic Streams Configuration */
    if(!json_parse_config_streams(root)) {
        return false;
    }
    return true;
}

/**
 * bbl_config_load_json
 *
 * This function populates the BBL context
 * from given JSON configuration file returning
 * true if successful or false if failed with
 * error message printed to stderr.
 *
 * @param filename JSON filename
 */
bool
bbl_config_load_json(const char *filename)
{
    json_t *root = NULL;
    json_error_t error;
    bool result = false;

    root = json_load_file(filename, 0, &error);
    if(root) {
        result = json_parse_config(root);
        json_decref(root);
    } else {
        fprintf(stderr, "JSON config error: File %s Line %d: %s\n", filename, error.line, error.text);
    }
    return result;
}

/**
 * bbl_config_streams_load_json
 *
 * This function populates traffic streams
 * from given JSON stream configuration file returning
 * true if successful or false if failed with
 * error message printed to stderr.
 *
 * @param filename JSON filename
 */
bool
bbl_config_streams_load_json(const char *filename)
{
    json_t *root = NULL;
    json_error_t error;
    bool result = false;

    root = json_load_file(filename, 0, &error);
    if(root) {
        result = json_parse_config_streams(root);
        json_decref(root);
    } else {
        fprintf(stderr, "JSON stream config error: File %s Line %d: %s\n", filename, error.line, error.text);
    }
    return result;
}

/**
 * bbl_config_init_defaults
 *
 * This functions is population the BBL context
 * with default configuration values.
 */
void
bbl_config_init_defaults()
{
    g_ctx->pcap.include_streams = false;
    g_ctx->config.username = g_default_user;
    g_ctx->config.password = g_default_pass;
    g_ctx->config.tx_interval = 1 * MSEC;
    g_ctx->config.rx_interval = 1 * MSEC;
    g_ctx->config.io_slots = 4096;
    g_ctx->config.qdisc_bypass = true;
    g_ctx->config.sessions = 1;
    g_ctx->config.sessions_max_outstanding = 800;
    g_ctx->config.sessions_start_rate = 400;
    g_ctx->config.sessions_stop_rate = 400;
    g_ctx->config.sessions_autostart = true;
    g_ctx->config.monkey_autostart = true;
    g_ctx->config.pppoe_discovery_timeout = 5;
    g_ctx->config.pppoe_discovery_retry = 10;
    g_ctx->config.ppp_mru = 1492;
    g_ctx->config.lcp_conf_request_timeout = 5;
    g_ctx->config.lcp_conf_request_retry = 10;
    g_ctx->config.lcp_keepalive_interval = 30;
    g_ctx->config.lcp_keepalive_retry = 3;
    g_ctx->config.authentication_timeout = 5;
    g_ctx->config.authentication_retry = 30;
    g_ctx->config.ipoe_ipv6_enable = true;
    g_ctx->config.ipoe_ipv4_enable = true;
    g_ctx->config.arp_timeout = 1;
    g_ctx->config.arp_interval = 300;
    g_ctx->config.ipcp_enable = true;
    g_ctx->config.ipcp_request_ip = true;
    g_ctx->config.ipcp_request_dns1 = true;
    g_ctx->config.ipcp_request_dns2 = true;
    g_ctx->config.ipcp_conf_request_timeout = 5;
    g_ctx->config.ipcp_conf_request_retry = 10;
    g_ctx->config.ip6cp_enable = true;
    g_ctx->config.ip6cp_conf_request_timeout = 5;
    g_ctx->config.ip6cp_conf_request_retry = 10;
    g_ctx->config.dhcp_enable = false;
    g_ctx->config.dhcp_access_line = true;
    g_ctx->config.dhcp_timeout = 5;
    g_ctx->config.dhcp_retry = 10;
    g_ctx->config.dhcp_release_interval = 1;
    g_ctx->config.dhcp_release_retry = 3;
    g_ctx->config.dhcpv6_enable = true;
    g_ctx->config.dhcpv6_ia_na = true;
    g_ctx->config.dhcpv6_ia_pd = true;
    g_ctx->config.dhcpv6_rapid_commit = true;
    g_ctx->config.dhcpv6_access_line = true;
    g_ctx->config.dhcpv6_timeout = 5;
    g_ctx->config.dhcpv6_retry = 10;
    g_ctx->config.igmp_autostart = true;
    g_ctx->config.igmp_version = IGMP_VERSION_3;
    g_ctx->config.igmp_start_delay = 1;
    g_ctx->config.igmp_group = 0;
    g_ctx->config.igmp_group_iter = htobe32(1);
    g_ctx->config.igmp_source = 0;
    g_ctx->config.igmp_group_count = 1;
    g_ctx->config.igmp_zap_wait = true;
    g_ctx->config.igmp_robustness_interval = 1000;
    g_ctx->config.multicast_traffic_pps = 1000;
    g_ctx->config.traffic_autostart = true;
    g_ctx->config.stream_rate_calc = true;
    g_ctx->config.stream_max_burst = 32;
    g_ctx->config.multicast_traffic_autostart = true;
    g_ctx->config.session_traffic_autostart = true;
}