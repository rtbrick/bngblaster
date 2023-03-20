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
    /*
    * The next 2 lines of code is used to declare the key and value variables where the
    * json_object_foreach() sets the values of key and value
    */
    json_t *value = NULL;
    const char *key;

    bool access_line_profile_id_absent = true;
    
    json_object_foreach(config, key, value) {
        if (!strcmp(key,"access-line-profile-id")) {
            profile->access_line_profile_id = json_number_value(value);
            access_line_profile_id_absent = false;
            continue;
        }

        if (!strcmp(key,"act-up")) {
            profile->act_up = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"act-down")) {
            profile->act_down = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"min-up")) {
            profile->min_up = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"min-down")) {
            profile->min_down = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"att-up")) {
            profile->att_up = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"att-down")) {
            profile->att_down = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"min-up-low")) {
            profile->min_up_low = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"min-down-low")) {
            profile->min_down_low = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"max-interl-delay-up")) {
            profile->max_interl_delay_up = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"act-interl-delay-up")) {
            profile->act_interl_delay_up = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"max-interl-delay-down")) {
            profile->max_interl_delay_down = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"act-interl-delay-down")) {
            profile->act_interl_delay_down = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"data-link-encaps")) {
            profile->data_link_encaps = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"dsl-type")) {
            profile->dsl_type = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"pon-type")) {
            profile->pon_type = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"etr-up")) {
            profile->etr_up = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"etr-down")) {
            profile->etr_down = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"attetr-up")) {
            profile->attetr_up = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"attetr-down")) {
            profile->attetr_down = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"gdr-up")) {
            profile->gdr_up = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"gdr-down")) {
            profile->gdr_down = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"attgdr-up")) {
            profile->attgdr_up = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"attgdr-down")) {
            profile->attgdr_down = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"ont-onu-avg-down")) {
            profile->ont_onu_avg_down = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"ont-onu-peak-down")) {
            profile->ont_onu_peak_down = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"ont-onu-max-up")) {
            profile->ont_onu_max_up = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"ont-onu-ass-up")) {
            profile->ont_onu_ass_up = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"pon-max-up")) {
            profile->pon_max_up = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"pon-max-down")) {
            profile->pon_max_down = json_number_value(value);
            continue;
        }

        /* If none of the above key values are matchhed */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in access-line-profiles\n", key);
        return false;
    }

    if (access_line_profile_id_absent) {
        fprintf(stderr, "Config error: Missing value for access-line-profiles->access-line-profile-id\n");
        return false;
    }
    
    return true;

}

static bool
json_parse_lag(json_t *lag, bbl_lag_config_s *lag_config)
{
    /*
    * The next 2 lines of code is used to declare the key and value variables where the
    * json_object_foreach() sets the values of key and value
    */
    json_t *value = NULL;
    const char *key;

    /*flag variables to check are declared here*/
    bool lag_interface_absent = true;
    bool lacp_sys_prior_absent = true;
    bool lacp_sys_id_absent = true;
    bool lacp_min_act_links_absent = true;
    bool lacp_max_act_links_absent = true;
    bool lacp_mac_absent = true;

    /*char *s is used to get the lacp-system-id / mac*/
    const char *string = NULL;
    
    static uint8_t lag_id = 0;
    lag_config->id = ++lag_id;

    json_object_foreach(lag, key, value) {
        
        if (!strcmp(key, "interface")) {
              lag_config->interface = strdup(json_string_value(value));
              lag_interface_absent = false;
              continue;
        }

        if (!strcmp(key,"lacp")) {
            lag_config->lacp_enable = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key,"lacp-timeout-short")) {
            lag_config->lacp_timeout_short = json_boolean_value(value);
            continue;
        }        
        
        if (!strcmp(key,"lacp-system-priority")) {
            lag_config->lacp_system_priority = json_number_value(value);
            lacp_sys_prior_absent = false;
            continue;
        }

        if (!strcmp(key,"lacp-system-id")) {
            string = json_string_value(value);
            lacp_sys_id_absent = false;
            if(sscanf(string, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &lag_config->lacp_system_id[0],
                &lag_config->lacp_system_id[1],
                &lag_config->lacp_system_id[2],
                &lag_config->lacp_system_id[3],
                &lag_config->lacp_system_id[4],
                &lag_config->lacp_system_id[5]) < 6) {
                    fprintf(stderr, "JSON config error: Invalid value for lag->lacp-system-id\n");
                    return false;
            }
            continue;
        }   

        if (!strcmp(key,"lacp-min-active-links")) {
            lag_config->lacp_min_active_links = json_number_value(value);
            lacp_min_act_links_absent = false;
            continue;
        }

        if (!strcmp(key,"lacp-max-active-links")) {
            lag_config->lacp_max_active_links = json_number_value(value);
            lacp_max_act_links_absent = false;
            continue;
        }      

        if (!strcmp(key,"mac")) {
            string = json_string_value(value);
            lacp_mac_absent = false;
            if(sscanf(string, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &lag_config->mac[0],
                &lag_config->mac[1],
                &lag_config->mac[2],
                &lag_config->mac[3],
                &lag_config->mac[4],
                &lag_config->mac[5]) < 6) {
                    fprintf(stderr, "JSON config error: Invalid value for lag->mac\n");
                    return false;
            }
            continue;
        }  

        /* If none of the above key values are macthed*/
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in interface->lag[%d]\n",key, lag_id - 1);
        return false;

    }

    if (lag_interface_absent) {
        fprintf(stderr, "JSON config error: Missing value for lag->interface\n");
        return false;
    }

    if (lacp_sys_prior_absent) {
        lag_config->lacp_system_priority = 32768;
    }

    if (lacp_sys_id_absent) {
        lag_config->lacp_system_id[0] = 0x02;
        lag_config->lacp_system_id[1] = 0xff;
        lag_config->lacp_system_id[2] = 0xff;
        lag_config->lacp_system_id[3] = 0xff;
        lag_config->lacp_system_id[4] = 0xff;
    }

    if (lacp_min_act_links_absent) {
        lag_config->lacp_min_active_links = 0;
    }

    if (lacp_max_act_links_absent) {
        lag_config->lacp_max_active_links = UINT8_MAX;
    }

    if (lacp_mac_absent) {
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
    const char *key;
    json_t *value;

    char *string;
    json_t *sub = NULL;
    int index;
    int size;
    double number;

    /*  All flag variables are declared here    */
    bool link_interface_absent = true;
    bool link_io_mode_absent = true;
    bool link_io_slots_absent = true;
    bool link_qdisc_bypass_absent = true;
    bool link_tx_int_absent = true;
    bool link_rx_int_absent = true;
    bool link_tx_threads_absent = true;
    bool link_rx_threads_absent = true;
    bool link_lag_int_absent = true; //used inside json_object_foreach
    bool link_lag_lacp_absent = true;

    json_object_foreach(link, key, value) {
        
        if (!strcmp(key,"interface")) {
            string = strdup(json_string_value(value));
            if(link_present(string) || lag_present(string)) {
                fprintf(stderr, "JSON config error: Duplicate link configuration for %s\n", string);
                return false;
            }
            link_config->interface = string;
            link_interface_absent = false;   
            continue;     
        }

        if (!strcmp(key, "description")) {
            link_config->description = strdup(json_string_value(value));
            continue;
        }

        if (!strcmp(key, "mac")) {
            string = strdup(json_string_value(value));
            if(sscanf(string, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                &link_config->mac[0],
                &link_config->mac[1],
                &link_config->mac[2],
                &link_config->mac[3],
                &link_config->mac[4],
                &link_config->mac[5]) < 6) {
                    fprintf(stderr, "JSON config error: Invalid value for links->mac\n");
                    return false;
            }
            continue;
        }

        if (!strcmp(key, "io-mode")) {
            string = strdup(json_string_value(value));
            link_io_mode_absent = false;
            if (!strcmp(string, "packet_mmap_raw")) {
                link_config->io_mode = IO_MODE_PACKET_MMAP_RAW;
                io_packet_mmap_set_max_stream_len();
            } else if (!strcmp(string, "packet_mmap")) {
                link_config->io_mode = IO_MODE_PACKET_MMAP;
                io_packet_mmap_set_max_stream_len();
            } else if (!strcmp(string, "raw")) {
                link_config->io_mode = IO_MODE_RAW;
#if BNGBLASTER_DPDK
            } else if (!strcmp(string, "dpdk")) {
                link_config->io_mode = IO_MODE_DPDK;
                g_ctx->dpdk = true;
#endif                
            } else {
                fprintf(stderr, "Config error: Invalid value for links->io-mode\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "io-slots")) {
            number = json_number_value(value);
            if(number < 32 || number >= UINT16_MAX) {
                fprintf(stderr, "JSON config error: Invalid value for links->io-slots\n");
                return false;
            }
            link_config->io_slots_tx = number;
            link_config->io_slots_rx = number;
            link_io_slots_absent = false;
            continue;
        }

        if (!strcmp(key, "io-slots-tx")) {
            number = json_number_value(value);
            if(number < 32 || number >= UINT16_MAX) {
                fprintf(stderr, "JSON config error: Invalid value for links->io-slots-tx\n");
                return false;
            }
            link_config->io_slots_tx = number;
            continue;
        }

        if (!strcmp(key, "io-slots-rx")) {
            number = json_number_value(value);
            if(number < 32 || number >= UINT16_MAX) {
                fprintf(stderr, "JSON config error: Invalid value for links->io-slots-rx\n");
                return false;
            }
            link_config->io_slots_rx = number; 
            continue;        
        }

        if (!strcmp(key, "qdisc-bypass")) {
            link_config->qdisc_bypass = json_number_value(value);
            link_qdisc_bypass_absent = false;
            continue;
        }

        if (!strcmp(key, "tx-interval")) {
            link_config->tx_interval = json_number_value(value) * MSEC;
            link_tx_int_absent = false;
            continue;
        }

        if (!strcmp(key, "rx-interval")) {
            link_config->rx_interval = json_number_value(value) * MSEC;
            link_rx_int_absent = false;
            continue;
        }

        if (!strcmp(key, "tx-threads")) {
            link_config->tx_threads = json_number_value(value);
            link_tx_threads_absent = false;
            continue;
        }

        if (!strcmp(key, "rx-threads")) {
            link_config->rx_threads = json_number_value(value);
            link_rx_threads_absent = false;
            continue;
        }

        if (!strcmp(key, "rx-cpuset")) {
            if (json_is_array(value)) {
                size = json_array_size(value);
                link_config->rx_cpuset_cur = 0;
                link_config->rx_cpuset_count = size;
                link_config->rx_cpuset = calloc(size, sizeof(uint16_t));
                json_array_foreach(value, index, sub) {
                    if(json_is_number(sub)) {
                        link_config->rx_cpuset[index] = json_number_value(sub);
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
            continue;
        }

        if (!strcmp(key, "tx-cpuset")) {
            if (json_is_array(value)) {
                size = json_array_size(value);
                link_config->tx_cpuset_cur = 0;
                link_config->tx_cpuset_count = size;
                link_config->tx_cpuset = calloc(size, sizeof(uint16_t));
                json_array_foreach(value, index, sub) {
                    if(json_is_number(sub)) {
                        link_config->tx_cpuset[index] = json_number_value(sub);
                    } else {
                        fprintf(stderr, "JSON config error: Invalid value for links->rx-cpuset\n");
                        return false;
                    }
                }
            } else if(json_is_number(value)) {
                link_config->tx_cpuset = calloc(1, sizeof(uint16_t));
                link_config->tx_cpuset[0] = json_number_value(value);
                link_config->tx_cpuset_count = 1;
                link_config->tx_cpuset_cur = 0;
            }
            continue;
        }

        if (!strcmp(key, "lag-interface")) {
            string = strdup(json_string_value(value));
            if(!lag_present(string)) {
                fprintf(stderr, "JSON config error: Missing configuration for lag-interface %s\n", string);
                return false;
            }
            link_config->lag_interface = string;
            link_lag_int_absent = false;
            continue;
        }

        if (!strcmp(key, "lacp-priority")) {
            if (link_lag_int_absent) {
                fprintf(stderr, "JSON config error: Missing configuration for lag-interface %s\n", string);
                return false;
            }
            link_config->lacp_priority = json_number_value(value);
            link_lag_lacp_absent = false;
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in interfaces->links\n",key);
        return false;

    }

    if (link_interface_absent) {
        fprintf(stderr, "JSON config error: Missing value for links->interface\n");
        return false;
    }

    if (link_io_mode_absent) {
        link_config->io_mode = g_ctx->config.io_mode;
    }

    if (link_io_slots_absent) {
        link_config->io_slots_tx = g_ctx->config.io_slots;
        link_config->io_slots_rx = g_ctx->config.io_slots;
    }

    if (link_qdisc_bypass_absent) {
        link_config->qdisc_bypass = g_ctx->config.qdisc_bypass;
    }

    if (link_tx_int_absent) {
        link_config->tx_interval = g_ctx->config.tx_interval;
    }

    if (link_rx_int_absent) {
        link_config->rx_interval = g_ctx->config.rx_interval;
    }

    if (link_tx_threads_absent) {
        link_config->tx_threads = g_ctx->config.tx_threads;
    }

    if (link_rx_threads_absent) {
        link_config->rx_threads = g_ctx->config.rx_threads;
    }

    if (link_lag_lacp_absent) {
        link_config->lacp_priority = 32768;      
    }

    return true;
}

static bool
json_parse_network_interface(json_t *network_interface, bbl_network_config_s *network_config)
{
    const char *key;
    json_t *value = NULL;
    const char *s = NULL;
    ipv4addr_t ipv4 = {0};
    uint16_t number;
    static int8_t net_id = -1;
    ++net_id;

    /*  Flag variables are declared */
    bool net_int_absent = true;
    bool ipv6_ra_absent = true;
    bool mtu_absent = true;
    bool gate_resv_wait_absent = true;
    bool isis_instance_id_absent = true;
    bool isis_level_absent = true;
    bool isis_p2p_absent = true;
    bool isis_l1_absent = true;
    bool isis_l2_absent = true;

    json_object_foreach(network_interface, key, value) {
        
        if (!strcmp(key, "interface")) {
            network_config->interface = strdup(json_string_value(value));
            link_add(network_config->interface);
            net_int_absent = false;
            continue;
        }

        if (!strcmp(key, "address")) {
            if (!scan_ipv4_prefix(json_string_value(value), &network_config->ip)) {
                fprintf(stderr, "JSON config error: Invalid value for network->address\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "gateway")) {
            if(!inet_pton(AF_INET, json_string_value(value), &ipv4)) {
                fprintf(stderr, "JSON config error: Invalid value for network->gateway\n");
                return false;
            }
            network_config->gateway = ipv4;
            continue;
        }

        if (!strcmp(key, "address-ipv6")) {
            if(!scan_ipv6_prefix(json_string_value(value), &network_config->ip6)) {
                fprintf(stderr, "JSON config error: Invalid value for network->address-ipv6\n");
                return false;
            }
            continue;              
        }        

        if (!strcmp(key, "gateway-ipv6")) {
            if(!inet_pton(AF_INET6, json_string_value(value), &network_config->gateway6)) {
                fprintf(stderr, "JSON config error: Invalid value for network->gateway-ipv6\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "ipv6-router-advertisement")) {
            if (json_is_boolean(value)) {
                network_config->ipv6_ra = json_boolean_value(value);
                ipv6_ra_absent = false;
            }
            continue;            
        }

        if (!strcmp(key, "gateway-mac")) {
            s = json_string_value(value);
            if(sscanf(s, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                    &network_config->gateway_mac[0],
                    &network_config->gateway_mac[1],
                    &network_config->gateway_mac[2],
                    &network_config->gateway_mac[3],
                    &network_config->gateway_mac[4],
                    &network_config->gateway_mac[5]) < 6) {
                fprintf(stderr, "JSON config error: Invalid value for network->gateway-mac\n");
                return false;
            }    
            continue;        
        }

        if (!strcmp(key, "vlan")) {
            if(json_is_number(value)) {
                network_config->vlan = json_number_value(value);
                network_config->vlan &= 4095;
            }       
            continue;     
        }

        if (!strcmp(key, "mtu")) {
            if(json_is_number(value)) {
                number = json_number_value(value);
                if (number < 64 || number > 9000) {
                    fprintf(stderr, "JSON config error: Invalid value for network->mtu\n");
                    return false;
                }
                network_config->mtu = number;
                mtu_absent = false;
            }     
            continue;       
        }

        if (!strcmp(key, "gateway-resolve-wait")) {
            if (json_is_boolean(value)) {
                network_config->gateway_resolve_wait = json_boolean_value(value);
                gate_resv_wait_absent = false;
            }
            continue;
        }

        /* IS-IS interface configuration */

        if (!strcmp(key, "isis-instance-id")) {
            if(json_is_number(value)) {
                network_config->isis_instance_id = json_number_value(value);
                isis_instance_id_absent = false;
            }
            continue;
        }

        if (!strcmp(key, "isis-level") && json_is_number(value)) {
            network_config->isis_level = json_number_value(value);
            isis_level_absent = false;
            if (network_config->isis_level < 1 || network_config->isis_level > 3) {
                fprintf(stderr, "JSON config error: Invalid value for network->isis-level (1-3)\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "isis-p2p") && json_is_boolean(value)) {
            network_config->isis_p2p = json_boolean_value(value);
            isis_p2p_absent = false;
            continue;
        }

        if (!strcmp(key, "isis-l1-metric") && json_is_number(value)) {
            network_config->isis_l1_metric = json_number_value(value);
            isis_l1_absent = false;
            continue;
        }

        if (!strcmp(key, "isis-l2-metric") && json_is_number(value)) {
            network_config->isis_l2_metric = json_number_value(value);
            isis_l2_absent = false;
            continue;
        }

        /* LDP interface configuration */
        if (!strcmp(key, "ldp-instance-id") && json_is_number(value)) {
            network_config->ldp_instance_id = json_number_value(value);
            continue;
        }

        /* If any other keys are present */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in interfaces->network[%d]\n",key,net_id);
        return false;

    }

    /*  Block works if isis instance id is present but level isnt  */
    if (!isis_instance_id_absent && isis_level_absent) {
        network_config->isis_level = 3;
    }

    if (!isis_instance_id_absent && isis_p2p_absent) {
        network_config->isis_p2p = true;
    }

    if (!isis_instance_id_absent && isis_l1_absent) {
        network_config->isis_l1_metric = 10;
    }

    if (!isis_instance_id_absent && isis_l2_absent) {
        network_config->isis_l2_metric = 10;
    }

    /* If block gets executed when isis attributes are present 
     * but isis instance id is not present
    */
    if (!(isis_level_absent && isis_p2p_absent && isis_l1_absent && isis_l2_absent) && isis_instance_id_absent ) {
        fprintf(stderr, "Config error: Missing value for network->isis_instance_id\n");
        return false;
    }

    if (gate_resv_wait_absent) {
        network_config->gateway_resolve_wait = true;
    }

    if (mtu_absent) {
        network_config->mtu = 1500;
    }

    if (ipv6_ra_absent) {
        network_config->ipv6_ra = true;
    }

    if (net_int_absent) {
        fprintf(stderr, "JSON config error: Missing value for network->interface\n");
        return false;
    }

    return true;
}

static bool
json_parse_access_interface(json_t *access_interface, bbl_access_config_s *access_config)
{
    const char *key;
    json_t *value = NULL;
    const char *s = NULL;
    uint32_t ipv4;

    access_config->ipv4_enable = true;
    access_config->ipv6_enable = true;

    /* Flag variables are declared */
    bool acc_int_absent = true;
    bool acc_n_int_absent = true;
    bool acc_a_int_absent = true;
    bool acc_o_vlan_absent = true;
    bool acc_i_vlan_absent = true;
    bool acc_o_v_step_absent = true;
    bool acc_i_v_step_absent = true;
    bool acc_cfm_cc_absent = true;
    bool acc_cfm_ma_absent = true;

    /* Default values*/
    access_config->i1 = 1;
    access_config->i1_step = 1;
    access_config->i2 = 1;
    access_config->i2_step = 1;
    access_config->ppp_mru = g_ctx->config.ppp_mru;
    access_config->username = strdup(g_ctx->config.username);
    access_config->password = strdup(g_ctx->config.password);
    access_config->authentication_protocol = g_ctx->config.authentication_protocol;
    if(g_ctx->config.agent_circuit_id) {
        access_config->agent_circuit_id = strdup(g_ctx->config.agent_circuit_id);
    }

    if(g_ctx->config.agent_remote_id) {
        access_config->agent_remote_id = strdup(g_ctx->config.agent_remote_id);
    }
    access_config->rate_up = g_ctx->config.rate_up;
    access_config->rate_down = g_ctx->config.rate_down;
    access_config->dsl_type = g_ctx->config.dsl_type;
    access_config->ipcp_enable = g_ctx->config.ipcp_enable;
    access_config->dhcp_enable = g_ctx->config.dhcp_enable;
    access_config->ip6cp_enable = g_ctx->config.ip6cp_enable;
    access_config->dhcpv6_enable = g_ctx->config.dhcpv6_enable;
    access_config->igmp_autostart = g_ctx->config.igmp_autostart;
    access_config->igmp_version = g_ctx->config.igmp_version;
    access_config->session_traffic_autostart = g_ctx->config.session_traffic_autostart;


    json_object_foreach(access_interface, key, value) {
        if (!strcmp(key, "interface") && json_is_string(value)) {
            access_config->interface = strdup(json_string_value(value));
            link_add(access_config->interface);
            acc_int_absent = false;
            continue;
        }

        if (!strcmp(key, "network-interface") && json_is_string(value)) {
            if (!acc_a_int_absent) {
                fprintf(stderr, "JSON config error: You can't define access->network-interface and access->a10nsp-interface\n");
                return false;
            }
            access_config->network_interface = strdup(json_string_value(value));
            acc_n_int_absent = false;
            continue;
        }

        if (!strcmp(key, "a10nsp-interface") && json_is_string(value)) {
            if (!acc_n_int_absent) {
                fprintf(stderr, "JSON config error: You can't define access->network-interface and access->a10nsp-interface\n");
                return false;
            }
            access_config->a10nsp_interface = strdup(json_string_value(value));
            acc_a_int_absent = false;
            continue;
        }

        if (!strcmp(key, "i1-start") && json_is_number(value)) {
            access_config->i1 = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "i1-step") && json_is_number(value)) {
            access_config->i1_step = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "i2-start") && json_is_number(value)) {
            access_config->i2 = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "i2-step") && json_is_number(value)) {
            access_config->i2_step = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "type") && json_is_string(value)) {
            s = json_string_value(value);
            if (!strcmp(s, "pppoe")) {
                access_config->access_type = ACCESS_TYPE_PPPOE;
            } else if (!strcmp(s, "ipoe")) {
                access_config->access_type = ACCESS_TYPE_IPOE;
                access_config->ipv4_enable = g_ctx->config.ipoe_ipv4_enable;
                access_config->ipv6_enable = g_ctx->config.ipoe_ipv6_enable;               
            } else {
                fprintf(stderr, "JSON config error: Invalid value for access->type\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "vlan-mode")) {
            s = json_string_value(value);
            if (!strcmp(s, "1:1")) {
                access_config->vlan_mode = VLAN_MODE_11;
            } else if (!strcmp(s, "N:1")) {
                access_config->vlan_mode = VLAN_MODE_N1;
            } else {
                fprintf(stderr, "JSON config error: Invalid value for access->vlan-mode\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "monkey") && json_is_boolean(value)) {
            access_config->monkey = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "qinq") && json_is_boolean(value)) {
            access_config->qinq = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "outer-vlan") && json_is_number(value)) {
            access_config->access_outer_vlan_min = (int) json_number_value(value) & 4095;
            access_config->access_outer_vlan_max = access_config->access_outer_vlan_min;
            acc_o_vlan_absent = false;
            continue;
        }

        if (!strcmp(key, "outer-vlan-min") && json_is_number(value) && acc_o_vlan_absent) {
            access_config->access_outer_vlan_min = (int) json_number_value(value) & 4095;
            continue;
        }

        if (!strcmp(key, "outer-vlan-max") && json_is_number(value) && acc_o_vlan_absent) {
            access_config->access_outer_vlan_max = (int) json_number_value(value) & 4095;
            continue;
        }

        if (!strcmp(key, "outer-vlan-step") && json_is_number(value) && acc_o_vlan_absent) {
            access_config->access_outer_vlan_step = json_number_value(value);
            acc_o_v_step_absent = false;
            continue;
        }

        if (!strcmp(key, "inner-vlan") && json_is_number(value)) {
            access_config->access_inner_vlan_min = (int) json_number_value(value) & 4095;
            access_config->access_inner_vlan_max = access_config->access_inner_vlan_min;
            acc_i_vlan_absent = false;
            continue;
        }

        if (!strcmp(key, "inner-vlan-min") && json_is_number(value) && acc_i_vlan_absent) {
            access_config->access_inner_vlan_min = (int) json_number_value(value) & 4095;
            continue;
        }

        if (!strcmp(key, "inner-vlan-max") && json_is_number(value) && acc_i_vlan_absent) {
            access_config->access_inner_vlan_max = (int) json_number_value(value) & 4095;
            continue;
        }

        if (!strcmp(key, "inner-vlan-step") && json_is_number(value) && acc_i_vlan_absent) {
            access_config->access_inner_vlan_step = json_number_value(value);
            acc_i_v_step_absent = false;
            continue;
        }

        if (!strcmp(key, "third-vlan") && json_is_number(value)) {
            access_config->access_third_vlan = (int) json_number_value(value) & 4095;
            continue;
        }

        if (!strcmp(key, "ppp-mru") && json_is_number(value)) {
            access_config->ppp_mru = json_number_value(value);
            continue;
        }

        if(!strcmp(key, "address") && json_is_string(value)) {
            s = json_string_value(value);
            if(!inet_pton(AF_INET, s, &ipv4)) {
                fprintf(stderr, "JSON config error: Invalid value for access->address\n");
                return false;
            }
            access_config->static_ip = ipv4;
            continue;
        }

        if(!strcmp(key, "address-iter") && json_is_string(value)) {
            s = json_string_value(value);
            if(!inet_pton(AF_INET, s, &ipv4)) {
                fprintf(stderr, "JSON config error: Invalid value for access->address-iter\n");
                return false;
            }
            access_config->static_ip_iter = ipv4;
            continue;
        }

        if(!strcmp(key, "gateway") && json_is_string(value)) {
            s = json_string_value(value);
            if(!inet_pton(AF_INET, s, &ipv4)) {
                fprintf(stderr, "JSON config error: Invalid value for access->gateway\n");
                return false;
            }
            access_config->static_gateway = ipv4;
            continue;
        }

        if(!strcmp(key, "gateway-iter") && json_is_string(value)) {
            s = json_string_value(value);
            if(!inet_pton(AF_INET, s, &ipv4)) {
                fprintf(stderr, "JSON config error: Invalid value for access->gateway-iter\n");
                return false;
            }
            access_config->static_gateway_iter = ipv4;
            continue;
        }

        /* Optionally overload some settings per range */
        if (!strcmp(key, "username") && json_is_string(value)) {
            access_config->username = json_string_value(value);
            continue;
        }

        if (!strcmp(key, "password") && json_is_string(value)) {
            access_config->password = json_string_value(value);
            continue;
        }

        if (!strcmp(key, "authentication-protocol") && json_is_string(value)) {
            s = json_string_value(value);
            if (!strcmp(s, "PAP")) {
                access_config->authentication_protocol = PROTOCOL_PAP;
            } else if(!strcmp(s, "CHAP")) {
                access_config->authentication_protocol = PROTOCOL_CHAP;
            } else {
                fprintf(stderr, "Config error: Invalid value for access->authentication-protocol\n");
                return false;
            }
            continue;
        }

        /* Access Line */
        if (!strcmp(key, "agent-circuit-id") && json_is_string(value)) {
            access_config->agent_circuit_id = strdup(json_string_value(value));
            continue;
        }

        if (!strcmp(key, "agent-remote-id") && json_is_string(value)) {
            access_config->agent_remote_id = strdup(json_string_value(value));
            continue;
        }

        if (!strcmp(key, "rate-up") && json_is_number(value)) {
            access_config->rate_up = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "rate-down") && json_is_number(value)) {
            access_config->rate_down = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "dsl-type") && json_is_number(value)) {
            access_config->dsl_type = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "access-line-profile-id") && json_is_number(value)) {
            access_config->access_line_profile_id = json_number_value(value);
            continue;
        }

        /* IPv4 settings */

        if (!strcmp(key,"ipcp") && json_is_boolean(value)) {
            access_config->ipcp_enable = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key,"dhcp") && json_is_boolean(value)) {
            access_config->dhcp_enable = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key,"ipv4") && json_is_boolean(value)) {
            access_config->ipv4_enable = json_boolean_value(value);
            continue;
        }
        
        /* IPv6 settings */

        if (!strcmp(key,"ip6cp") && json_is_boolean(value)) {
            access_config->ip6cp_enable = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key,"dhcpv6") && json_is_boolean(value)) {
            access_config->dhcpv6_enable = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key,"ipv6") && json_is_boolean(value)) {
            access_config->ipv6_enable = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key,"igmp-autostart") && json_is_boolean(value)) {
            access_config->igmp_autostart = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key,"igmp-version") && json_is_number(value)) {
            access_config->igmp_version = json_number_value(value);
            if(access_config->igmp_version < 1 || access_config->igmp_version > 3) {
                fprintf(stderr, "JSON config error: Invalid value for access->igmp-version (1-3)\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key,"session-traffic-autostart") && json_is_boolean(value)) {
            access_config->session_traffic_autostart = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key,"session-group-id") && json_is_number(value)) {
            access_config->session_group_id = json_number_value(value);
            if(access_config->session_group_id >= UINT16_MAX) {
                fprintf(stderr, "JSON config error: Invalid value for access->session-group-id\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key,"stream-group-id") && json_is_number(value)) {
            access_config->stream_group_id = json_number_value(value);
            if(access_config->stream_group_id >= UINT16_MAX) {
                fprintf(stderr, "JSON config error: Invalid value for access->stream-group-id\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key,"cfm-cc") && json_is_boolean(value)) {
            access_config->cfm_cc = json_boolean_value(value);
            acc_cfm_cc_absent = false;
            continue;
        }

        if (!strcmp(key,"cfm-level") && json_is_number(value)) {
            access_config->cfm_level = json_number_value(value);
            if(access_config->cfm_level > 7) {
                fprintf(stderr, "JSON config error: Invalid value for access->cfm-level\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key,"cfm-ma-id") && json_is_number(value)) {
            access_config->cfm_ma_id = json_number_value(value);
            continue;
        }

        if (!strcmp(key,"cfm-ma-name") && json_is_string(value)) {
            access_config->cfm_ma_name = strdup(json_string_value(value));
            acc_cfm_ma_absent = false;
            continue;
        }

        /* If none of the above key values are matched */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in interfaces->access\n", key);
        return false;
    }

    if (acc_int_absent) {
        fprintf(stderr, "JSON config error: Missing value for access->interface\n");
        return false;
    }

    if (acc_o_vlan_absent && acc_o_v_step_absent) {
        access_config->access_outer_vlan_step = 1;
    }

    if (acc_i_vlan_absent && acc_i_v_step_absent) {
        access_config->access_inner_vlan_step = 1;
    }

    if(access_config->access_outer_vlan_min > access_config->access_outer_vlan_max ||
       access_config->access_inner_vlan_min > access_config->access_inner_vlan_max) {
        fprintf(stderr, "JSON config error: Invalid value for access VLAN range (min > max)\n");
        return false;
    }

    /*  IMPORTANT
    *   Previous commit: if (access_config->cfm_cc) {}
    *   Instead of access_config->cfm_ma_name
    */

    if(!acc_cfm_cc_absent && acc_cfm_ma_absent) {
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
    const char *key = NULL;

    json_object_foreach(a10nsp_interface, key, value) {

        if (!strcmp(key, "interface") && json_is_string(value)) {
            a10nsp_config->interface = strdup(json_string_value(value));
            link_add(a10nsp_config->interface);
            continue;
        }

        if (!strcmp(key, "qinq") && json_is_boolean(value)) {
            a10nsp_config->qinq = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "mac") && json_is_string(value)) {
            s = json_string_value(value);
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
            continue;
        }

        /* If none of the above key values are matched */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in interfaces->a10nsp\n", key);
        return false;

    }

    if (a10nsp_config->interface == NULL) {
        fprintf(stderr, "JSON config error: Missing value for a10nsp->interface\n");
        return false;
    }

    return true;
}

static bool
json_parse_bgp_config(json_t *bgp, bgp_config_s *bgp_config)
{
    json_t *value = NULL;
    const char *key = NULL; 
    
    g_ctx->tcp = true;

    /* Default values */
    bgp_config->local_as = BGP_DEFAULT_AS;
    bgp_config->peer_as = bgp_config->local_as;
    bgp_config->hold_time = BGP_DEFAULT_HOLD_TIME;
    bgp_config->id = htobe32(0x01020304);
    bgp_config->reconnect = true;
    bgp_config->start_traffic = false;
    bgp_config->teardown_time = BGP_DEFAULT_TEARDOWN_TIME;

    /* Flag variables*/
    bool bgp_ipv4_peer_absent = true;


    json_object_foreach(bgp, key, value) {

        if (!strcmp(key, "network-interface") && json_is_string(value)) {
            bgp_config->network_interface = strdup(json_string_value(value));
            continue;
        }

        if (!strcmp(key, "local-ipv4-address") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &bgp_config->ipv4_local_address)) {
                fprintf(stderr, "JSON config error: Invalid value for bgp->local-ipv4-address\n");
                return false;
            }
            add_secondary_ipv4(bgp_config->ipv4_local_address);
            continue;
        }

        if (!strcmp(key, "peer-ipv4-address") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &bgp_config->ipv4_peer_address)) {
                fprintf(stderr, "JSON config error: Invalid value for bgp->peer-ipv4-address\n");
                return false;
            }
            bgp_ipv4_peer_absent = false;
            continue;
        }

        if (!strcmp(key, "local-as") && json_is_number(value)) {
            bgp_config->local_as = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "peer-as") && json_is_number(value)) {
            bgp_config->peer_as = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "hold-time") && json_is_number(value)) {
            bgp_config->hold_time = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "id") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &bgp_config->id)) {
                fprintf(stderr, "JSON config error: Invalid value for bgp->id\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "reconnect") && json_is_boolean(value)) {
            bgp_config->reconnect = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "start-traffic") && json_is_boolean(value)) {
            bgp_config->start_traffic = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "teardown-time") && json_is_number(value)) {
            bgp_config->teardown_time = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "raw-update-file") && json_is_string(value)) {
            bgp_config->raw_update_file = strdup(json_string_value(value));
            if(!bgp_raw_update_load(bgp_config->raw_update_file, true)) {
                return false;
            }
            continue;
        }

        /* If none of the above key values are matched */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in bgp\n", key);
        return false;
    }

    if (bgp_ipv4_peer_absent) {
        fprintf(stderr, "JSON config error: Missing value for bgp->peer-ipv4-address\n");
        return false;   
    }

    return true;
}

static bool
json_parse_isis_config(json_t *isis, isis_config_s *isis_config)
{
    json_t *sub, *con, *c, *value = NULL;
    const char *s = NULL;
    int i, size;
    const char *key = NULL;
    const char *conn_key = NULL;
    
    isis_external_connection_s *connection = NULL;

    /* Flag variables */
    bool isis_id_absent = true;
    bool isis_l1_auth_key_absent = true;
    bool isis_l1_auth_type_absent = true;
    bool isis_l1_auth_hello_absent = true;
    bool isis_l1_auth_csnp_absent = true;
    bool isis_l1_auth_psnp_absent = true;
    bool isis_l2_auth_key_absent = true;
    bool isis_l2_auth_type_absent = true;
    bool isis_l2_auth_hello_absent = true;
    bool isis_l2_auth_csnp_absent = true;
    bool isis_l2_auth_psnp_absent = true;
    bool isis_area_absent = true;


    /* Default values */
    isis_config->level = 3;
    isis_config->protocol_ipv4  = true;
    isis_config->protocol_ipv6  = true;
    isis_config->hello_interval = ISIS_DEFAULT_HELLO_INTERVAL;
    isis_config->hold_time = ISIS_DEFAULT_HOLD_TIME;
    isis_config->lsp_lifetime = ISIS_DEFAULT_LSP_LIFETIME;
    isis_config->lsp_refresh_interval = ISIS_DEFAULT_LSP_REFRESH_IVL;
    isis_config->lsp_retry_interval = ISIS_DEFAULT_LSP_RETRY_IVL;
    isis_config->lsp_tx_interval = ISIS_DEFAULT_LSP_TX_IVL_MS;
    isis_config->lsp_tx_window_size = ISIS_DEFAULT_LSP_WINDOWS_SIZE;
    isis_config->csnp_interval = ISIS_DEFAULT_CSNP_INTERVAL;
    isis_config->hostname = g_default_hostname;
    isis_config->router_id_str = g_default_router_id;
    isis_config->system_id_str = g_default_system_id;
    isis_config->teardown_time = ISIS_DEFAULT_TEARDOWN_TIME;


    json_object_foreach(isis, key, value) {

        if (!strcmp(key, "instance-id") && json_is_number(value)) {
            isis_config->id = json_number_value(value);
            isis_id_absent = false;
            continue;
        }

        if (!strcmp(key, "level") && json_is_number(value)) {
            isis_config->level = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "overload") && json_is_boolean(value)) {
            isis_config->overload = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "protocol-ipv4") && json_is_boolean(value)) {
            isis_config->protocol_ipv4 = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "protocol-ipv6") && json_is_boolean(value)) {
            isis_config->protocol_ipv6 = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "level1-auth-key") && json_is_string(value)) {
            isis_config->level1_key = strdup(json_string_value(value));
            isis_l1_auth_key_absent = false;
            continue;
        }

        if (!strcmp(key, "level1-auth-type") && json_is_string(value)) {
            s = strdup(json_string_value(value));
            if (!strcmp(s, "md5")) {
                isis_config->level1_auth = ISIS_AUTH_HMAC_MD5;
            } else if (!strcmp(s, "simple")) {
                isis_config->level1_auth = ISIS_AUTH_CLEARTEXT;
            } else {
                fprintf(stderr, "JSON config error: Invalid value for isis->level1-auth-type\n");
                return false;
            }
            isis_l1_auth_type_absent = false;
            continue;
        }

        if (!strcmp(key, "level1-auth-hello") && json_is_boolean(value)) {
            isis_config->level1_auth_hello = json_boolean_value(value);
            isis_l1_auth_hello_absent = false;
            continue;
        }

        if (!strcmp(key, "level1-auth-psnp") && json_is_boolean(value)) {
            isis_config->level1_auth_psnp = json_boolean_value(value);
            isis_l1_auth_psnp_absent = false;
            continue;
        }

        if (!strcmp(key, "level1-auth-csnp") && json_is_boolean(value)) {
            isis_config->level1_auth_csnp= json_boolean_value(value);
            isis_l1_auth_csnp_absent = false;
            continue;
        }

        if (!strcmp(key, "level2-auth-key") && json_is_string(value)) {
            isis_config->level2_key = strdup(json_string_value(value));
            isis_l2_auth_key_absent = false;
            continue;
        }

        if (!strcmp(key, "level2-auth-type") && json_is_string(value)) {
            s = strdup(json_string_value(value));
            if (!strcmp(s, "md5")) {
                isis_config->level2_auth = ISIS_AUTH_HMAC_MD5;
            } else if (!strcmp(s, "simple")) {
                isis_config->level2_auth = ISIS_AUTH_CLEARTEXT;
            } else {
                fprintf(stderr, "JSON config error: Invalid value for isis->level2-auth-type\n");
                return false;
            }
            isis_l2_auth_type_absent = false;
        }

        if (!strcmp(key, "level2-auth-hello") && json_is_boolean(value)) {
            isis_config->level2_auth_hello = json_boolean_value(value);
            isis_l2_auth_hello_absent = false;
            continue;
        }

        if (!strcmp(key, "level2-auth-psnp") && json_is_boolean(value)) {
            isis_config->level2_auth_psnp = json_boolean_value(value);
            isis_l2_auth_psnp_absent = false;
            continue;
        }

        if (!strcmp(key, "level2-auth-csnp") && json_is_boolean(value)) {
            isis_config->level2_auth_csnp= json_boolean_value(value);
            isis_l2_auth_csnp_absent = false;
            continue;
        }

        if (!strcmp(key, "hello-interval") && json_is_number(value)) {
            isis_config->hello_interval = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "hello-padding") && json_is_boolean(value)) {
            isis_config->hello_padding = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "hold-time") && json_is_number(value)) {
            isis_config->hold_time = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "lsp-lifetime") && json_is_number(value)) {
            isis_config->lsp_lifetime = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "lsp-refresh-interval") && json_is_number(value)) {
            isis_config->lsp_refresh_interval = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "lsp-retry-interval") && json_is_number(value)) {
            isis_config->lsp_retry_interval = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "lsp-tx-interval") && json_is_number(value)) {
            isis_config->lsp_tx_interval = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "hostname") && json_is_string(value)) {
            isis_config->hostname = json_string_value(value);
            continue;
        }

        if (!strcmp(key, "router-id") && json_is_string(value)) {
            isis_config->router_id_str = json_string_value(value);
            continue;
        }

        if (!strcmp(key, "system-id") && json_is_string(value)) {
            isis_config->system_id_str = json_string_value(value);
            continue;
        }

        if (!strcmp(key, "area")) {
            if (json_is_array(value)) {
                isis_config->area_count = json_array_size(value);
                isis_config->area = calloc(isis_config->area_count, sizeof(isis_area_s));
                for(i = 0; i < isis_config->area_count; i++) {
                    if(!isis_str_to_area(json_string_value(json_array_get(value, i)), &isis_config->area[i])) {
                        fprintf(stderr, "JSON config error: Invalid array value for isis->area\n");
                        return false;
                    }
                }                
            } else if(json_is_string(value)) {
                isis_config->area = calloc(1, sizeof(isis_area_s));
                isis_config->area_count = 1;
                if(!isis_str_to_area(json_string_value(value), isis_config->area)) {
                    fprintf(stderr, "JSON config error: Invalid string value for isis->area\n");
                    return false;
                }
            }
            isis_area_absent = false;
            continue;
        }

        if (!strcmp(key, "sr-base") && json_is_number(value)) {
            isis_config->sr_base = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "sr-range") && json_is_number(value)) {
            isis_config->sr_range = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "sr-node-sid") && json_is_number(value)) {
            isis_config->sr_node_sid = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "teardown-time") && json_is_number(value)) {
            isis_config->teardown_time = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "external") && json_is_object(value)) {
            json_object_foreach(value, s, sub) {

                if (!strcmp(s, "mrt-file") && json_is_string(sub)) {
                    isis_config->external_mrt_file = strdup(json_string_value(sub));
                    continue;
                }

                if (!strcmp(s, "connections") && json_is_array(sub)) {
                    size = json_array_size(sub);
                    for(i = 0; i < size; i++) {
                        if(connection) {
                            connection->next = calloc(1, sizeof(isis_external_connection_s));
                            connection = connection->next;
                        } else {
                            connection = calloc(1, sizeof(isis_external_connection_s));
                            isis_config->external_connection = connection;
                        }
                        con = json_array_get(sub, i);
                        bool isis_conn_sys_id_absent = true;
                        connection->level[ISIS_LEVEL_1_IDX].metric = 10;
                        connection->level[ISIS_LEVEL_2_IDX].metric = 10;
                        json_object_foreach(con, conn_key, c) {

                            if (!strcmp(conn_key, "system-id")  && json_is_string(c)) {
                                if(!isis_str_to_system_id(json_string_value(c), connection->system_id)) {
                                    fprintf(stderr, "JSON config error: Invalid value for isis->external->connections->system-id\n");
                                    return false;
                                }
                                isis_conn_sys_id_absent = false;
                                continue;
                            }

                            if (!strcmp(conn_key, "l1-metric") && json_is_number(c)) {
                                connection->level[ISIS_LEVEL_1_IDX].metric = json_number_value(c);
                                continue;
                            }

                            if (!strcmp(conn_key, "l2-metric") && json_is_number(c)) {
                                connection->level[ISIS_LEVEL_2_IDX].metric = json_number_value(c);
                                continue;
                            }

                            /*  Any other keys are present  */
                            if (conn_key[0] == '_')
                                continue;
                            fprintf( stderr, "Config error: Incorrect attribute name (%s) in isis->external->connections[%d]\n",conn_key,i);
                            return false;
                        }
                        if (isis_conn_sys_id_absent) {
                            fprintf(stderr, "JSON config error: Missing value for isis->external->connections->system-id\n");
                            return false;
                        }
                    }
                    continue;
                }

                /*  Any other keys are present  */
                if (s[0] == '_')
                    continue;
                fprintf( stderr, "Config error: Incorrect attribute name (%s) in isis->external\n",s);
                return false;
            }
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in isis\n",key);
        return false;
    }

    if (isis_id_absent) {
        fprintf(stderr, "JSON config error: Missing value for isis->instance-id\n");
        return false;
    }

    if (isis_config->level == 0 || isis_config->level > 3) {
        fprintf(stderr, "JSON config error: Invalid value for isis->level\n");
        return false;
    }

    if (isis_area_absent) {
        isis_config->area = calloc(1, sizeof(isis_area_s));
        isis_config->area_count = 1;
        if(!isis_str_to_area(g_default_area, isis_config->area)) {
            fprintf(stderr, "JSON config error: Invalid value for isis->area\n");
            return false;
        }
    }

    /* Level 1 */
    if (!isis_l1_auth_key_absent && isis_l1_auth_type_absent) {
        isis_config->level1_auth = ISIS_AUTH_NONE;
    }

    if (!isis_l1_auth_type_absent && isis_l1_auth_hello_absent) {
        isis_config->level1_auth_hello  = true;
    }

    if (!isis_l1_auth_type_absent && isis_l1_auth_psnp_absent) {
        isis_config->level1_auth_psnp  = true;
    }

    if (!isis_l1_auth_type_absent && isis_l1_auth_csnp_absent) {
        isis_config->level1_auth_csnp  = true;
    }

    /* Level 2 */
    if (!isis_l2_auth_key_absent && isis_l2_auth_type_absent) {
        isis_config->level2_auth = ISIS_AUTH_NONE;
    }

    if (!isis_l2_auth_type_absent && isis_l2_auth_hello_absent) {
        isis_config->level2_auth_hello  = true;
    }

    if (!isis_l2_auth_type_absent && isis_l2_auth_psnp_absent) {
        isis_config->level2_auth_psnp  = true;
    }

    if (!isis_l2_auth_type_absent && isis_l2_auth_csnp_absent) {
        isis_config->level2_auth_csnp  = true;
    }

    /* ~~~Level 2~~~*/

    if(!inet_pton(AF_INET, isis_config->router_id_str, &isis_config->router_id)) {
        fprintf(stderr, "JSON config error: Invalid value for isis->router-id\n");
        return false;
    }

    if(!isis_str_to_system_id(isis_config->system_id_str, isis_config->system_id)) {
        fprintf(stderr, "JSON config error: Invalid value for isis->system-id\n");
        return false;
    }
    
    return true;
}

static bool
json_parse_ldp_config(json_t *ldp, ldp_config_s *ldp_config)
{
    json_t *value = NULL;
    const char *key = NULL;
    
    g_ctx->tcp = true;

    /* Flag variables */
    bool ldp_inst_id_absent = true;
    bool ldp_ipv4_trans_absent = true;

    /* Default values */
    ldp_config->keepalive_time = LDP_DEFAULT_KEEPALIVE_TIME;
    ldp_config->hold_time = LDP_DEFAULT_HOLD_TIME;
    ldp_config->teardown_time = LDP_DEFAULT_TEARDOWN_TIME;
    ldp_config->hostname = g_default_hostname;
    ldp_config->lsr_id_str = g_default_router_id;

    json_object_foreach(ldp, key, value) {

        if (!strcmp(key, "instance-id") && json_is_number(value)) {
            ldp_config->id = json_number_value(value);
            ldp_inst_id_absent = false;
            continue;
        }

        if (!strcmp(key, "keepalive-time") && json_is_number(value)) {
            ldp_config->keepalive_time = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "hold-time") && json_is_number(value)) {
            ldp_config->hold_time = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "teardown-time") && json_is_number(value)) {
            ldp_config->teardown_time = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "hostname") && json_is_string(value)) {
            ldp_config->hostname = json_string_value(value);
            continue;
        }

        if (!strcmp(key, "lsr-id") && json_is_string(value)) {
            ldp_config->lsr_id_str = json_string_value(value);
            continue;
        }

        if (!strcmp(key, "ipv4-transport-address") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &ldp_config->ipv4_transport_address)) {
                fprintf(stderr, "JSON config error: Invalid value for ldp->ipv4-transport-address\n");
                return false;
            }
            ldp_ipv4_trans_absent = false;
            continue;
        }

        if (!strcmp(key, "raw-update-file") && json_is_string(value)) {
            ldp_config->raw_update_file = strdup(json_string_value(value));
            if(!ldp_raw_update_load(ldp_config->raw_update_file, true)) {
                return false;
            }
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in ldp\n",key);
        return false;

    }

    if (ldp_inst_id_absent) {
        fprintf(stderr, "JSON config error: Missing value for ldp->instance-id\n");
        return false;
    }

    if(!inet_pton(AF_INET, ldp_config->lsr_id_str, &ldp_config->lsr_id)) {
        fprintf(stderr, "JSON config error: Invalid value for ldp->lsr-id\n");
        return false;
    }

    if (ldp_ipv4_trans_absent) {
        ldp_config->ipv4_transport_address = ldp_config->lsr_id;
    }

    return true;
}

static bool
json_parse_stream(json_t *stream, bbl_stream_config_s *stream_config)
{
    json_t *value = NULL;
    const char *s = NULL;
    const char *key = NULL;
    double bps, pps;

    /* Flag Variables */
    bool stream_name_absent = true;
    bool stream_group_id_absent = true;
    bool stream_dir_absent = true;
    bool stream_pps_absent = true;

    /* Default Values */
    stream_config->type = 0;
    stream_config->src_port = BBL_UDP_PORT;
    stream_config->dst_port = BBL_UDP_PORT;
    stream_config->length = 128;
    stream_config->pps = 1;
    stream_config->ipv4_df = true;
    stream_config->tx_mpls1_ttl = 255;
    stream_config->tx_mpls2_ttl = 255;


    json_object_foreach(stream, key, value) {

        if (!strcmp(key, "name") && json_is_string(value)) {
            stream_config->name = strdup(json_string_value(value));
            stream_name_absent = false;
            continue;
        }

        if (!strcmp(key, "stream-group-id") && json_is_number(value)) {
            stream_config->stream_group_id = json_number_value(value);
            if(stream_config->stream_group_id >= UINT16_MAX) {
                fprintf(stderr, "JSON config error: Invalid value for stream->stream-group-id\n");
            }
            stream_group_id_absent = false;
            continue;
        }

        if (!strcmp(key, "type") && json_is_string(value)) {
            s = json_string_value(value);
            if (strcmp(s, "ipv4") == 0) {
                stream_config->type = BBL_SUB_TYPE_IPV4;
            } else if(strcmp(s, "ipv6") == 0) {
                stream_config->type = BBL_SUB_TYPE_IPV6;
            } else if(strcmp(s, "ipv6pd") == 0) {
                stream_config->type = BBL_SUB_TYPE_IPV6PD;
            } else {
                fprintf(stderr, "JSON config error: Invalid value for stream->type\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "direction") && json_is_string(value)) {
            s = json_string_value(value);
            if (strcmp(s, "upstream") == 0) {
                stream_config->direction = BBL_DIRECTION_UP;
            } else if(strcmp(s, "downstream") == 0) {
                stream_config->type = BBL_DIRECTION_DOWN;
            } else if(strcmp(s, "both") == 0) {
                stream_config->type = BBL_DIRECTION_BOTH;
            } else {
                fprintf(stderr, "JSON config error: Invalid value for stream->direction\n");
                return false;
            }
            stream_dir_absent = false;
            continue;
        }

        if (!strcmp(key, "network-interface") && json_is_string(value)) {
            stream_config->network_interface = strdup(json_string_value(value));
            continue;
        }

        if (!strcmp(key, "a10nsp-interface") && json_is_string(value)) {
            stream_config->a10nsp_interface = strdup(json_string_value(value));
            continue;
        }

        if (!strcmp(key, "source-port") && json_is_number(value)) {
            stream_config->src_port = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "destination-port") && json_is_number(value)) {
            stream_config->dst_port = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "length") && json_is_number(value)) {
            stream_config->length = json_number_value(value);
            if(stream_config->length < 76 || 
                stream_config->length > 9000 ||
                stream_config->length > g_ctx->config.io_max_stream_len) {
                    fprintf(stderr, "JSON config error: Invalid value for stream->length (must be between 76 and %u)\n", g_ctx->config.io_max_stream_len);
                    return false;
                }
            continue;
        }

        if (!strcmp(key, "priority") && json_is_number(value)) {
            stream_config->priority = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "vlan-priority") && json_is_number(value)) {
            stream_config->vlan_priority = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "pps") && json_is_number(value)) {
            stream_config->pps = json_number_value(value);
            pps = stream_config->pps;
            stream_pps_absent = false;
            continue;
        }

        if (!strcmp(key, "bps") && json_is_number(value)) {
            bps = json_number_value(value);
            stream_config->pps = bps / (stream_config->length * 8);
            continue;
        }

        if (!strcmp(key, "Kbps") && json_is_number(value)) {
            bps = json_number_value(value);
            stream_config->pps = (bps * 1000) / (stream_config->length * 010);
            continue;
        }

        if (!strcmp(key, "Mbps") && json_is_number(value)) {
            bps = json_number_value(value);
            stream_config->pps = (bps * 1000000) / (stream_config->length * 8);
            continue;
        }

        if (!strcmp(key, "Gbps") && json_is_number(value)) {
            bps = json_number_value(value);
            stream_config->pps = (bps * 1000000000) / (stream_config->length * 8);
            continue;
        }

        if (!strcmp(key, "max-packets") && json_is_number(value)) {
            stream_config->max_packets = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "start-delay") && json_is_number(value)) {
            stream_config->start_delay = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "ldp-ipv4-lookup-address") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &stream_config->ipv4_ldp_lookup_address)) {
                fprintf(stderr, "JSON config error: Invalid value for streams->ldp-ipv4-lookup-address\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "access-ipv4-source-address") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &stream_config->ipv4_access_src_address)) {
                fprintf(stderr, "JSON config error: Invalid value for streams->access-ipv4-source-address\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "access-ipv6-source-address") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &stream_config->ipv6_access_src_address)) {
                fprintf(stderr, "JSON config error: Invalid value for streams->access-ipv6-source-address\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "network-ipv4-address") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &stream_config->ipv4_network_address)) {
                fprintf(stderr, "JSON config error: Invalid value for streams->network-ipv4-address\n");
                return false;
            }
            add_secondary_ipv4(stream_config->ipv4_network_address);
            continue;
        }

        if (!strcmp(key, "network-ipv6-address") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &stream_config->ipv6_network_address)) {
                fprintf(stderr, "JSON config error: Invalid value for streams->network-ipv4-address\n");
                return false;
            }
            add_secondary_ipv6(stream_config->ipv6_network_address);
            continue;
        }

        if (!strcmp(key, "destination-ipv4-address") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &stream_config->ipv4_destination_address)) {
                fprintf(stderr, "JSON config error: Invalid value for streams->destination-ipv4-address\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "destination-ipv6-address") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &stream_config->ipv6_destination_address)) {
                fprintf(stderr, "JSON config error: Invalid value for streams->destination-ipv6-address\n");
                return false;
            }
            continue;
        }

        if(!strcmp(key,"ipv4-df") && json_is_boolean(value)) {
            stream_config->ipv4_df = json_is_boolean(value);
            continue;
        }

        /* MPLS labels */
        if (!strcmp(key, "tx-label1") && json_is_number(value)) {
            stream_config->tx_mpls1 = true;
            stream_config->tx_mpls1_label = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "tx-label1-exp") && json_is_number(value)) {
            stream_config->tx_mpls1_exp = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "tx-label1-ttl") && json_is_number(value)) {
            stream_config->tx_mpls1_ttl = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "tx-label2") && json_is_number(value)) {
            stream_config->tx_mpls2 = true;
            stream_config->tx_mpls2_label = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "tx-label2-exp") && json_is_number(value)) {
            stream_config->tx_mpls2_exp = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "tx-label2-ttl") && json_is_number(value)) {
            stream_config->tx_mpls2_ttl = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "rx-label1") && json_is_number(value)) {
            stream_config->rx_mpls1 = true;
            stream_config->rx_mpls1_label = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "rx-label2") && json_is_number(value)) {
            stream_config->rx_mpls2 = true;
            stream_config->rx_mpls2_label = json_number_value(value);
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in streams\n",key);
        return false;

    }

    if (stream_name_absent) {
        fprintf(stderr, "JSON config error: Missing value for stream->name\n");
        return false;
    }

    if (!stream_config->type) {
        fprintf(stderr, "JSON config error: Missing value for stream->type\n");
        return false;
    }

    if (stream_dir_absent) {
        if (!stream_group_id_absent) {
            stream_config->direction = BBL_DIRECTION_BOTH;
        } else {
            stream_config->direction = BBL_DIRECTION_DOWN;
        }
    }

    if(stream_config->stream_group_id == 0 && stream_config->direction != BBL_DIRECTION_DOWN) {
        fprintf(stderr, "JSON config error: Invalid value for stream->direction (must be downstream for RAW streams)\n");
        return false;
    }

    if(stream_config->network_interface && stream_config->a10nsp_interface) {
        fprintf(stderr, "JSON config error: Not allowed to set stream->network-interface and stream->a10nsp-interface\n");
        return false;
    }

    /* PPS given prirority over BPS */
    if (!stream_pps_absent) {
        stream_config->pps = pps;
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
json_parse_config_streams(json_t *streams)
{
    int i, size;

    bbl_stream_config_s *stream_config = g_ctx->config.stream_config;

    if(json_is_array(streams)) {
        /* Get tail end of stream-config list. */
        if(stream_config) {
            while(stream_config->next) {
                stream_config = stream_config->next;
            }
        }
        /* Config is provided as array (multiple streams) */
        size = json_array_size(streams);
        for(i = 0; i < size; i++) {
            if(!stream_config) {
                g_ctx->config.stream_config = calloc(1, sizeof(bbl_stream_config_s));
                stream_config = g_ctx->config.stream_config;
            } else {
                stream_config->next = calloc(1, sizeof(bbl_stream_config_s));
                stream_config = stream_config->next;
            }
            if(!json_parse_stream(json_array_get(streams, i), stream_config)) {
                return false;
            }
        }
    }
    return true;
}

static bool
json_parse_sessions(json_t *sessions) 
{
    json_t *value = NULL;
    const char *key = NULL;

    json_object_foreach(sessions, key, value) {

        if (!strcmp(key, "count") && json_is_number(value)) {
            g_ctx->config.sessions = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "max-outstanding") && json_is_number(value)) {
            g_ctx->config.sessions_max_outstanding = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "start-rate") && json_is_number(value)) {
            g_ctx->config.sessions_start_rate = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "stop-rate") && json_is_number(value)) {
            g_ctx->config.sessions_stop_rate = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "iterate-vlan-outer") && json_is_boolean(value)) {
            g_ctx->config.iterate_outer_vlan = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "start-delay") && json_is_number(value)) {
            g_ctx->config.sessions_start_delay = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "autostart") && json_is_boolean(value)) {
            g_ctx->config.sessions_autostart = json_boolean_value(value);
            continue;
        }
        
        if (!strcmp(key, "reconnect") && json_is_boolean(value)) {
            g_ctx->config.sessions_reconnect = json_boolean_value(value);
            continue;
        }
        
        if (!strcmp(key, "monkey-autostart") && json_is_boolean(value)) {
            g_ctx->config.monkey_autostart = json_boolean_value(value);
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in sessions\n",key);
        return false;
    }
    return true;
}

static bool
json_parse_ipoe(json_t *ipoe)
{
    json_t *value = NULL;
    const char *key = NULL;

    json_object_foreach(ipoe, key, value) {

        if (!strcmp(key, "ipv6") && json_is_boolean(value)){
            g_ctx->config.ipoe_ipv6_enable = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "ipv4") && json_is_boolean(value)){
            g_ctx->config.ipoe_ipv4_enable = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "arp-timeout") && json_is_number(value)){
            g_ctx->config.arp_timeout = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "arp-interval") && json_is_number(value)){
            g_ctx->config.arp_interval = json_number_value(value);
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in ipoe\n",key);
        return false;
    }
    return true;
}

static bool
json_parse_pppoe(json_t *pppoe)
{
    json_t *value = NULL;
    const char *key = NULL;

    g_ctx->config.pppoe_reconnect = g_ctx->config.sessions_reconnect;

    /* Deprecated ...
    * PPPoE sessions, max-outstanding, start
    * and stop rate was moved to section "sessions"
    * as all those values apply to PPPoE and IPoE
    * but for compatibility they are still supported
    * here as well for some time.
    */

    json_object_foreach(pppoe, key, value) {

        if (!strcmp(key, "sessions") && json_is_number(value)){
            g_ctx->config.sessions = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "max-outstanding") && json_is_number(value)){
            g_ctx->config.sessions_max_outstanding = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "start-rate") && json_is_number(value)){
            g_ctx->config.sessions_start_rate = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "stop-rate") && json_is_number(value)){
            g_ctx->config.sessions_stop_rate = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "session-time") && json_is_number(value)){
            g_ctx->config.pppoe_session_time = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "reconnect") && json_is_boolean(value)){
            g_ctx->config.pppoe_reconnect = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "discovery-timeout") && json_is_number(value)){
            g_ctx->config.pppoe_discovery_timeout = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "discovery-retry") && json_is_number(value)){
            g_ctx->config.pppoe_discovery_retry = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "service-name") && json_is_string(value)){
            g_ctx->config.pppoe_service_name = strdup(json_string_value(value));
            continue;
        }

        if (!strcmp(key, "host-uniq") && json_is_boolean(value)){
            g_ctx->config.pppoe_host_uniq = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "max-payload") && json_is_number(value)){
            g_ctx->config.pppoe_max_payload = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "vlan-priority") && json_is_number(value)){
            g_ctx->config.pppoe_vlan_priority = json_number_value(value);
            if(g_ctx->config.pppoe_vlan_priority > 7) {
                fprintf(stderr, "JSON config error: Invalid value for pppoe->vlan-priority\n");
                return false;
            }
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in pppoe\n",key);
        return false;
    }
    return true;
}

static bool
json_parse_ppp_auth(json_t *ppp_auth)
{
    json_t *value;
    const char *key = NULL;
    const char *s;

    json_object_foreach(ppp_auth, key, value) {

        if (!strcmp(key, "username") && json_is_string(value)) {
            g_ctx->config.username = json_string_value(value);
            continue;
        }

        if (!strcmp(key, "password") && json_is_string(value)) {
            g_ctx->config.password = json_string_value(value);
            continue;
        }

        if (!strcmp(key, "timeout") && json_is_number(value)) {
            g_ctx->config.authentication_timeout = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "retry") && json_is_number(value)) {
            g_ctx->config.authentication_retry = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "protocol") && json_is_string(value)) {
            s = json_string_value(value);
            if(strcmp(s, "PAP") == 0) {
                g_ctx->config.authentication_protocol = PROTOCOL_PAP;
            } else if(strcmp(s, "CHAP") == 0) {
                g_ctx->config.authentication_protocol = PROTOCOL_CHAP;
            } else {
                fprintf(stderr, "JSON config error: Invalid value for ppp->authentication->protocol\n");
                return false;
            }
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in ppp->authentication\n",key);
        return false;
    }
    return true;
}

static bool
json_parse_ppp_lcp(json_t *ppp_lcp)
{
    json_t *value;
    const char *key = NULL;

    json_object_foreach(ppp_lcp, key, value) {

        if (!strcmp(key, "conf-request-timeout") && json_is_number(value)){
            g_ctx->config.lcp_conf_request_timeout = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "conf-request-retry") && json_is_number(value)){
            g_ctx->config.lcp_conf_request_retry = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "keepalive-interval") && json_is_number(value)){
            g_ctx->config.lcp_keepalive_interval = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "keepalive-retry") && json_is_number(value)){
            g_ctx->config.lcp_keepalive_retry = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "start-delay") && json_is_number(value)){
            g_ctx->config.lcp_start_delay = json_number_value(value);
            if(g_ctx->config.lcp_start_delay >= 1000) {
                fprintf(stderr, "JSON config error: ppp->lcp->start-delay must be < 1000\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "ignore-vendor-specific") && json_is_boolean(value)){
            g_ctx->config.lcp_vendor_ignore = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "connection-status-message") && json_is_boolean(value)){
            g_ctx->config.lcp_connection_status_message = json_boolean_value(value);
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in ppp->lcp\n",key);
        return false;
    }
    return true;
}

static bool
json_parse_ppp_ipcp(json_t *ppp_ipcp)
{
    json_t *value;
    const char *key = NULL;

    json_object_foreach(ppp_ipcp, key, value) {

        if (!strcmp(key, "enable") && json_is_boolean(value)){
            g_ctx->config.ipcp_enable = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "request-ip") && json_is_boolean(value)){
            g_ctx->config.ipcp_request_ip = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "request-dns1") && json_is_boolean(value)){
            g_ctx->config.ipcp_request_dns1 = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "request-dns2") && json_is_boolean(value)){
            g_ctx->config.ipcp_request_dns2 = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "conf-request-timeout") && json_is_number(value)){
            g_ctx->config.ipcp_conf_request_timeout = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "conf-request-retry") && json_is_number(value)){
            g_ctx->config.ipcp_conf_request_retry = json_number_value(value);
            continue;
        }
        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in ppp->ipcp\n",key);
        return false;
    }
    return true;
}

static bool
json_parse_ppp_ip6cp(json_t *ppp_ip6cp)
{
    json_t *value;
    const char *key = NULL;

    json_object_foreach(ppp_ip6cp, key, value) {

        if (!strcmp(key, "enable") && json_is_boolean(value)){
            g_ctx->config.ip6cp_enable = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "conf-request-timeout") && json_is_number(value)){
            g_ctx->config.ip6cp_conf_request_timeout = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "conf-request-retry") && json_is_number(value)){
            g_ctx->config.ip6cp_conf_request_retry = json_number_value(value);
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in ppp->ip6cp\n",key);
        return false;
    }
    return true;
}

static bool
json_parse_ppp(json_t *ppp)
{
    json_t *value;
    const char *key = NULL;

    json_object_foreach(ppp, key, value) {

        if (!strcmp(key, "mru") && json_is_number(value)){
            g_ctx->config.ppp_mru = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "authentication") && json_is_object(value)) {
            if (!json_parse_ppp_auth(value))
                return false;
            continue;
        }

        if (!strcmp(key, "lcp") && json_is_object(value)) {
            if (!json_parse_ppp_lcp(value))
                return false;
            continue;
        }

        if (!strcmp(key, "ipcp") && json_is_object(value)) {
            if (!json_parse_ppp_ipcp(value))
                return false;
            continue;
        }

        if (!strcmp(key, "ip6cp") && json_is_object(value)) {
            if (!json_parse_ppp_ip6cp(value))
                return false;
            continue;
        }
        
        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in ppp\n",key);
        return false;
    }
    return true;
}


static bool
json_parse_dhcp(json_t *dhcp)
{
    json_t *value;
    const char *key = NULL;

    json_object_foreach(dhcp, key, value) {

        if (!strcmp(key, "enable") && json_is_boolean(value)){
            g_ctx->config.dhcp_enable = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "broadcast") && json_is_boolean(value)){
            g_ctx->config.dhcp_broadcast = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "timeout") && json_is_number(value)){
            g_ctx->config.dhcp_timeout = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "retry") && json_is_number(value)){
            g_ctx->config.dhcp_retry = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "release-interval") && json_is_number(value)){
            g_ctx->config.dhcp_release_interval = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "release-retry") && json_is_number(value)){
            g_ctx->config.dhcp_release_retry = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "tos") && json_is_number(value)){
            g_ctx->config.dhcp_tos = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "vlan-priority") && json_is_number(value)){
            g_ctx->config.dhcp_vlan_priority = json_number_value(value);
            if(g_ctx->config.dhcp_vlan_priority > 7) {
                fprintf(stderr, "JSON config error: Invalid value for dhcp->vlan-priority\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "access-line") && json_is_boolean(value)){
            g_ctx->config.dhcp_access_line = json_boolean_value(value);
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in dhcp\n",key);
        return false;
    }
    return true;
}

static bool
json_parse_dhcpv6(json_t *dhcpv6)
{
    json_t *value;
    const char *key = NULL;

    json_object_foreach(dhcpv6, key, value) {

        if (!strcmp(key, "enable") && json_is_boolean(value)){
            g_ctx->config.dhcpv6_enable = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "ia-na") && json_is_boolean(value)){
            g_ctx->config.dhcpv6_ia_na = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "ia-pd") && json_is_boolean(value)){
            g_ctx->config.dhcpv6_ia_pd = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "rapid-commit") && json_is_boolean(value)){
            g_ctx->config.dhcpv6_rapid_commit = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "timeout") && json_is_number(value)){
            g_ctx->config.dhcpv6_timeout = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "retry") && json_is_number(value)){
            g_ctx->config.dhcpv6_retry = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "access-line") && json_is_boolean(value)){
            g_ctx->config.dhcpv6_access_line = json_boolean_value(value);
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in dhcpv6\n",key);
        return false;
    }
    return true;
}

static bool
json_parse_igmp(json_t *igmp)
{
    json_t *value;
    const char *key = NULL;
    double number;

    json_object_foreach(igmp, key, value) {

        if (!strcmp(key, "version") && json_is_number(value)){
            g_ctx->config.igmp_version = json_number_value(value);
            if(g_ctx->config.igmp_version < 1 || g_ctx->config.igmp_version > 3) {
                fprintf(stderr, "JSON config error: Invalid value for igmp->version\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "combined-leave-join") && json_is_boolean(value)){
            g_ctx->config.igmp_combined_leave_join = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "autostart") && json_is_boolean(value)){
            g_ctx->config.igmp_autostart = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "start-delay") && json_is_number(value)){
            number = json_number_value(value);
            if(number < 1 || number > UINT16_MAX) {
                fprintf(stderr, "JSON config error: Invalid value for igmp->start-delay\n");
                return false;
            }
            g_ctx->config.igmp_start_delay = number;
            continue;
        }

        if (!strcmp(key, "group") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &g_ctx->config.igmp_group)) {
                fprintf(stderr, "JSON config error: Invalid value for igmp->group\n");
                return false;
            }
        }

        if (!strcmp(key, "group-iter") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &g_ctx->config.igmp_group_iter)) {
                fprintf(stderr, "JSON config error: Invalid value for igmp->group\n");
                return false;
            }
        }

        if (!strcmp(key, "source") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &g_ctx->config.igmp_source)) {
                fprintf(stderr, "JSON config error: Invalid value for igmp->group\n");
                return false;
            }
        }

        if (!strcmp(key, "group-count") && json_is_number(value)){
            g_ctx->config.igmp_group_count = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "zapping-interval") && json_is_number(value)){
            g_ctx->config.igmp_zap_interval = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "zapping-view-duration") && json_is_number(value)){
            g_ctx->config.igmp_zap_view_duration = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "zapping-count") && json_is_number(value)){
            g_ctx->config.igmp_zap_count = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "zapping-wait") && json_is_boolean(value)){
            g_ctx->config.igmp_zap_wait = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "send-multicast-traffic") && json_is_boolean(value)){
            g_ctx->config.send_multicast_traffic = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "multicast-traffic-autostart") && json_is_boolean(value)){
            g_ctx->config.multicast_traffic_autostart = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "multicast-traffic-length") && json_is_number(value)){
            g_ctx->config.multicast_traffic_len = json_number_value(value);
            if(g_ctx->config.multicast_traffic_len > 1500) {
                fprintf(stderr, "JSON config error: Invalid value for igmp->multicast-traffic-length (max 1500)\n");
            }
            continue;
        }

        if (!strcmp(key, "multicast-traffic-tos") && json_is_number(value)){
            g_ctx->config.multicast_traffic_tos = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "multicast-traffic-pps") && json_is_number(value)){
            g_ctx->config.multicast_traffic_pps = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "network-interface") && json_is_string(value)) {
            g_ctx->config.multicast_traffic_network_interface = strdup(json_string_value(value));
            continue;
        }

        if (!strcmp(key, "max-join-delay") && json_is_number(value)){
            g_ctx->config.igmp_max_join_delay = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "robustness-interval") && json_is_number(value)){
            g_ctx->config.igmp_robustness_interval = json_number_value(value);
            continue;
        }
        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in igmp\n",key);
        return false;
    }
    return true;
}

static bool
json_parse_access_line(json_t *access_line)
{
    json_t *value;
    const char *key = NULL;

    json_object_foreach(access_line, key, value) {

        if (!strcmp(key, "agent-circuit-id") && json_is_string(value)) {
            g_ctx->config.agent_circuit_id = json_string_value(value);
            continue;
        }

        if (!strcmp(key, "agent-remote-id") && json_is_string(value)) {
            g_ctx->config.agent_remote_id = json_string_value(value);
            continue;
        }

        if (!strcmp(key, "rate-up") && json_is_number(value)){
            g_ctx->config.rate_up = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "rate-down") && json_is_number(value)){
            g_ctx->config.rate_down = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "dsl-type") && json_is_number(value)){
            g_ctx->config.dsl_type = json_number_value(value);
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in access-line\n",key);
        return false;
    }
    return true;
}

static bool
json_parse_traffic(json_t *traffic)
{
    json_t *value;
    const char *key = NULL;
    double number;

    json_object_foreach(traffic, key, value) {

        if (!strcmp(key, "autostart") && json_is_boolean(value)){
            g_ctx->config.traffic_autostart = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "stop-verified") && json_is_boolean(value)){
            g_ctx->config.traffic_stop_verified = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "max-burst") && json_is_number(value)){
            number = json_number_value(value);
            if(number < 1 || number > UINT8_MAX) {
                fprintf(stderr, "JSON config error: Invalid value for traffic->max-burst\n");
                return false;
            }
            g_ctx->config.stream_max_burst = number;
            continue;
        }

        if (!strcmp(key, "stream-rate-calculation") && json_is_boolean(value)){
            g_ctx->config.stream_rate_calc = json_boolean_value(value);
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in traffic\n",key);
        return false;
    }
    return true;
}

static bool
json_parse_session_traffic(json_t *sess_traffic)
{
    json_t *value;
    const char *key = NULL;

    json_object_foreach(sess_traffic, key, value) {

        if (!strcmp(key, "autostart") && json_is_boolean(value)){
            g_ctx->config.session_traffic_autostart = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "ipv4-pps") && json_is_number(value)){
            g_ctx->config.session_traffic_ipv4_pps = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "ipv6-pps") && json_is_number(value)){
            g_ctx->config.session_traffic_ipv6_pps = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "ipv6pd-pps") && json_is_number(value)){
            g_ctx->config.session_traffic_ipv6pd_pps = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "ipv4-label") && json_is_number(value)){
            g_ctx->config.session_traffic_ipv4_label = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "ipv4-address") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &g_ctx->config.session_traffic_ipv4_address)) {
                fprintf(stderr, "JSON config error: Invalid value for session-traffic->ipv4-address\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "ipv6-label") && json_is_number(value)){
            g_ctx->config.session_traffic_ipv6_label = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "ipv6-address") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &g_ctx->config.session_traffic_ipv6_address)) {
                fprintf(stderr, "JSON config error: Invalid value for session-traffic->ipv4-address\n");
                return false;
            }
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in session-traffic\n",key);
        return false;
    }
    return true;
}

static bool
json_parse_interfaces(  json_t *interfaces , 
                        bbl_lag_config_s *lag_config,
                        bbl_link_config_s *link_config,
                        bbl_network_config_s  *network_config,
                        bbl_access_config_s *access_config,
                        bbl_a10nsp_config_s *a10nsp_config)
{
    json_t *value;
    const char *key = NULL;
    const char *s = NULL;
    int size;
    int i;

    /* Flag variables*/
    bool int_io_mode_absent = true;

    /* Default Values*/

    json_object_foreach(interfaces, key, value) {

        if (!strcmp(key, "io-mode") && json_is_string(value)) {
            if (!strcmp(s, "packet_mmap_raw")) {
                g_ctx->config.io_mode = IO_MODE_PACKET_MMAP_RAW;
                io_packet_mmap_set_max_stream_len();
            } else if(strcmp(s, "packet_mmap") == 0) {
                g_ctx->config.io_mode = IO_MODE_PACKET_MMAP;
                io_packet_mmap_set_max_stream_len();
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
            int_io_mode_absent = false;
            continue;
        }

        if (!strcmp(key, "io-slots") && json_is_number(value)){
            g_ctx->config.io_slots = json_number_value(value);
            if(g_ctx->config.io_slots < 32 || g_ctx->config.io_slots >= UINT16_MAX) {
                fprintf(stderr, "JSON config error: Invalid value for interfaces->io-slots\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "qdisc-bypass") && json_is_boolean(value)){
            g_ctx->config.qdisc_bypass = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "tx-interval") && json_is_number(value)){
            g_ctx->config.tx_interval = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "rx-interval") && json_is_number(value)){
            g_ctx->config.rx_interval = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "tx-threads") && json_is_number(value)){
            g_ctx->config.tx_threads = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "rx-threads") && json_is_number(value)){
            g_ctx->config.rx_threads = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "capture-include-streams") && json_is_boolean(value)){
            g_ctx->pcap.include_streams = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "mac-modifier") && json_is_number(value)){
            if(json_number_value(value) < 0 || json_number_value(value) > UINT8_MAX) {
                fprintf(stderr, "Config error: Invalid value for interfaces->mac-modifier\n");
                return false;
            }
            g_ctx->config.mac_modifier = json_number_value(value);
            continue;
        }

        /* LAG Configuration Section */
        if (!strcmp(key, "lag")) {
            if(json_is_array(value)) {
                /* Config is provided as array (multiple LAG) */
                size = json_array_size(value);
                for(i = 0; i < size; i++) {
                    if(!lag_config) {
                        g_ctx->config.lag_config = calloc(1, sizeof(bbl_lag_config_s));
                        lag_config = g_ctx->config.lag_config;
                    } else {
                        lag_config->next = calloc(1, sizeof(bbl_lag_config_s));
                        lag_config = lag_config->next;
                    }
                    if(!json_parse_lag(json_array_get(value, i), lag_config)) {
                        return false;
                    }
                }
            } else if(json_is_object(value)) {
                /* Config is provided as object (single LAG) */
                lag_config = calloc(1, sizeof(bbl_lag_config_s));
                if(!g_ctx->config.lag_config) {
                    g_ctx->config.lag_config = lag_config;
                }
                if(!json_parse_lag(value, lag_config)) {
                    return false;
                }
            }
            continue;
        }

        /* Links Configuration Section */
        if (!strcmp(key, "links")) {
            if(json_is_array(value)) {
                /* Config is provided as array (multiple links) */
                size = json_array_size(value);
                for(i = 0; i < size; i++) {
                    if(!link_config) {
                        g_ctx->config.link_config = calloc(1, sizeof(bbl_link_config_s));
                        link_config = g_ctx->config.link_config;
                    } else {
                        link_config->next = calloc(1, sizeof(bbl_link_config_s));
                        link_config = link_config->next;
                    }
                    if(!json_parse_link(json_array_get(value, i), link_config)) {
                        return false;
                    }
                }
            } else if(json_is_object(value)) {
                /* Config is provided as object (single network interface) */
                link_config = calloc(1, sizeof(bbl_link_config_s));
                if(!g_ctx->config.link_config) {
                    g_ctx->config.link_config = link_config;
                }
                if(!json_parse_link(value, link_config)) {
                    return false;
                }
            }
            continue;
        }

        /* Network Interface Configuration Section */
        if (!strcmp(key, "network")) {
            if(json_is_array(value)) {
                /* Config is provided as array (multiple network interfaces) */
                size = json_array_size(value);
                for(i = 0; i < size; i++) {
                    if(!network_config) {
                        g_ctx->config.network_config = calloc(1, sizeof(bbl_network_config_s));
                        network_config = g_ctx->config.network_config;
                    } else {
                        network_config->next = calloc(1, sizeof(bbl_network_config_s));
                        network_config = network_config->next;
                    }
                    if(!json_parse_network_interface(json_array_get(value, i), network_config)) {
                        return false;
                    }
                }
            } else if(json_is_object(value)) {
                /* Config is provided as object (single network interface) */
                network_config = calloc(1, sizeof(bbl_network_config_s));
                if(!g_ctx->config.network_config) {
                    g_ctx->config.network_config = network_config;
                }
                if(!json_parse_network_interface(value, network_config)) {
                    return false;
                }
            }
            continue;
        }

        /* Access Interface Configuration Section */
        if (!strcmp(key, "access")) {
            if(json_is_array(value)) {
                /* Config is provided as array (multiple access ranges) */
                size = json_array_size(value);
                for(i = 0; i < size; i++) {
                    if(!access_config) {
                        g_ctx->config.access_config = calloc(1, sizeof(bbl_access_config_s));
                        access_config = g_ctx->config.access_config;
                    } else {
                        access_config->next = calloc(1, sizeof(bbl_access_config_s));
                        access_config = access_config->next;
                    }
                    if(!json_parse_access_interface(json_array_get(value, i), access_config)) {
                        return false;
                    }
                }
            } else if(json_is_object(value)) {
                /* Config is provided as object (single access range) */
                access_config = calloc(1, sizeof(bbl_access_config_s));
                if(!g_ctx->config.access_config) {
                    g_ctx->config.access_config = access_config;
                }
                if(!json_parse_access_interface(value, access_config)) {
                    return false;
                }
            }
            continue;
        }

        /* A10NSP Interface Configuration Section */
        if (!strcmp(key, "a10nsp")) {
            if(json_is_array(value)) {
                /* Config is provided as array (multiple a10nsp interfaces) */
                size = json_array_size(value);
                for(i = 0; i < size; i++) {
                    if(!a10nsp_config) {
                        g_ctx->config.a10nsp_config = calloc(1, sizeof(bbl_a10nsp_config_s));
                        a10nsp_config = g_ctx->config.a10nsp_config;
                    } else {
                        a10nsp_config->next = calloc(1, sizeof(bbl_a10nsp_config_s));
                        a10nsp_config = a10nsp_config->next;
                    }
                    if(!json_parse_a10nsp_interface(json_array_get(value, i), a10nsp_config)) {
                        return false;
                    }
                }
            } else if(json_is_object(value)) {
                /* Config is provided as object (single a10nsp interface) */
                a10nsp_config = calloc(1, sizeof(bbl_a10nsp_config_s));
                if(!g_ctx->config.a10nsp_config) {
                    g_ctx->config.a10nsp_config = a10nsp_config;
                }
                if(!json_parse_a10nsp_interface(value, a10nsp_config)) {
                    return false;
                }
            }
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in interfaces\n",key);
        return false;
    }

    if (int_io_mode_absent) {
        g_ctx->config.io_mode = IO_MODE_PACKET_MMAP_RAW;
        io_packet_mmap_set_max_stream_len();
    }

    return true;
}

static bool
json_parse_l2tp(json_t *l2tp, bbl_l2tp_server_s *l2tp_server)
{
    json_t *value;
    const char *key = NULL;
    const char *s = NULL;
    double number;

    /* Flag variables */
    bool l2tp_name_absent = true;
    bool l2tp_address_absent = true;

    /* Default variables */
    l2tp_server->receive_window = 16;
    l2tp_server->max_retry = 5;
    l2tp_server->congestion_mode = BBL_L2TP_CONGESTION_DEFAULT;
    l2tp_server->hello_interval = 30;

    json_object_foreach(l2tp, key, value) {

        if (!strcmp(key, "name") && json_is_string(value)) {
            l2tp_server->host_name = strdup(json_string_value(value));
            l2tp_name_absent = false;
            continue;
        }

        if (!strcmp(key, "secret") && json_is_string(value)) {
            l2tp_server->secret = strdup(json_string_value(value));
            continue;
        }

        if (!strcmp(key, "address") && json_is_string(value)) {
            if(!inet_pton(AF_INET, json_string_value(value), &l2tp_server->ip)) {
                    fprintf(stderr, "JSON config error: Invalid value for l2tp-server->address\n");
                    return false;
            }
            CIRCLEQ_INIT(&l2tp_server->tunnel_qhead);
            add_secondary_ipv4(l2tp_server->ip);
            l2tp_address_absent = false;
            continue;
        }

        if (!strcmp(key, "receive-window-size") && json_is_number(value)) {
            number = json_number_value(value);
            if(number < 1 || number > UINT16_MAX) {
                fprintf(stderr, "JSON config error: Invalid value for l2tp-server->receive-window-size\n");
                return false;
            }
            l2tp_server->receive_window = number;
            continue;
        }

        if (!strcmp(key, "max-retry") && json_is_number(value)) {
            if(json_number_value(value) < 1 || json_number_value(value) > UINT16_MAX) {
                fprintf(stderr, "JSON config error: Invalid value for l2tp-server->max-retry\n");
                return false;
            }
            l2tp_server->max_retry = json_number_value(value);
            continue;
        }

        if (!strcmp(key, "congestion-mode") && json_is_string(value)) {
            s = json_string_value(value);
            if (!strcmp(s, "default")) {
                l2tp_server->congestion_mode = BBL_L2TP_CONGESTION_DEFAULT;
            } else if (!strcmp(s, "slow")) {
                l2tp_server->congestion_mode = BBL_L2TP_CONGESTION_SLOW;
            } else if (!strcmp(s, "aggressive")) {
                l2tp_server->congestion_mode = BBL_L2TP_CONGESTION_AGGRESSIVE;
            } else {
                fprintf(stderr, "Config error: Invalid value for l2tp-server->congestion-mode\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "data-control-priority") && json_is_boolean(value)){
            l2tp_server->data_control_priority = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "data-length") && json_is_boolean(value)){
            l2tp_server->data_length = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "data-offset") && json_is_boolean(value)){
            l2tp_server->data_offset = json_boolean_value(value);
            continue;
        }

        if (!strcmp(key, "data-control-tos") && json_is_number(value)) {
            l2tp_server->data_control_tos = json_number_value(value);
            if(json_number_value(value) < 1 || json_number_value(value) > UINT8_MAX) {
                fprintf(stderr, "JSON config error: Invalid value for l2tp-server->data-control-tos\n");
                return false;
            }
            continue;
        }

        if (!strcmp(key, "control-tos") && json_is_number(value)) {
            l2tp_server->control_tos = json_number_value(value);
            if(json_number_value(value) < 1 || json_number_value(value) > UINT8_MAX) {
                    fprintf(stderr, "JSON config error: Invalid value for l2tp-server->control-tos\n");
                    return false;
                }
            continue;
        }

        if (!strcmp(key, "hello-interval") && json_is_number(value)) {
            l2tp_server->hello_interval = json_number_value(value);
            if(json_number_value(value) < 1 || json_number_value(value) > UINT16_MAX) {
                    fprintf(stderr, "JSON config error: Invalid value for l2tp-server->hello-interval\n");
                    return false;
                }
            continue;
        }

        if (!strcmp(key, "lcp-padding") && json_is_number(value)){
            l2tp_server->lcp_padding = json_number_value(value);
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s) in l2tp-server\n",key);
        return false;
    }

    if (l2tp_name_absent) {
        fprintf(stderr, "JSON config error: Missing value for l2tp-server->name\n");
        return false;
    }

    if (l2tp_address_absent) {
        fprintf(stderr, "JSON config error: Missing value for l2tp-server->address\n");
        return false;
    }
    return true;
}

static bool
json_parse_config(json_t *root)
{
    json_t *section, *sub;
    const char *s;
    const char *key = NULL;
    int i, size;

    /* Flag variables */
    bool conf_inter_absent = true;

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

    /* Check keys in root config */
    json_object_foreach(root, key, section) {

        if (!strcmp(key, "sessions") && json_is_object(section)) {
            if (!json_parse_sessions(section))
                return false;
            continue;
        }

        if (!strcmp(key, "ipoe") && json_is_object(section)) {
            if (!json_parse_ipoe(section))
                return false;
            continue;
        }
        
        if (!strcmp(key, "pppoe") && json_is_object(section)) {
            if (!json_parse_pppoe(section))
                return false;
            continue;
        }

        if (!strcmp(key, "ppp") && json_is_object(section)) {
            if (!json_parse_ppp(section))
                return false;
            continue;
        }
        
        if (!strcmp(key, "dhcp") && json_is_object(section)) {
            if (!json_parse_dhcp(section))
                return false;
            continue;
        }

        if (!strcmp(key, "dhcpv6") && json_is_object(section)) {
            if (!json_parse_dhcpv6(section))
                return false;
            continue;
        }

        if (!strcmp(key, "igmp") && json_is_object(section)) {
            if (!json_parse_igmp(section))
                return false;
            continue;
        }

        if (!strcmp(key, "access-line") && json_is_object(section)) {
            if (!json_parse_access_line(section))
                return false;
            continue;
        }

        if (!strcmp(key, "access-line-profiles") && json_is_array(section)) {
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
            continue;
        }

        if (!strcmp(key, "traffic") && json_is_object(section)) {
            if (!json_parse_traffic(section))
                return false;
            continue;
        }

        if (!strcmp(key, "session-traffic") && json_is_object(section)) {
            if (!json_parse_session_traffic(section))
                return false;
            continue;
        }

        if (!strcmp(key, "interfaces") && json_is_object(section)) {
            if (!json_parse_interfaces( section, 
                                        lag_config, 
                                        link_config,
                                        network_config,
                                        access_config,
                                        a10nsp_config))
                return false;
            conf_inter_absent = false;
            continue;
        }

        if (!strcmp(key, "l2tp-server")) {
            if (json_is_array(section)) {
                if(!g_ctx->config.network_config) {
                    fprintf(stderr, "JSON config error: Failed to add L2TP server because of missing or incomplete network interface config\n");
                    return false;
                }
                size = json_array_size(section);
                for (i = 0; i < size; i++) {
                    sub = json_array_get(section, i);
                    if (!l2tp_server) {
                        g_ctx->config.l2tp_server = calloc(1, sizeof(bbl_l2tp_server_s));
                        l2tp_server = g_ctx->config.l2tp_server;
                    } else {
                        l2tp_server->next = calloc(1, sizeof(bbl_l2tp_server_s));
                        l2tp_server = l2tp_server->next;
                    }
                    if (!json_parse_l2tp(sub, l2tp_server))
                        return false;
                }
            } else if(json_is_object(section)) {
                fprintf(stderr, "JSON config error: List expected in L2TP server configuration but dictionary found\n");
            }
            continue;
        }

        if (!strcmp(key, "streams")) {
            if(!json_parse_config_streams(section)) {
                return false;
            }
            continue;
        }

        if (!strcmp(key, "isis")) {
            if(json_is_array(section)) {
                /* Config is provided as array (multiple IS-IS instances) */
                size = json_array_size(section);
                for(i = 0; i < size; i++) {
                    if(!isis_config) {
                        g_ctx->config.isis_config = calloc(1, sizeof(isis_config_s));
                        isis_config = g_ctx->config.isis_config;
                    } else {
                        isis_config->next = calloc(1, sizeof(isis_config_s));
                        isis_config = isis_config->next;
                    }
                    if(!json_parse_isis_config(json_array_get(section, i), isis_config)) {
                        return false;
                    }
                }
            } else if(json_is_object(section)) {
                /* Config is provided as object (single IS-IS instance) */
                isis_config = calloc(1, sizeof(isis_config_s));
                if(!g_ctx->config.isis_config) {
                    g_ctx->config.isis_config = isis_config;
                }
                if(!json_parse_isis_config(section, isis_config)) {
                    return false;
                }
            }
            continue;
        }

        /* Pre-Load LDP RAW update files */
        if (!strcmp(key, "ldp-raw-update-files") && json_is_array(section)) {
            size = json_array_size(section);
            for(i = 0; i < size; i++) {
                s = json_string_value(json_array_get(section, i));
                if(s) {
                    if(!ldp_raw_update_load(s, true)) {
                        return false;
                    }
                }
            }
            continue;
        }

        if (!strcmp(key, "ldp") && json_is_object(section)) {
            if(json_is_array(section)) {
                /* Config is provided as array (multiple LDP instances) */
                size = json_array_size(section);
                for(i = 0; i < size; i++) {
                    if(!ldp_config) {
                        g_ctx->config.ldp_config = calloc(1, sizeof(ldp_config_s));
                        ldp_config = g_ctx->config.ldp_config;
                    } else {
                        ldp_config->next = calloc(1, sizeof(ldp_config_s));
                        ldp_config = ldp_config->next;
                    }
                    if(!json_parse_ldp_config(json_array_get(section, i), ldp_config)) {
                        return false;
                    }
                }
            } else if(json_is_object(section)) {
                /* Config is provided as object (single LDP instance) */
                ldp_config = calloc(1, sizeof(ldp_config_s));
                if(!g_ctx->config.ldp_config) {
                    g_ctx->config.ldp_config = ldp_config;
                }
                if(!json_parse_ldp_config(section, ldp_config)) {
                    return false;
                }
            }
            continue;        
        }

        if (!strcmp(key, "bgp")) {
            if(json_is_array(section)) {
                /* Config is provided as array (multiple BGP sessions) */
                size = json_array_size(section);
                for(i = 0; i < size; i++) {
                    if(!bgp_config) {
                        g_ctx->config.bgp_config = calloc(1, sizeof(bgp_config_s));
                        bgp_config = g_ctx->config.bgp_config;
                    } else {
                        bgp_config->next = calloc(1, sizeof(bgp_config_s));
                        bgp_config = bgp_config->next;
                    }
                    if(!json_parse_bgp_config(json_array_get(section, i), bgp_config)) {
                        return false;
                    }
                }
            } else if(json_is_object(section)) {
                /* Config is provided as object (single BGP session) */
                bgp_config = calloc(1, sizeof(bgp_config_s));
                if(!g_ctx->config.bgp_config) {
                    g_ctx->config.bgp_config = bgp_config;
                }
                if(!json_parse_bgp_config(section, bgp_config)) {
                    return false;
                }
            }
            continue;
        }

        /* Pre-Load BGP RAW update files */
        if (!strcmp(key, "bgp-raw-update-files") && json_is_array(section)) {
            size = json_array_size(section);
            for(i = 0; i < size; i++) {
                s = json_string_value(json_array_get(section, i));
                if(s) {
                    if(!bgp_raw_update_load(s, true)) {
                        return false;
                    }
                }
            }
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Incorrect attribute name (%s)\n",key);
        return false;
    }

    if (conf_inter_absent) {
        fprintf(stderr, "JSON config error: Missing interfaces section\n");
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
    const char *key = NULL;
    json_t *value;

    root = json_load_file(filename, 0, &error);
    if (!root) {
        fprintf(stderr, "JSON stream config error: File %s Line %d: %s\n", filename, error.line, error.text);
    }
    json_object_foreach(root, key, value) {
        
        if (!strcmp(key, "streams")) {
            result = json_parse_config_streams(value);
            continue;
        }

        /*  Any other keys are present  */
        if (key[0] == '_')
            continue;
        fprintf( stderr, "Config error: Only attribute should be root->streams\n");
        return false;

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
    g_ctx->config.io_max_stream_len = 9000;
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
    g_ctx->config.dhcp_enable = true;
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