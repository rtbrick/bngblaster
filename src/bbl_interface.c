/*
 * BNG Blaster (BBL) - Interfaces
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"
#include "bbl_io.h"
#include <sys/stat.h>

/**
 * bbl_interface_lock
 *
 * @brief This functions locks the interface 
 * creating the file "/tmp/bngblaster_<interface>.lock".
 * 
 * @param ctx global context
 * @param interface interface
 * @return false if failed to lock (e.g. in use)
 */
static bool
bbl_interface_lock(bbl_ctx_s *ctx, char *interface_name) 
{
    FILE *lock_file;
    char  lock_path[FILE_PATH_LEN];
    int   lock_pid;
    char  proc_pid_path[FILE_PATH_LEN];

    struct stat sts;
    pid_t pid = getpid();

    snprintf(lock_path, sizeof(lock_path), "/tmp/bngblaster_%s.lock", interface_name);
    lock_file = fopen(lock_path, "r");
    if(lock_file) {
        // lock file exists
        if(fscanf(lock_file,"%d", &lock_pid) == 1 && lock_pid > 1) {
            snprintf(proc_pid_path, sizeof(proc_pid_path), "/proc/%d", lock_pid);
            if (!(stat(proc_pid_path, &sts) == -1 && errno == ENOENT)) {
                LOG(ERROR, "Interface %s in use by process %d (%s)\n", interface_name, lock_pid, lock_path);
                if(!ctx->config.interface_lock_force) return false;
            }
        } else {
            LOG(ERROR, "Invalid interface lock file %s\n", lock_path);
            if(!ctx->config.interface_lock_force) return false;
        }
        fclose(lock_file);
    }
    /* crate lock file */
    lock_pid = pid;
    lock_file = fopen(lock_path, "w");
    if(!lock_file) {
        LOG(ERROR, "Failed to open interface lock file %s\n", lock_path);
        return false;
    }
    fprintf(lock_file, "%d", lock_pid);
    fclose(lock_file);
    return true;
}

/**
 * bbl_interface_unlock_all
 *
 * @brief This functions unlocks all interfaces.
 *
 * @param ctx global context
 */
void
bbl_interface_unlock_all(bbl_ctx_s *ctx)
{
    char lock_path[FILE_PATH_LEN];
    for(int i = 0; i < ctx->interfaces.count; i++) {
        snprintf(lock_path, sizeof(lock_path), "/tmp/bngblaster_%s.lock", ctx->interfaces.names[i]);
        remove(lock_path);
    }
}

/**
 * bbl_add_interface
 *
 * @param ctx global context
 * @param interface interface name
 * @return interface
 */
static bbl_interface_s *
bbl_add_interface(bbl_ctx_s *ctx, char *interface_name)
{
    bbl_interface_s *interface;
    struct ifreq ifr;

    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);

    if(!bbl_interface_lock(ctx, interface_name)) {
        return NULL;
    }

    interface = calloc(1, sizeof(bbl_interface_s));
    if (!interface) {
        LOG(ERROR, "No memory for interface %s\n", interface_name);
        return NULL;
    }

    interface->name = strdup(interface_name);
    interface->ctx = ctx;
    CIRCLEQ_INSERT_TAIL(&ctx->interface_qhead, interface, interface_qnode);

    interface->pcap_index = ctx->pcap.index;
    ctx->pcap.index++;

    ctx->interfaces.names[ctx->interfaces.count++] = interface->name;

    /*
     * TX list init.
     */
    CIRCLEQ_INIT(&interface->session_tx_qhead);
    CIRCLEQ_INIT(&interface->l2tp_tx_qhead);

    /*
     * Obtain the interface MAC address.
     */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface_name);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        LOG(ERROR, "Getting MAC address error %s (%d) for interface %s\n",
            strerror(errno), errno, interface->name);
        return NULL;
    }
    memcpy(&interface->mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);

    /*
     * Obtain the interface index.
     */
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        LOG(ERROR, "Get interface index error %s (%d) for interface %s\n",
            strerror(errno), errno, interface->name);
        return NULL;
    }
    interface->ifindex = ifr.ifr_ifindex;

    /* The BNG Blaster supports multiple IO modes where packet_mmap is
     * selected per default. */
    if(!bbl_io_add_interface(ctx, interface)) {
        LOG(ERROR, "Failed to add interface %s\n", interface->name);
        return NULL;
    }

    /*
     * Timer to compute periodic rates.
     */
    timer_add_periodic(&ctx->timer_root, &interface->rate_job, "Rate Computation", 1, 0, interface,
                       &bbl_compute_interface_rate_job);

    return interface;
}

/**
 * bbl_interface_present
 * 
 * @param ctx global context
 * @param interface_name interface name
 * @return true if interface is already added
 */
static bool
bbl_interface_present(bbl_ctx_s *ctx, char *interface_name)
{
    for(int i = 0; i < ctx->interfaces.count; i++) {
        if (strcmp(ctx->interfaces.names[i], interface_name) == 0) {
            return true;
        }
    }
    return false;
}

/**
 * bbl_add_access_interfaces
 *
 * @param ctx global context
 */
static bool
bbl_add_access_interfaces(bbl_ctx_s *ctx)
{
    bbl_access_config_s *access_config = ctx->config.access_config;
    struct bbl_interface_ *access_if;
    int i;

    while(access_config) {
        for(i = 0; i < ctx->interfaces.access_if_count; i++) {
            if(ctx->interfaces.access_if[i]->name) {
                if (strcmp(ctx->interfaces.access_if[i]->name, access_config->interface) == 0) {
                    /* Interface already added! */
                    access_config->access_if = ctx->interfaces.access_if[i];
                    goto NEXT;
                }
            }
        }
        access_if = bbl_add_interface(ctx, access_config->interface);
        if (!access_if) {
            LOG(ERROR, "Failed to add access interface %s\n", access_config->interface);
            return false;
        }
        access_if->type = INTERFACE_TYPE_ACCESS;
        access_config->access_if = access_if;
        if(ctx->interfaces.access_if_count < BBL_MAX_INTERFACES) {
            ctx->interfaces.access_if[ctx->interfaces.access_if_count++] = access_if;
        } else {
            LOG(ERROR, "Failed to add access interface %s (limit reached)\n", access_config->interface);
            return false;
        }
        bbl_send_init_interface(access_if, BBL_SEND_DEFAULT_SIZE);
NEXT:
        access_config = access_config->next;
    }
    return true;
}

/**
 * bbl_add_network_interfaces
 *
 * @param ctx global context
 */
static bool
bbl_add_network_interfaces(bbl_ctx_s *ctx)
{
    bbl_network_config_s *network_config = ctx->config.network_config;
    struct bbl_interface_ *network_if;

    while(network_config) {
        if(bbl_interface_present(ctx, network_config->interface)) {
            LOG(ERROR, "Failed to add network interface %s (already added)\n", network_config->interface);
            return false;
        }
        network_if = bbl_add_interface(ctx, network_config->interface);
        if (!network_if) {
            LOG(ERROR, "Failed to add network interface %s\n", network_config->interface);
            return false;
        }
        network_if->type = INTERFACE_TYPE_NETWORK;
        network_config->network_if = network_if;
        if(ctx->interfaces.network_if_count < BBL_MAX_INTERFACES) {
            ctx->interfaces.network_if[ctx->interfaces.network_if_count++] = network_if;
        } else {
            LOG(ERROR, "Failed to add network interface %s (limit reached)\n", network_config->interface);
            return false;
        }

        bbl_send_init_interface(network_if, BBL_SEND_DEFAULT_SIZE);

        /* Init ethernet */
        network_if->vlan = network_config->vlan;

        /* Copy gateway MAC from config (default 00:00:00:00:00:00) */
        memcpy(network_if->gateway_mac, network_config->gateway_mac, ETH_ADDR_LEN);

        /* Init IPv4 */
        if(network_config->ip && network_config->gateway) {
            network_if->ip = network_config->ip;
            network_if->gateway = network_config->gateway;
            /* Send initial ARP request */
            network_if->send_requests |= BBL_IF_SEND_ARP_REQUEST;
        }

        /* Init IPv6 */
        if(network_config->ip6.len && network_config->gateway6.len) {
            memcpy(&network_if->ip6, &network_config->ip6, sizeof(ipv6_prefix));
            memcpy(&network_if->gateway6, &network_config->gateway6, sizeof(ipv6_prefix));
            /* Send initial ICMPv6 NS */
            network_if->send_requests |= BBL_IF_SEND_ICMPV6_NS;
        }

        network_if->gateway_resolve_wait = network_config->gateway_resolve_wait;

        /* Next ... */
        network_config = network_config->next;
    }
    return true;
}

/**
 * bbl_add_a10nsp_interfaces
 *
 * @param ctx global context
 */
static bool
bbl_add_a10nsp_interfaces(bbl_ctx_s *ctx)
{
    bbl_a10nsp_config_s *a10nsp_config = ctx->config.a10nsp_config;
    struct bbl_interface_ *a10nsp_if;

    while(a10nsp_config) {
        if(bbl_interface_present(ctx, a10nsp_config->interface)) {
            LOG(ERROR, "Failed to add a10nsp interface %s (already added)\n", a10nsp_config->interface);
            return false;
        }
        a10nsp_if = bbl_add_interface(ctx, a10nsp_config->interface);
        if (!a10nsp_if) {
            LOG(ERROR, "Failed to add a10nsp interface %s\n", a10nsp_config->interface);
            return false;
        }
        a10nsp_if->type = INTERFACE_TYPE_A10NSP;
        a10nsp_config->a10nsp_if = a10nsp_if;
        a10nsp_if->qinq = a10nsp_config->qinq;
        if(*(uint32_t*)a10nsp_config->mac) {
            memcpy(a10nsp_if->mac, a10nsp_config->mac, ETH_ADDR_LEN);
        }

        if(ctx->interfaces.a10nsp_if_count < BBL_MAX_INTERFACES) {
            ctx->interfaces.a10nsp_if[ctx->interfaces.a10nsp_if_count++] = a10nsp_if;
        } else {
            LOG(ERROR, "Failed to add a10nsp interface %s (limit reached)\n", a10nsp_config->interface);
            return false;
        }

        bbl_send_init_interface(a10nsp_if, BBL_SEND_DEFAULT_SIZE);
        
        a10nsp_config = a10nsp_config->next;
    }
    return true;
}

/**
 * bbl_add_interfaces
 *
 * @brief This function will add and initialize
 * all interfaces defined in the configuration.
 * 
 * @param ctx global context
 * @return true if all interfaces are 
 * added and initialised successfully
 */
bool
bbl_add_interfaces(bbl_ctx_s *ctx)
{
    /* Add network interfaces */
    if(!bbl_add_access_interfaces(ctx)) {
        return false;
    }
    /* Add access interfaces */
    if(!bbl_add_network_interfaces(ctx)) {
        return false;
    }

    /* Add a10nsp interfaces */
    if(!bbl_add_a10nsp_interfaces(ctx)) {
        return false;
    }
    return true;
}

/**
 * bbl_get_network_interface
 *
 * @brief This function returns the network interface
 * with the given name or the first interface 
 * if name is NULL. 
 * 
 * @param ctx global context
 * @param interface interface name
 * @return interface
 */
bbl_interface_s *
bbl_get_network_interface(bbl_ctx_s *ctx, char *interface_name)
{
    for(int i = 0; i < ctx->interfaces.network_if_count; i++) {
        if(ctx->interfaces.network_if[i]) {
            if(interface_name) {
                if (strcmp(ctx->interfaces.network_if[i]->name, interface_name) == 0) {
                    return ctx->interfaces.network_if[i];
                }
            } else {
                return ctx->interfaces.network_if[i]; 
            }
        }
    }
    return NULL;
}

/**
 * bbl_get_a10nsp_interface
 *
 * @brief This function returns the network interface
 * with the given name. 
 * 
 * @param ctx global context
 * @param interface interface name
 * @return interface
 */
bbl_interface_s *
bbl_get_a10nsp_interface(bbl_ctx_s *ctx, char *interface_name)
{
    if(!interface_name) {
        return NULL;
    }
    for(int i = 0; i < ctx->interfaces.a10nsp_if_count; i++) {
        if(ctx->interfaces.a10nsp_if[i]) {
            if (strcmp(ctx->interfaces.a10nsp_if[i]->name, interface_name) == 0) {
                return ctx->interfaces.a10nsp_if[i];
            }
        }
    }
    return NULL;
}