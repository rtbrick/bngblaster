/*
 * BNG Blaster (BBL) - Interfaces
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"
#include <sys/stat.h>

static json_t *
bbl_interface_ctrl_topology_cpuset(uint16_t *cpuset, uint16_t count)
{
    uint16_t i;
    json_t *jarray = json_array();

    if(!jarray) {
        return NULL;
    }
    for(i = 0; i < count; i++) {
        json_array_append_new(jarray, json_integer(cpuset[i]));
    }
    return jarray;
}

static json_t *
bbl_interface_ctrl_topology_threads(io_handle_s *io, bool auto_cpuset, bool manual_cpuset)
{
    json_t *jarray = json_array();
    json_t *jobj;
    const char *source;

    if(!(jarray && io)) {
        return NULL;
    }
    while(io) {
        if(io->thread) {
            source = "none";
            if(manual_cpuset) {
                source = "manual";
            } else if(auto_cpuset) {
                source = "auto";
            }
            jobj = json_pack("{si ss sb sb si}",
                             "id", io->id,
                             "cpu-source", source,
                             "thread-active", io->thread->active,
                             "thread-stopped", io->thread->stopped,
                             "selected-cpu", io->thread->selected_cpu);
#ifdef BNGBLASTER_DPDK
            if(jobj && io->mode == IO_MODE_DPDK) {
                json_object_set_new(jobj, "queue", json_integer(io->queue));
            }
#endif
            if(jobj) {
                json_array_append_new(jarray, jobj);
            }
        }
        io = io->next;
    }
    return jarray;
}

const char *
interface_type_string(interface_type_t type)
{
    switch(type) {
        case DEFAULT_INTERFACE: return "Interface";
        case LAG_INTERFACE: return "LAG-Interface";
        case LAG_MEMBER_INTERFACE: return "LAG-Member-Interface";
        default: return "N/A";
    }
}

const char *
interface_state_string(interface_state_t state)
{
    switch(state) {
        case INTERFACE_DISABLED: return "Disabled";
        case INTERFACE_UP: return "Up";
        case INTERFACE_DOWN: return "Down";
        case INTERFACE_STANDBY: return "Standby";
        default: return "N/A";
    }
}

static const char *
interface_io_mode_string(io_mode_t mode)
{
    switch(mode) {
        case IO_MODE_PACKET_MMAP_RAW: return "packet_mmap_raw";
        case IO_MODE_PACKET_MMAP: return "packet_mmap";
        case IO_MODE_RAW: return "raw";
        case IO_MODE_DPDK: return "dpdk";
        case IO_MODE_AF_XDP: return "af_xdp";
        default: return "disabled";
    }
}

/**
 * bbl_interface_lock
 *
 * @brief This functions locks the interface
 * creating the file "/run/lock/bngblaster_<interface>.lock".
 *
 * @param interface_name interface name
 * @return false if failed to lock (e.g. in use)
 */
static bool
bbl_interface_lock(char *interface_name)
{
    FILE *lock_file;
    char  lock_path[FILE_PATH_LEN];
    int   lock_pid;
    char  proc_pid_path[FILE_PATH_LEN];

    struct stat sts;
    pid_t pid = getpid();

    snprintf(lock_path, sizeof(lock_path), "/run/lock/bngblaster_%s.lock", interface_name);
    lock_file = fopen(lock_path, "r");
    if(lock_file) {
        /* lock file exists */
        if(fscanf(lock_file,"%d", &lock_pid) == 1 && lock_pid > 1) {
            snprintf(proc_pid_path, sizeof(proc_pid_path), "/proc/%d", lock_pid);
            if(!(stat(proc_pid_path, &sts) == -1 && errno == ENOENT)) {
                LOG(ERROR, "Interface %s in use by process %d (%s)\n", interface_name, lock_pid, lock_path);
                if(!g_ctx->config.interface_lock_force) {
                    fclose(lock_file);
                    return false;
                }
            }
        } else {
            LOG(ERROR, "Invalid interface lock file %s\n", lock_path);
            if(!g_ctx->config.interface_lock_force) {
                fclose(lock_file);
                return false;
            }
        }
        fclose(lock_file);
    }
    /* create lock file */
    lock_pid = pid;
    lock_file = fopen(lock_path, "w");
    if(!lock_file) {
        LOG(ERROR, "Failed to open interface lock file %s %s (%d)\n", 
            lock_path, strerror(errno), errno);
        return false;
    }
    fprintf(lock_file, "%d", lock_pid);
    {
        int fd = fileno(lock_file);
        if(fd >= 0) {
            fchmod(fd, 0666);
        }
    }
    fclose(lock_file);
    return true;
}

/**
 * bbl_interface_unlock_all
 *
 * @brief This functions unlocks all interfaces.
 */
void
bbl_interface_unlock_all()
{
    char lock_path[FILE_PATH_LEN];
    struct bbl_interface_ *interface;
    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        snprintf(lock_path, sizeof(lock_path), "/run/lock/bngblaster_%s.lock", interface->name);
        remove(lock_path);
    }
}

/**
 * bbl_add_interface
 *
 * @param interface interface name
 * @param link_config link configuration
 * @return interface
 */
static bbl_interface_s *
bbl_interface_link_add(char *interface_name, bbl_link_config_s *link_config)
{
    bbl_interface_s *interface;

    interface = calloc(1, sizeof(bbl_interface_s));
    if(!interface) {
        LOG(ERROR, "No memory for interface %s\n", interface_name);
        return NULL;
    }
    interface->name = strdup(interface_name);
    interface->ifindex = g_ctx->interfaces++;
    interface->state = INTERFACE_UP;
    
    if(!bbl_interface_lock(interface_name)) {
        return NULL;
    }
    CIRCLEQ_INSERT_TAIL(&g_ctx->interface_qhead, interface, interface_qnode);

    interface->config = link_config;
    if(!io_interface_init(interface)) {
        return NULL;
    }
    if(!bbl_lag_interface_add(interface, link_config)) {
        return NULL;
    }
    return interface;
}

/**
 * bbl_interface_links_add
 */
static bool
bbl_interface_links_add()
{
    bbl_link_config_s *link_config = g_ctx->config.link_config;
    struct bbl_interface_ *interface;

    while(link_config) {
        if(bbl_interface_get(link_config->interface) != NULL) {
            LOG(ERROR, "Failed to add link %s (duplicate link configuration)\n", 
                link_config->interface);
            return false;
        }
        interface = bbl_interface_link_add(link_config->interface, link_config);
        if(!interface) {
            LOG(ERROR, "Failed to add link %s\n", link_config->interface);
            return false;
        }
        link_config = link_config->next;
    }
    return true;
}

/**
 * bbl_interface_init
 *
 * @brief This function will add and initialize
 * all interfaces defined in the configuration.
 *
 * @return true if all interfaces are
 * added and initialised successfully
 */
bool
bbl_interface_init()
{
    /* LAG must be added before links, so that links
     * can reference to LAG. */
    if(!bbl_lag_add()) {
        return false;
    }
    if(!bbl_interface_links_add()) {
        return false;
    }
    if(!bbl_access_interfaces_add()) {
        return false;
    }
    if(!bbl_network_interfaces_add()) {
        return false;
    }
    if(!bbl_a10nsp_interfaces_add()) {
        return false;
    }
    return true;
}

/**
 * bbl_interface_get
 * 
 * Get interface by name. 
 *
 * @param interface_name interface name
 * @return the interface or NULL
 */
bbl_interface_s *
bbl_interface_get(char *interface_name)
{
    bbl_interface_s *interface;

    if(!interface_name) {
        return NULL;
    }

    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        if(strcmp(interface->name, interface_name) == 0) {
            return interface;
        }
    }
    return NULL;
}

static int
bbl_interface_ctrl_enable_disable(int fd, json_t *arguments, bool enable)
{
    const char *s;
    bbl_interface_s *interface;

    /* Unpack further arguments */
    if(json_unpack(arguments, "{s:s}", "interface", &s) != 0) {
        return bbl_ctrl_status(fd, "error", 400, "missing argument interface");
    }

    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        if(strcmp(interface->name, s) == 0) {
            if(interface->type == LAG_INTERFACE) {
                return bbl_ctrl_status(fd, "error", 400, "invalid interface");
            }
            if(enable) {
                if(interface->state == INTERFACE_DISABLED) {
                    if(interface->lag_member && interface->lag_member->lacp_state) {
                        interface->state = INTERFACE_DOWN;
                    } else {
                        interface->state = INTERFACE_UP;
                    }
                    LOG(INFO, "Interface (%s) enabled\n", interface->name);
                }
            } else {
                if(interface->state != INTERFACE_DISABLED) {
                    bbl_lag_member_lacp_reset(interface);
                    interface->state = INTERFACE_DISABLED;
                    LOG(INFO, "Interface (%s) disabled\n", interface->name);
                }
            }
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        }
    }

    return bbl_ctrl_status(fd, "warning", 404, "interface not found");
}

int
bbl_interface_ctrl_enable(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    return bbl_interface_ctrl_enable_disable(fd, arguments, true);
}

int
bbl_interface_ctrl_disable(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    return bbl_interface_ctrl_enable_disable(fd, arguments, false);
}

int
bbl_interface_ctrl(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments __attribute__((unused)))
{
    int result = 0;

    bbl_interface_s *interface;

    io_handle_s *io;
    json_t *root, *jobj, *jobj_array;

    jobj_array = json_array();

    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t rx_bytes;

    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {

        io = interface->io.tx;
        tx_packets = 0;
        tx_bytes = 0;
        while(io) {
            tx_packets += io->stats.packets;
            tx_bytes += io->stats.bytes;
            io = io->next;
        }
        io = interface->io.rx;
        rx_packets = 0;
        rx_bytes = 0;
        while(io) {
            rx_packets += io->stats.packets;
            rx_bytes += io->stats.bytes;
            io = io->next;
        }

        jobj = json_pack("{ss si si ss* ss* si sI sI sI sI }",
            "name", interface->name,
            "ifindex", interface->ifindex,
            "ifindex-kernel", interface->kernel_index,
            "type", interface_type_string(interface->type),
            "state", interface_state_string(interface->state),
            "state-transitions", interface->state_transitions,
            "tx-packets", tx_packets,
            "tx-bytes", tx_bytes,
            "rx-packets", rx_packets,
            "rx-bytes", rx_bytes);
        if(jobj) {
            json_array_append_new(jobj_array, jobj);
        }
    }

    root = json_pack("{ss si so*}",
        "status", "ok",
        "code", 200,
        "interfaces", jobj_array);

    if(root) {
        result = json_dumpfd(root, fd, 0);
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
    }
    return result;
}

int
bbl_interface_ctrl_topology(int fd, uint32_t session_id __attribute__((unused)), json_t *arguments)
{
    int result = 0;
    const char *name = NULL;
    bbl_interface_s *interface;
    json_t *root;
    json_t *jobj;
    json_t *jobj_array = json_array();
    json_t *jcpuset;
    json_t *jrx_threads;
    json_t *jtx_threads;

    if(arguments) {
        json_unpack(arguments, "{s?s}", "interface", &name);
    }

    CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
        if(name && strcmp(name, interface->name) != 0) {
            continue;
        }
        if(!interface->config) {
            continue;
        }

        jcpuset = bbl_interface_ctrl_topology_cpuset(interface->local_cpuset, interface->local_cpuset_count);
        jrx_threads = bbl_interface_ctrl_topology_threads(interface->io.rx,
                                                          interface->config->rx_auto_cpuset,
                                                          interface->config->rx_cpuset_count != 0);
        jtx_threads = bbl_interface_ctrl_topology_threads(interface->io.tx,
                                                          interface->config->tx_auto_cpuset,
                                                          interface->config->tx_cpuset_count != 0);
        jobj = json_pack("{ss ss si so so so sb sb}",
                         "name", interface->name,
                         "io-mode", interface_io_mode_string(interface->config->io_mode),
                         "numa-node", interface->numa_node,
                         "local-cpuset", jcpuset,
                         "rx-threads", jrx_threads,
                         "tx-threads", jtx_threads,
                         "rx-auto-cpuset", interface->config->rx_auto_cpuset,
                         "tx-auto-cpuset", interface->config->tx_auto_cpuset);
        if(jobj) {
            json_array_append_new(jobj_array, jobj);
        }
    }

    if(name && json_array_size(jobj_array) == 0) {
        json_decref(jobj_array);
        return bbl_ctrl_status(fd, "warning", 404, "interface not found");
    }

    root = json_pack("{ss si so}",
                     "status", "ok",
                     "code", 200,
                     "interfaces", jobj_array);
    if(root) {
        result = json_dumpfd(root, fd, JSON_INDENT(4));
        json_decref(root);
    } else {
        result = bbl_ctrl_status(fd, "error", 500, "internal error");
    }
    return result;
}
