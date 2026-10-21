/*
 * BNG Blaster (BBL) - IO Interface Functions
 *
 * Christian Giese, July 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "io.h"
#include "ifaddrs.h"
#include <dirent.h>

static bool
read_first_line(const char *path, char *buf, size_t len)
{
    FILE *fp;

    fp = fopen(path, "r");
    if(!fp) {
        return false;
    }
    if(!fgets(buf, len, fp)) {
        fclose(fp);
        return false;
    }
    fclose(fp);
    return true;
}

static bool
read_cpu_topology_int(uint16_t cpu, const char *leaf, int *value)
{
    char path[256];
    char buf[64];

    snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%u/topology/%s", cpu, leaf);
    if(!read_first_line(path, buf, sizeof(buf))) {
        return false;
    }
    *value = atoi(buf);
    return true;
}

static bool
parse_cpuset(char *input, uint16_t **cpuset, uint16_t *count)
{
    long max_cpu;
    char *buf;
    char *token;
    char *saveptr = NULL;
    uint16_t *list;
    uint16_t list_count = 0;
    unsigned int first;
    unsigned int last;
    unsigned int cpu;

    max_cpu = sysconf(_SC_NPROCESSORS_CONF);
    if(max_cpu <= 0) {
        max_cpu = CPU_SETSIZE;
    }

    buf = strdup(input);
    list = calloc(max_cpu, sizeof(uint16_t));
    if(!(buf && list)) {
        free(buf);
        free(list);
        return false;
    }

    token = strtok_r(buf, ", \t\r\n", &saveptr);
    while(token) {
        if(sscanf(token, "%u-%u", &first, &last) == 2) {
            if(last < first) {
                free(buf);
                free(list);
                return false;
            }
        } else if(sscanf(token, "%u", &first) == 1) {
            last = first;
        } else {
            free(buf);
            free(list);
            return false;
        }

        for(cpu = first; cpu <= last; cpu++) {
            if(list_count >= max_cpu) {
                free(buf);
                free(list);
                return false;
            }
            list[list_count++] = cpu;
        }
        token = strtok_r(NULL, ", \t\r\n", &saveptr);
    }

    free(buf);
    if(!list_count) {
        free(list);
        return false;
    }

    *cpuset = list;
    *count = list_count;
    return true;
}

static bool
cpu_in_list(const uint16_t *cpuset, uint16_t count, uint16_t cpu)
{
    uint16_t i;
    for(i = 0; i < count; i++) {
        if(cpuset[i] == cpu) {
            return true;
        }
    }
    return false;
}

static bool
append_cpu(uint16_t *cpuset, uint16_t *count, uint16_t max, uint16_t cpu)
{
    if(*count >= max || cpu_in_list(cpuset, *count, cpu)) {
        return false;
    }
    cpuset[(*count)++] = cpu;
    return true;
}

static void
order_cpuset_physical_first(uint16_t **cpuset, uint16_t count)
{
    uint16_t *ordered = NULL;
    uint16_t ordered_count = 0;
    uint16_t i;
    uint16_t j;
    int package_id;
    int core_id;
    int *seen_package = NULL;
    int *seen_core = NULL;
    uint16_t seen_count = 0;
    bool sibling_added;

    if(count < 2) {
        return;
    }

    ordered = calloc(count, sizeof(uint16_t));
    seen_package = calloc(CPU_SETSIZE, sizeof(int));
    seen_core = calloc(CPU_SETSIZE, sizeof(int));
    if(!ordered || !seen_package || !seen_core) {
        free(ordered);
        free(seen_package);
        free(seen_core);
        return;
    }

    for(i = 0; i < count; i++) {
        if(!read_cpu_topology_int((*cpuset)[i], "physical_package_id", &package_id) ||
           !read_cpu_topology_int((*cpuset)[i], "core_id", &core_id)) {
            continue;
        }
        sibling_added = false;
        for(j = 0; j < seen_count; j++) {
            if(seen_package[j] == package_id && seen_core[j] == core_id) {
                sibling_added = true;
                break;
            }
        }
        if(!sibling_added) {
            append_cpu(ordered, &ordered_count, count, (*cpuset)[i]);
            if(seen_count < CPU_SETSIZE) {
                seen_package[seen_count] = package_id;
                seen_core[seen_count] = core_id;
                seen_count++;
            }
        }
    }

    for(i = 0; i < count; i++) {
        append_cpu(ordered, &ordered_count, count, (*cpuset)[i]);
    }

    if(ordered_count == count) {
        memcpy(*cpuset, ordered, count * sizeof(uint16_t));
    }
    free(ordered);
    free(seen_package);
    free(seen_core);
}

/**
 * Check if an interrupt is requested by a driver, which
 * is the case if it has an action (named subdirectory).
 *
 * @param irq interrupt number
 * @param name optional name, which must be part of the action name
 * @return true if requested (and matching name)
 */
static bool
irq_requested(const char *irq, const char *name)
{
    char path[512];
    struct dirent *entry;
    DIR *dir;
    bool requested = false;

    snprintf(path, sizeof(path), "/proc/irq/%s", irq);
    dir = opendir(path);
    if(!dir) {
        return false;
    }
    while((entry = readdir(dir))) {
        if(entry->d_type == DT_DIR && entry->d_name[0] != '.') {
            if(!name || strstr(entry->d_name, name)) {
                requested = true;
                break;
            }
        }
    }
    closedir(dir);
    return requested;
}

/**
 * Mark all CPUs handling interrupts of the interface (NIC).
 *
 * The NIC queues raise interrupts on those CPUs and the kernel
 * driver processes the queues there (NAPI). A busy polling
 * I/O thread on the same CPU delays this processing, which
 * limits the throughput of the interface.
 *
 * Only interrupts requested by the driver are considered. If
 * the names of those interrupts contain the interface name
 * (e.g. i40e-eth1-TxRx-0), only those are considered to skip
 * other interrupts of the device (e.g. i40e-0000:01:00.0:misc).
 *
 * @param interface interface
 * @param irq_cpus array of CPU_SETSIZE flags
 * @return number of interrupts found
 */
uint16_t
io_interface_irq_cpus(bbl_interface_s *interface, bool *irq_cpus)
{
    char path[512];
    char buf[4096];
    const char *name = NULL;
    uint16_t *cpuset;
    uint16_t count;
    uint16_t irqs = 0;
    uint16_t i;
    struct dirent *entry;
    DIR *dir;

    /* LAG interfaces have no link configuration and no interrupts,
     * which are handled by their member interfaces. */
    if(!interface->config ||
       interface->config->io_mode == IO_MODE_DPDK ||
       interface->config->io_mode == IO_MODE_LOOPBACK) {
        return 0;
    }

    snprintf(path, sizeof(path), "/sys/class/net/%s/device/msi_irqs", interface->name);
    dir = opendir(path);
    if(!dir) {
        return 0;
    }
    while((entry = readdir(dir))) {
        if(isdigit((unsigned char)entry->d_name[0]) &&
           irq_requested(entry->d_name, interface->name)) {
            name = interface->name;
            break;
        }
    }
    rewinddir(dir);
    while((entry = readdir(dir))) {
        if(!isdigit((unsigned char)entry->d_name[0]) ||
           !irq_requested(entry->d_name, name)) {
            continue;
        }
        /* The effective affinity is the CPU actually handling the
         * interrupt, while the configured affinity may contain many
         * CPUs and is only used if it contains a single CPU. */
        cpuset = NULL;
        count = 0;
        snprintf(path, sizeof(path), "/proc/irq/%s/effective_affinity_list", entry->d_name);
        if(!(read_first_line(path, buf, sizeof(buf)) && parse_cpuset(buf, &cpuset, &count))) {
            snprintf(path, sizeof(path), "/proc/irq/%s/smp_affinity_list", entry->d_name);
            if(!(read_first_line(path, buf, sizeof(buf)) && parse_cpuset(buf, &cpuset, &count))) {
                continue;
            }
            if(count != 1) {
                free(cpuset);
                continue;
            }
        }
        for(i = 0; i < count; i++) {
            if(cpuset[i] < CPU_SETSIZE) {
                irq_cpus[cpuset[i]] = true;
            }
        }
        free(cpuset);
        irqs++;
    }
    closedir(dir);
    return irqs;
}

/* Remove CPUs not allowed for this process (e.g. restricted with taskset
 * or a cgroup cpuset), so that parallel instances can be separated. */
static uint16_t
filter_allowed_cpus(uint16_t *cpuset, uint16_t count)
{
    uint16_t allowed = 0;
    uint16_t i;

    for(i = 0; i < count; i++) {
        if(io_thread_cpu_allowed(cpuset[i])) {
            cpuset[allowed++] = cpuset[i];
        }
    }
    return allowed;
}

bool
io_interface_init_topology(bbl_interface_s *interface, int numa_node_hint)
{
    char path[256];
    char buf[4096];
    uint16_t *cpuset = NULL;
    uint16_t count = 0;
    int numa_node = -1;
    bool use_local = false;
    bool use_numa = false;
    bool use_online = false;

    if(numa_node_hint >= 0) {
        numa_node = numa_node_hint;
    }

    if(numa_node < 0) {
        if(interface->config->io_mode == IO_MODE_DPDK) {
            snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/numa_node", interface->name);
        } else {
            snprintf(path, sizeof(path), "/sys/class/net/%s/device/numa_node", interface->name);
        }
        if(read_first_line(path, buf, sizeof(buf))) {
            numa_node = atoi(buf);
        }
    }

    if(interface->config->io_mode == IO_MODE_DPDK) {
        snprintf(path, sizeof(path), "/sys/bus/pci/devices/%s/local_cpulist", interface->name);
    } else {
        snprintf(path, sizeof(path), "/sys/class/net/%s/device/local_cpulist", interface->name);
    }
    if(read_first_line(path, buf, sizeof(buf)) && parse_cpuset(buf, &cpuset, &count)) {
        count = filter_allowed_cpus(cpuset, count);
        if(count) {
            use_local = true;
            goto SUCCESS;
        }
        free(cpuset);
        cpuset = NULL;
    }

    if(numa_node >= 0) {
        snprintf(path, sizeof(path), "/sys/devices/system/node/node%d/cpulist", numa_node);
        if(read_first_line(path, buf, sizeof(buf)) && parse_cpuset(buf, &cpuset, &count)) {
            count = filter_allowed_cpus(cpuset, count);
            if(count) {
                use_numa = true;
                goto SUCCESS;
            }
            free(cpuset);
            cpuset = NULL;
        }
    }

    use_online = true;
    if(read_first_line("/sys/devices/system/cpu/online", buf, sizeof(buf)) &&
       parse_cpuset(buf, &cpuset, &count)) {
        count = filter_allowed_cpus(cpuset, count);
        if(count) {
            goto SUCCESS;
        }
        free(cpuset);
    }
    return false;

SUCCESS:
    order_cpuset_physical_first(&cpuset, count);
    interface->numa_node = numa_node;
    interface->local_cpuset = cpuset;
    interface->local_cpuset_count = count;
    if(use_online) {
        LOG(INFO, "Auto CPU placement for interface %s uses all allowed CPUs (%u entries)\n",
            interface->name, count);
    } else if(use_local && numa_node >= 0) {
        LOG(INFO, "Auto CPU placement for interface %s uses local CPU list on NUMA node %d (%u entries)\n",
            interface->name, numa_node, count);
    } else if(use_local) {
        LOG(INFO, "Auto CPU placement for interface %s uses local CPU list (%u entries)\n",
            interface->name, count);
    } else if(use_numa) {
        LOG(INFO, "Auto CPU placement for interface %s uses NUMA node %d (%u CPUs)\n",
            interface->name, numa_node, count);
    } else if(numa_node >= 0) {
        LOG(INFO, "Auto CPU placement for interface %s is associated with NUMA node %d (%u CPUs)\n",
            interface->name, numa_node, count);
    }
    return true;
}

static bool
set_kernel_info(bbl_interface_s *interface)
{
    struct ifreq ifr = {0};

    int fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);
    if(ioctl(fd, SIOCGIFHWADDR, &ifr) == -1) {
        LOG(ERROR, "Getting MAC address error %s (%d) for interface %s\n",
            strerror(errno), errno, interface->name);
        close(fd);
        return false;
    }
    memcpy(&interface->mac, ifr.ifr_hwaddr.sa_data, IFHWADDRLEN);

    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface->name);
    if(ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
        LOG(ERROR, "Get interface index error %s (%d) for interface %s\n",
            strerror(errno), errno, interface->name);
        close(fd);
        return false;
    }
    interface->kernel_index = ifr.ifr_ifindex;

    close(fd);
    return true;
}

/* Set interface in promisc mode. */
static bool
set_promisc(bbl_interface_s *interface) {
    /* Taken and adapted from:
     * https://stackoverflow.com/questions/41678219/how-to-properly-put-network-interface-into-promiscuous-mode-on-linux
     * This prevents the ioctl get flags / set flags race condition. */
    struct packet_mreq mreq = {0};
    int sfd;

    LOG(DEBUG, "Set interface %s (%d) in promiscuous mode\n", interface->name, interface->kernel_index);

    /* This socket is only opened, but not closed. Closing the socket would reset
     * its flags - effectively removing the just added promisc mode.
     * We want to keep the interface in promisc mode until the end of the program. */
    if((sfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1) {
        LOG_NOARG(ERROR, "Unable to open control socket for promiscuous mode activation\n");
        return false;
    }

    mreq.mr_type = PACKET_MR_PROMISC;
    mreq.mr_ifindex = interface->kernel_index;
    if(setsockopt(sfd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) != 0) {
        LOG(ERROR, "Failed to put interface %s in promiscuous mode\n", interface->name);
        return false;
    }
    return true;
}

static bool
io_interface_init_rx(bbl_interface_s *interface)
{
    bbl_link_config_s *config = interface->config;
    io_handle_s *io;
    
    uint8_t count = 1;
    if(config->rx_threads) {
        count = config->rx_threads;
    }

    while(count) {
        io = calloc(1, sizeof(io_handle_s));
        if(!io) return false;
        io->id = --count;
        io->mode = config->io_mode;
        if(io->mode == IO_MODE_PACKET_MMAP_RAW) {
            io->mode = IO_MODE_PACKET_MMAP;
        }
        io->direction = IO_INGRESS;
        io->next = interface->io.rx;
        interface->io.rx = io;
        io->interface = interface;
        if(config->rx_threads) {
            if(!io_thread_init(io)) {
                return false;
            }
        }
        switch(io->mode) {
            case IO_MODE_PACKET_MMAP:
                if(!io_packet_mmap_init(io)) {
                    return false;
                }
                break;
            case IO_MODE_RAW:
                if(!io_raw_init(io)) {
                    return false;
                }
                break;
            default:
                return false;
        }
    }
    return true;
}

static bool
io_interface_init_tx(bbl_interface_s *interface)
{
    bbl_link_config_s *config = interface->config;
    io_handle_s *io;
    
    uint8_t count = 1;
    if(config->tx_threads) {
        count = config->tx_threads;
    }

    while(count) {
        io = calloc(1, sizeof(io_handle_s));
        if(!io) return false;
        io->id = --count;
        io->mode = config->io_mode;
        if(io->mode == IO_MODE_PACKET_MMAP_RAW) {
            io->mode = IO_MODE_RAW;
        }
        io->direction = IO_EGRESS;
        io->next = interface->io.tx;
        interface->io.tx = io;
        io->interface = interface;
        if(config->tx_threads) {
            if(!io_thread_init(io)) {
                return false;
            }
        }
        switch(io->mode) {
            case IO_MODE_PACKET_MMAP:
                if(!io_packet_mmap_init(io)) {
                    return false;
                }
                break;
            case IO_MODE_RAW:
                if(!io_raw_init(io)) {
                    return false;
                }
                break;
            default:
                return false;
        }
    }
    return true;
}

static void
address_warning(bbl_interface_s *interface)
{
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;
    struct sockaddr_in *ipv4;
    struct sockaddr_in6 *ipv6;

    char address[INET6_ADDRSTRLEN];

    static bool warning = false;

    if(getifaddrs(&ifaddr) == 0) {
        for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if(strcmp(ifa->ifa_name, interface->name) == 0) {
                if(ifa->ifa_addr->sa_family == AF_INET) {
                    ipv4 = (struct sockaddr_in *) ifa->ifa_addr;
                    inet_ntop(AF_INET, &(ipv4->sin_addr), address, INET6_ADDRSTRLEN);
                } else if(ifa->ifa_addr->sa_family == AF_INET6) {
                    ipv6 = (struct sockaddr_in6 *) ifa->ifa_addr;
                    inet_ntop(AF_INET6, &(ipv6->sin6_addr), address, INET6_ADDRSTRLEN);
                } else {
                    continue;
                }

                if(!warning) {
                    warning = true;
                    LOG_NOARG(INFO, "Warning: Interfaces must not have an IP address configured in the host OS!\n");
                }

                LOG(INFO, "Warning: IP address %s on interface %s is conflicting!\n",
                    address, interface->name);
            }
        }
    }
    freeifaddrs(ifaddr);
}

/**
 * io_interface_init
 *
 * @param interface interface.
 */
bool
io_interface_init(bbl_interface_s *interface)
{
    bbl_link_config_s *config = interface->config;

#ifdef BNGBLASTER_DPDK
    if(config->io_mode == IO_MODE_DPDK) {
        if(!io_dpdk_interface_init(interface)) {
            return false;
        }
    }
#endif

    if(config->io_mode == IO_MODE_LOOPBACK) {
        return io_loopback_interface_init(interface);
    }

    if(config->io_mode != IO_MODE_DPDK) {
        address_warning(interface);
        if(!set_kernel_info(interface)) {
            return false;
        }
        if((config->rx_auto_cpuset && !config->rx_cpuset_count) ||
           (config->tx_auto_cpuset && !config->tx_cpuset_count)) {
            if(!io_interface_init_topology(interface, -2)) {
                LOG(ERROR, "Failed to discover local CPU topology for interface %s\n", interface->name);
                return false;
            }
        }
        if(*(uint32_t*)config->mac) {
            memcpy(interface->mac, config->mac, ETH_ADDR_LEN);
        }
        if(config->io_mode == IO_MODE_AF_XDP) {
#ifdef BNGBLASTER_AF_XDP
            if(!io_af_xdp_interface_init(interface)) {
                return false;
            }
            /* Changing the number of queues resets SR-IOV VFs (e.g. iavf),
             * which clears promiscuous mode in hardware. Enable it only after
             * the AF_XDP setup, so the driver applies it to the reset VF. */
            if(!set_promisc(interface)) {
                return false;
            }
#else
            LOG(ERROR, "IO mode af_xdp requested for interface %s but BNG Blaster "
                "was built without AF_XDP support\n", interface->name);
            return false;
#endif
        } else {
            if(!set_promisc(interface)) {
                return false;
            }
            if(!io_interface_init_rx(interface)) {
                return false;
            }
            if(!io_interface_init_tx(interface)) {
                return false;
            }
        }
    }
    return true;
}
