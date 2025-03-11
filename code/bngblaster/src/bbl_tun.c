/*
 * BNG Blaster (BBL) - TUN Interfaces
 *
 * Christian Giese, March 2025
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"
#include "bbl_tun.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <linux/if_tun.h>

static int 
bbl_tun_add(char *dev, int flags)
{
    struct ifreq ifr = {0};
    int fd = 0;

    ifr.ifr_flags = flags;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    if ((fd = open("/dev/net/tun", O_RDWR)) < 0) {
        return -1;
    }

    if (ioctl(fd, TUNSETIFF, (void *)&ifr) < 0) {
        close(fd); return -1;
    }
    
    // Set non-blocking mode
    int current_flags = fcntl(fd, F_GETFL, 0);
    if (current_flags < 0) {
        close(fd); return -1;
    }
    if (fcntl(fd, F_SETFL, current_flags | O_NONBLOCK) < 0) {
        close(fd); return -1;
    }

    return fd;
}

static bool 
bbl_tun_config(char *dev, bool up, uint32_t ip, uint16_t mtu)
{
    struct ifreq ifr = {0};
    struct sockaddr_in addr = {0};
    int sockfd = 0;

    /** Create a socket for performing ioctls */
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        LOG_NOARG(ERROR, "Failed to crate a socket for performing ioctls\n");
        perror("socket");
        return -1;
    }
    
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);

    /* Set IP address */
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = ip;
    memcpy(&ifr.ifr_addr, &addr, sizeof(struct sockaddr));
    if (ioctl(sockfd, SIOCSIFADDR, &ifr) < 0) {
        LOG(ERROR, "Failed to set IP address of tun device %s\n", dev);
        close(sockfd);
        return false;
    }
    if(ip) {
        /* Set IP netmask */
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_BROADCAST;
        memcpy(&ifr.ifr_netmask, &addr, sizeof(struct sockaddr));
        if (ioctl(sockfd, SIOCSIFNETMASK, &ifr) < 0) {
            LOG(ERROR, "Failed to set IP netmask of tun device %s\n", dev);
            close(sockfd);
            return false;
        }
    }

    /* Set MTU if provided */
    if(mtu > 1280) {
        ifr.ifr_mtu = mtu;
        if (ioctl(sockfd, SIOCSIFMTU, &ifr) < 0) {
            LOG(ERROR, "Failed to set MTU of tun device %s\n", dev);
            close(sockfd);
            return false;
        }
    }
    
    /* Get interface flags */
    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0) {
        LOG(ERROR, "Failed to get interface flags of tun device %s\n", dev);
        close(sockfd);
        return false;
    }

    if(up) {
        ifr.ifr_flags |= IFF_UP; /* UP */
    } else {
        ifr.ifr_flags &= ~IFF_UP; /* DOWN */
    }

    /* Set interface flags */
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0) {
        LOG(ERROR, "Failed to set interface flags of tun device %s\n", dev);
        close(sockfd);
        return false;
    }
    
    close(sockfd);
    return true;
}

void 
bbl_tun_pppoe_tx_job(timer_s *timer) {
    bbl_session_s *session = timer->data;

    uint8_t buf[2048];
    uint8_t version;
    ssize_t len = 1;
    bbl_ethernet_header_s eth = {0};
    bbl_pppoe_session_s pppoe = {0};

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    eth.type = ETH_TYPE_PPPOE_SESSION;
    eth.next = &pppoe;
    pppoe.session_id = session->pppoe_session_id;
    while(true) {
        len = read(session->tun_fd, buf, sizeof(buf));
        if(len > 0) {
            version = buf[0] >> 4;    
            if (version == 4) {
                pppoe.protocol = PROTOCOL_IPV4;
            } else if (version == 6) {
                pppoe.protocol = PROTOCOL_IPV6;
            } else {
                continue;
            }
            pppoe.next = buf;
            pppoe.raw_len = len;
            bbl_txq_to_buffer(session->access_interface->txq, &eth);
        } else {
            break;
        }
    }
}

void 
bbl_tun_ipoe_tx_job(timer_s *timer) {
    bbl_session_s *session = timer->data;

    uint8_t buf[2048];
    uint8_t version;
    ssize_t len = 1;
    bbl_ethernet_header_s eth = {0};

    eth.dst = session->server_mac;
    eth.src = session->client_mac;
    eth.qinq = session->access_config->qinq;
    eth.vlan_outer = session->vlan_key.outer_vlan_id;
    eth.vlan_inner = session->vlan_key.inner_vlan_id;
    eth.vlan_three = session->access_third_vlan;
    while(true) {
        len = read(session->tun_fd, buf, sizeof(buf));
        if(len > 0) {
            version = buf[0] >> 4;    
            if (version == 4) {
                eth.type = ETH_TYPE_IPV4;
            } else if (version == 6) {
                eth.type = ETH_TYPE_IPV6;
            } else {
                continue;
            }
            eth.next = buf;
            eth.raw_len = len;
            bbl_txq_to_buffer(session->access_interface->txq, &eth);
        } else {
            break;
        }
    }
}


bool
bbl_tun_session_up(bbl_session_s *session)
{
    if(!session->tun_dev) return true;
    if(session->access_type == ACCESS_TYPE_PPPOE) {
        timer_add_periodic(&g_ctx->timer_root, &session->timer_tun, "TUN", 
                           0, 1 * MSEC, session, &bbl_tun_pppoe_tx_job);
    } else {
        timer_add_periodic(&g_ctx->timer_root, &session->timer_tun, "TUN", 
            0, 1 * MSEC, session, &bbl_tun_ipoe_tx_job);
    }
    return bbl_tun_config(session->tun_dev, true, session->ip_address, session->peer_mru);
}

bool
bbl_tun_session_down(bbl_session_s *session)
{
    if(!session->tun_dev) return true;
    timer_del(session->timer_tun);
    return bbl_tun_config(session->tun_dev, false, 0, 0);
}

bool
bbl_tun_session_init(bbl_session_s *session)
{
    char dev[IFNAMSIZ];
    if(!session->access_config->tun) return true;

    snprintf(dev, sizeof(dev), "bbl%d", session->session_id);
    session->tun_dev = strdup(dev);
    session->tun_fd = bbl_tun_add(session->tun_dev, IFF_TUN|IFF_NO_PI);

    if(session->tun_fd > 0) {
        LOG(DEBUG, "Created tun interface %s for session %u\n",
            dev, session->session_id);
        return true;
    }
    return false;
}