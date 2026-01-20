/*
 * BNG Blaster (BBL) - CFM Functions
 *
 * Christian Giese, October 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

bool
bbl_cfm_init(bbl_cfm_session_s *cfm)
{
    uint16_t u16;

    if(!(cfm->config->md_name || cfm->config->md_name_format == CFM_MD_NAME_FORMAT_NONE)) {
        return false;
    }

    switch(cfm->config->md_name_format) {
        case CFM_MD_NAME_FORMAT_NONE:
            break;
        case CFM_MD_NAME_FORMAT_DNS:
        case CFM_MD_NAME_FORMAT_STRING:
            cfm->md_name_buf = (uint8_t*)cfm->md_name;
            cfm->md_name_len = strlen(cfm->md_name);
            break;
        case CFM_MD_NAME_FORMAT_MAC_INT:
            cfm->md_name_buf = malloc(CFM_MD_MAC_INT_LEN);
            cfm->md_name_len = CFM_MD_MAC_INT_LEN;
            if(sscanf(cfm->md_name, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx/%hu",
                     &cfm->md_name_buf[0],
                     &cfm->md_name_buf[1],
                     &cfm->md_name_buf[2],
                     &cfm->md_name_buf[3],
                     &cfm->md_name_buf[4],
                     &cfm->md_name_buf[5],
                     &u16) < 7) {
                LOG(ERROR, "Invalid CFM MD name (%s) for fomat MAC_INT (example: 'aa:bb:cc:dd:ee:ff/123')\n", cfm->md_name);
                return false;
            }
            *(uint16_t*)&cfm->md_name_buf[6] = htobe16(u16);
            break;
        default:
            return false;
    }

    if(!cfm->ma_name) {
        return false;
    }

    switch(cfm->config->ma_name_format) {
        case CFM_MA_NAME_FORMAT_VLAN:
            cfm->ma_name_buf = malloc(CFM_MA_VLAN_LEN);
            cfm->ma_name_len = CFM_MA_VLAN_LEN;
            if(!sscanf(cfm->ma_name, "%hu", &u16)) {
                LOG(ERROR, "Invalid CFM MA name (%s) for fomat VLAN (example: '1000')\n", cfm->ma_name);
                return false;
            }
            if(u16 > BBL_ETH_VLAN_ID_MAX) {
                LOG(ERROR, "Invalid CFM MA name (%s) for fomat VLAN (example: '1000')\n", cfm->ma_name);
                return false;
            }
            *(uint16_t*)cfm->ma_name_buf = htobe16(u16);
            break;
        case CFM_MA_NAME_FORMAT_STRING:
        case CFM_MA_NAME_FORMAT_ICC:
            cfm->ma_name_buf = (uint8_t*)cfm->ma_name;
            cfm->ma_name_len = strlen(cfm->ma_name);
            break;
        case CFM_MA_NAME_FORMAT_UINT16:
            cfm->ma_name_buf = malloc(CFM_MA_VLAN_LEN);
            cfm->ma_name_len = CFM_MA_VLAN_LEN;
            if(!sscanf(cfm->ma_name, "%hu", &u16)) {
                LOG(ERROR, "Invalid CFM MA name (%s) for fomat UINT16 (example: '1000')\n", cfm->ma_name);
                return false;
            }
            *(uint16_t*)cfm->ma_name_buf = htobe16(u16);
            break;
        case CFM_MA_NAME_FORMAT_VPN_ID:
            cfm->ma_name_buf = malloc(CFM_MA_VPN_ID_LEN);
            cfm->ma_name_len = CFM_MA_VPN_ID_LEN;
            if(scan_hex_string(cfm->ma_name, cfm->ma_name_buf, CFM_MA_VPN_ID_LEN) != CFM_MA_VPN_ID_LEN) {
                LOG(ERROR, "Invalid CFM MA name (%s) for fomat VPN_ID (example: '11:22:33:44:55:66:77')\n", cfm->ma_name);
                return false;
            }
            break;
        default:
            return false;
    }
    return true;
}

void
bbl_cfm_cc_session_job(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    if(session->cfm && session->cfm->cc && (session->session_state != BBL_TERMINATED)) {
        session->send_requests |= BBL_SEND_CFM_CC;
        bbl_session_tx_qnode_insert(session);
    }
}

void
bbl_cfm_cc_interface_job(timer_s *timer)
{
    bbl_network_interface_s *network_interface = timer->data;
    if(network_interface->cfm && network_interface->cfm->cc) {
        network_interface->send_requests |= BBL_IF_SEND_CFM_CC;
    }
}

void
bbl_cfm_cc_start(bbl_cfm_session_s *cfm)
{

    if(cfm->session) {
        timer_add_periodic(&g_ctx->timer_root, &cfm->timer_cfm_cc, "CFM-CC", 
                           cfm->config->interval_sec, cfm->config->interval_nsec, cfm->session, &bbl_cfm_cc_session_job);
    } else if(cfm->network_interface) {
        timer_add_periodic(&g_ctx->timer_root, &cfm->timer_cfm_cc, "CFM-CC", 
                           cfm->config->interval_sec, cfm->config->interval_nsec, cfm->network_interface, &bbl_cfm_cc_interface_job);
    }
}

/* Control Socket Commands */

static int
bbl_cfm_ctrl_update(int fd, uint32_t session_id, json_t *arguments, bool rdi, bool status)
{
    bbl_session_s *session;
    char *network_interface_name = NULL;
    bbl_network_interface_s *network_interface;
    bbl_interface_s *interface;

    json_unpack(arguments, "{s:s}", "network-interface", &network_interface_name);

    uint32_t i;
    if(session_id) {
        session = bbl_session_get(session_id);
        if(session) {
            if(session->cfm) {
                if(rdi) {
                    session->cfm->rdi = status;
                } else {
                    session->cfm->cc = status;
                }   
            }
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else if (network_interface_name) {
        network_interface = bbl_network_interface_get(network_interface_name);
        if(network_interface && network_interface->cfm) {
            if(rdi) {
                network_interface->cfm->rdi = status;
            } else {
                network_interface->cfm->cc = status;
            } 
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "interface not found");
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            if(session && session->cfm) {
                if(rdi) {
                    session->cfm->rdi = status;
                } else {
                    session->cfm->cc = status;
                }
            }
        }
        /* Iterate over all network interfaces */
        CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
            network_interface = interface->network;
            while(network_interface) {
                if(network_interface->cfm) {
                    if(rdi) {
                        network_interface->cfm->rdi = status;
                    } else {
                        network_interface->cfm->cc = status;
                    } 
                }
                network_interface = network_interface->next;
            }
        }
    }
    return bbl_ctrl_status(fd, "ok", 200, NULL);
}

int
bbl_cfm_ctrl_cc_start(int fd, uint32_t session_id, json_t *arguments)
{
    return bbl_cfm_ctrl_update(fd, session_id, arguments, false, true);
}

int
bbl_cfm_ctrl_cc_stop(int fd, uint32_t session_id, json_t *arguments)
{
    return bbl_cfm_ctrl_update(fd, session_id, arguments, false, false);
}

int
bbl_cfm_ctrl_cc_rdi_on(int fd, uint32_t session_id, json_t *arguments)
{
    return bbl_cfm_ctrl_update(fd, session_id, arguments, true, true);
}

int
bbl_cfm_ctrl_cc_rdi_off(int fd, uint32_t session_id, json_t *arguments)
{
    return bbl_cfm_ctrl_update(fd, session_id, arguments, true, false);
}
