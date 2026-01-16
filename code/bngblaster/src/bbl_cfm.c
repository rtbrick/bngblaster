/*
 * BNG Blaster (BBL) - CFM Functions
 *
 * Christian Giese, October 2022
 *
 * Copyright (C) 2020-2025, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

void
bbl_cfm_cc_session_job(timer_s *timer)
{
    bbl_session_s *session = timer->data;
    if(session->cfm && session->cfm->cfm_cc && (session->session_state != BBL_TERMINATED)) {
        session->send_requests |= BBL_SEND_CFM_CC;
        bbl_session_tx_qnode_insert(session);
    }
}

void
bbl_cfm_cc_interface_job(timer_s *timer)
{
    bbl_network_interface_s *network_interface = timer->data;
    if(network_interface->cfm && network_interface->cfm->cfm_cc) {
        network_interface->send_requests |= BBL_IF_SEND_CFM_CC;
    }
}

void
bbl_cfm_cc_start(bbl_cfm_session_s *cfm)
{
    time_t interval_sec = 1;
    long interval_nsec = 0;

    switch(cfm->cfm_interval) {
        case 0: interval_sec = 0; interval_nsec = 3333333; break; /* 3.3ms */
        case 1: interval_sec = 0; interval_nsec = 10000000; break; /* 10ms */
        case 2: interval_sec = 0; interval_nsec = 100000000; break; /* 100ms */
        case 3: interval_sec = 1; interval_nsec = 0; break; /* 1s */
        case 4: interval_sec = 10; interval_nsec = 0; break; /* 10s */
        case 5: interval_sec = 60; interval_nsec = 0; break; /* 1min */
        case 6: interval_sec = 600; interval_nsec = 0; break; /* 10min */
        default: interval_sec = 1; interval_nsec = 0; break;
    }

    if(cfm->session) {
        timer_add_periodic(&g_ctx->timer_root, &cfm->timer_cfm_cc, "CFM-CC", 
                           interval_sec, interval_nsec, cfm->session, &bbl_cfm_cc_session_job);

    } else if(cfm->network_interface) {
        timer_add_periodic(&g_ctx->timer_root, &cfm->timer_cfm_cc, "CFM-CC", 
                           interval_sec, interval_nsec, cfm->network_interface, &bbl_cfm_cc_interface_job);
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
                    session->cfm->cfm_rdi = status;
                } else {
                    session->cfm->cfm_cc = status;
                }   
            }
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else if (network_interface_name) {
        network_interface = bbl_network_interface_get(network_interface_name);
        if(network_interface && network_interface->cfm) {
            if(rdi) {
                network_interface->cfm->cfm_rdi = status;
            } else {
                network_interface->cfm->cfm_cc = status;
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
                    session->cfm->cfm_rdi = status;
                } else {
                    session->cfm->cfm_cc = status;
                }
            }
        }
        /* Iterate over all network interfaces */
        CIRCLEQ_FOREACH(interface, &g_ctx->interface_qhead, interface_qnode) {
            network_interface = interface->network;
            while(network_interface) {
                if(network_interface->cfm) {
                    if(rdi) {
                        network_interface->cfm->cfm_rdi = status;
                    } else {
                        network_interface->cfm->cfm_cc = status;
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
