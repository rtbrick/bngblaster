/*
 * BNG Blaster (BBL) - CFM Functions
 *
 * Christian Giese, October 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "bbl.h"

static int
bbl_cfm_ctrl_cc_start_stop(int fd, uint32_t session_id, bool status)
{
    bbl_session_s *session;
    uint32_t i;
    if(session_id) {
        session = bbl_session_get(session_id);
        if(session) {
            session->cfm_cc = status;
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            if(session) {
                session->cfm_cc = status;
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

int
bbl_cfm_ctrl_cc_start(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)))
{
    return bbl_cfm_ctrl_cc_start_stop(fd, session_id, true);
}

int
bbl_cfm_ctrl_cc_stop(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)))
{
    return bbl_cfm_ctrl_cc_start_stop(fd, session_id, false);
}

static int
bbl_cfm_ctrl_cc_rdi(int fd, uint32_t session_id, bool status)
{
    bbl_session_s *session;
    uint32_t i;
    if(session_id) {
        session = bbl_session_get(session_id);
        if(session) {
            session->cfm_rdi = status;
            return bbl_ctrl_status(fd, "ok", 200, NULL);
        } else {
            return bbl_ctrl_status(fd, "warning", 404, "session not found");
        }
    } else {
        /* Iterate over all sessions */
        for(i = 0; i < g_ctx->sessions; i++) {
            session = &g_ctx->session_list[i];
            if(session) {
                session->cfm_rdi = status;
            }
        }
        return bbl_ctrl_status(fd, "ok", 200, NULL);
    }
}

int
bbl_cfm_ctrl_cc_rdi_on(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)))
{
    return bbl_cfm_ctrl_cc_rdi(fd, session_id, true);
}

int
bbl_cfm_ctrl_cc_rdi_off(int fd, uint32_t session_id, json_t *arguments __attribute__((unused)))
{
    return bbl_cfm_ctrl_cc_rdi(fd, session_id, false);
}