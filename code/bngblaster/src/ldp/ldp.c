/*
 * BNG Blaster (BBL) - LDP Functions
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ldp.h"


/**
 * ldp_id_to_str
 *
 * @param lsr_id LDP LSR ID
 * @param label_space_id LDP label space

 * @return LDP identifier string
 */
char *
ldp_id_to_str(uint32_t lsr_id, uint16_t label_space_id)
{
    static char buffer[4][LDP_IDENTIFIER_STR_LEN];
    static int idx = 0;
    char *ret;
    ret = buffer[idx];
    idx = (idx+1) & 3;

    snprintf(ret, LDP_IDENTIFIER_STR_LEN, "%s:%u",
             format_ipv4_address(&lsr_id), 
             label_space_id);

    return ret;
}

/**
 * ldp_init
 * 
 * This function inits all LDP sessions. 
 */
bool
ldp_init()
{
    ldp_config_s *config = g_ctx->config.ldp_config;
    ldp_instance_s *instance = NULL;

    while(config) {
        LOG(LDP, "Init LDP instance %u\n", config->id);
        if(instance) {
            instance->next = calloc(1, sizeof(ldp_instance_s));
            instance = instance->next;
        } else {
            instance = calloc(1, sizeof(ldp_instance_s));
            g_ctx->ldp_instances = instance;
        }
        instance->config = config;
        ldb_db_init(instance);
        config = config->next;
    }
    return true;
}

void
ldp_teardown_job(timer_s *timer) {
    ldp_instance_s *instance = timer->data;
    UNUSED(instance);
}

/**
 * ldp_teardown
 * 
 * This function stops all LDP sessions. 
 */
void
ldp_teardown()
{
    ldp_instance_s *instance = g_ctx->ldp_instances;
    ldp_session_s *session;
    while(instance) {
        if(!instance->teardown) {
            LOG(LDP, "Teardown LDP instance %u\n", instance->config->id);
            instance->teardown = true;
            session = instance->sessions;
            while(session) {
                session->teardown = true;
                ldp_session_close(session);
                session = session->next;
            }
            timer_add(&g_ctx->timer_root, &instance->teardown_timer, 
                      "LDP TEARDOWN", instance->config->teardown_time, 0, instance,
                      &ldp_teardown_job);
        }
        instance = instance->next;
    }
}