/*
 * BNG Blaster (BBL) - IS-IS MRT Files
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "isis.h"

bool
isis_mrt_load(isis_instance_s *instance, char *file_path)
{
    FILE *mrt_file;

    isis_mrt_hdr_t mrt = {0};
    isis_pdu_s pdu = {0};
    uint8_t level;
    uint8_t pdu_buf[ISIS_MAX_PDU_LEN];

    isis_lsp_s *lsp = NULL;
    uint64_t lsp_id;
    uint32_t seq;

    hb_tree *lsdb;
    void **search = NULL;
    dict_insert_result result;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    LOG(ISIS, "Load ISIS MRT file %s\n", file_path);

    mrt_file = fopen(file_path, "r");
    if(!mrt_file) {
        LOG(ERROR, "Failed to open MRT file %s\n", file_path);
        return false;
    }

    while(fread(&mrt, sizeof(isis_mrt_hdr_t), 1, mrt_file) == 1) {
        mrt.type = be16toh(mrt.type);
        mrt.subtype = be16toh(mrt.subtype);
        mrt.length = be32toh(mrt.length);
        //LOG(DEBUG, "MRT type: %u subtype: %u length: %u\n", mrt.type, mrt.subtype, mrt.length);
        if(!(mrt.type == ISIS_MRT_TYPE && 
             mrt.subtype == 0 &&
             mrt.length >= ISIS_HDR_LEN_COMMON &&
             mrt.length <= ISIS_MAX_PDU_LEN)) {
            LOG(ERROR, "Invalid MRT file %s\n", file_path);
            fclose(mrt_file);
            return false;
        }
        if(fread(pdu_buf, mrt.length, 1, mrt_file) != 1) {
            LOG(ERROR, "Invalid MRT file %s\n", file_path);
            fclose(mrt_file);
            return false;
        }
        if(isis_pdu_load(&pdu, pdu_buf, mrt.length) != PROTOCOL_SUCCESS) {
            LOG(ERROR, "Failed to load PDU from MRT file %s\n", file_path);
            fclose(mrt_file);
            return false;
        }
        switch (pdu.pdu_type) {
            case ISIS_PDU_L1_LSP:
                level = ISIS_LEVEL_1;
                break;
            case ISIS_PDU_L2_LSP:
                level = ISIS_LEVEL_2;
                break;
            default:
                LOG(ERROR, "Skip record from MRT file %s\n", file_path);
                continue;
        }

        lsp_id = be64toh(*(uint64_t*)PDU_OFFSET(&pdu, ISIS_OFFSET_LSP_ID));
        seq = be32toh(*(uint32_t*)PDU_OFFSET(&pdu, ISIS_OFFSET_LSP_SEQ));

        LOG(DEBUG, "ISIS ADD %s-LSP %s (seq %u) from MRT file to instance %u\n", 
            isis_level_string(level), 
            isis_lsp_id_to_str(&lsp_id), 
            seq, instance->config->id);

        /* Get LSDB */
        lsdb = instance->level[level-1].lsdb;
        search = hb_tree_search(lsdb, &lsp_id);
        if(search) {
            /* Update existing LSP. */
            lsp = *search;
            if(lsp->source.type == ISIS_SOURCE_SELF) {
                LOG_NOARG(ISIS, "Failed to add LSP to LSDB (overwriting self LSP not permitted)\n");
                fclose(mrt_file);
                return false;
            }
        } else {
            /* Create new LSP. */
            lsp = isis_lsp_new(lsp_id, level, instance);
            result = hb_tree_insert(lsdb,  &lsp->id);
            if (result.inserted) {
                *result.datum_ptr = lsp;
            } else {
                LOG_NOARG(ISIS, "Failed to add LSP to LSDB\n");
                fclose(mrt_file);
                return false;
            }
        }

        lsp->level = level;
        lsp->source.type = ISIS_SOURCE_EXTERNAL;
        lsp->source.adjacency = NULL;
        lsp->seq = seq;
        lsp->lifetime = be16toh(*(uint32_t*)PDU_OFFSET(&pdu, ISIS_OFFSET_LSP_LIFETIME));
        lsp->expired = false;
        lsp->instance = instance;
        lsp->timestamp.tv_sec = now.tv_sec;
        lsp->timestamp.tv_nsec = now.tv_nsec;

        PDU_CURSOR_RST(&pdu);
        memcpy(&lsp->pdu, &pdu, sizeof(isis_pdu_s));

        timer_add(&g_ctx->timer_root, 
                  &lsp->timer_lifetime, 
                  "ISIS LIFETIME", lsp->lifetime, 0, lsp,
                  &isis_lsp_lifetime_job);
    }
    fclose(mrt_file);
    return true;
}
