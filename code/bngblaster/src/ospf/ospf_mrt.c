/*
 * BNG Blaster (BBL) - OSPF MRT Files
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

extern uint8_t g_pdu_buf[];

bool
ospf_mrt_load(ospf_instance_s *instance, char *file_path, bool startup)
{
    FILE *mrt_file = NULL;
    ospf_mrt_hdr_t mrt = {0};

    ospf_pdu_s pdu = {0};
    uint32_t lsa_count = 0;

    LOG(OSPF, "Load OSPF MRT file %s\n", file_path);

    mrt_file = fopen(file_path, "r");
    if(!mrt_file) {
        LOG(ERROR, "Failed to open MRT file %s\n", file_path);
        return false;
    }

    while(fread(&mrt, sizeof(ospf_mrt_hdr_t), 1, mrt_file) == 1) {
        mrt.type = be16toh(mrt.type);
        mrt.subtype = be16toh(mrt.subtype);
        mrt.length = be32toh(mrt.length);
        //LOG(DEBUG, "MRT type: %u subtype: %u length: %u\n", mrt.type, mrt.subtype, mrt.length);

        if(!(mrt.subtype == 0 && mrt.length <= OSPF_PDU_LEN_MAX)) {
            LOG(ERROR, "Invalid MRT file %s\n", file_path);
            fclose(mrt_file);
            return false;
        }
        if(fread(g_pdu_buf, mrt.length, 1, mrt_file) != 1) {
            LOG(ERROR, "Invalid MRT file %s\n", file_path);
            fclose(mrt_file);
            return false;
        }

        if(mrt.type == OSPFv2_MRT_TYPE && mrt.length >= (OSPFv2_MRT_PDU_OFFSET+OSPF_PDU_LEN_MIN)) {
            if(ospf_pdu_load(&pdu, g_pdu_buf+OSPFv2_MRT_PDU_OFFSET, mrt.length-OSPFv2_MRT_PDU_OFFSET) != PROTOCOL_SUCCESS) {
                LOG(ERROR, "Invalid OSPFv2 MRT file %s (PDU load error)\n", file_path);
                fclose(mrt_file);
                return false;
            }
            if(pdu.pdu_version != OSPF_VERSION_2) {
                LOG(ERROR, "Invalid OSPFv2 MRT file %s (wrong PDU version)\n", file_path);
                fclose(mrt_file);
                return false;
            }
            if(pdu.pdu_len < OSPFV2_LS_UPDATE_LEN_MIN) {
                LOG(ERROR, "Invalid OSPFv2 MRT file %s (wrong PDU len)\n", file_path);
                fclose(mrt_file);
                return false;
            }
            lsa_count = be32toh(*(uint32_t*)OSPF_PDU_OFFSET(&pdu, OSPFV2_OFFSET_LS_UPDATE_COUNT));
            OSPF_PDU_CURSOR_SET(&pdu, OSPFV2_OFFSET_LS_UPDATE_LSA);
        } else if(mrt.type == OSPFv3_MRT_TYPE && mrt.length >= (OSPFv3_MRT_PDU_OFFSET+OSPF_PDU_LEN_MIN)) {
            if(ospf_pdu_load(&pdu, g_pdu_buf+OSPFv3_MRT_PDU_OFFSET, mrt.length-OSPFv3_MRT_PDU_OFFSET) != PROTOCOL_SUCCESS) {
                LOG(ERROR, "Invalid OSPFv3 MRT file %s (PDU load error)\n", file_path);
                fclose(mrt_file);
                return false;
            }
            if(pdu.pdu_version != OSPF_VERSION_3) {
                LOG(ERROR, "Invalid OSPFv3 MRT file %s (wrong PDU version)\n", file_path);
                fclose(mrt_file);
                return false;
            }
            if(pdu.pdu_len < OSPFV3_LS_UPDATE_LEN_MIN) {
                LOG(ERROR, "Invalid OSPFv3 MRT file %s (wrong PDU len)\n", file_path);
                fclose(mrt_file);
                return false;
            }
            lsa_count = be32toh(*(uint32_t*)OSPF_PDU_OFFSET(&pdu, OSPFV3_OFFSET_LS_UPDATE_COUNT));
            OSPF_PDU_CURSOR_SET(&pdu, OSPFV3_OFFSET_LS_UPDATE_LSA);
        } else {
            LOG(ERROR, "Invalid MRT file %s (wrong MRT type)\n", file_path);
            fclose(mrt_file);
            return false;
        }
        if(pdu.pdu_type != OSPF_PDU_LS_UPDATE) {
            LOG(ERROR, "Invalid MRT file %s (wrong PDU type)\n", file_path);
            fclose(mrt_file);
            return false;
        }
        if(pdu.pdu_version != instance->config->version) {
            LOG(ERROR, "Invalid MRT file %s (wrong version)\n", file_path);
            fclose(mrt_file);
            return false;
        }
        if(!ospf_lsa_load_external(instance, lsa_count, OSPF_PDU_CURSOR(&pdu), OSPF_PDU_CURSOR_LEN(&pdu))) {
            LOG(ERROR, "Invalid MRT file %s (LSA load error)\n", file_path);
            fclose(mrt_file);
            return false;
        }
    }

    if(startup) {
        /* Adding 3 nanoseconds to enforce a dedicated timer bucket. */
        timer_smear_bucket(&g_ctx->timer_root, OSPF_LSA_REFRESH_TIME, 3);
    }

    fclose(mrt_file);
    return true;
}