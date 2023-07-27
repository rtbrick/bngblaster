/*
 * BNG Blaster (BBL) - OSPF MRT Files
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

extern uint8_t g_pdu_buf[];

bool
ospf_mrt_load(ospf_instance_s *instance, char *file_path)
{
    FILE *mrt_file;
    ospf_mrt_hdr_t mrt = {0};

    ospf_pdu_s pdu = {0};
    uint32_t lsa_count;

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
        if(!(mrt.type == OSPF_MRT_TYPE && 
             mrt.subtype == 0 &&
             mrt.length >= OSPF_PDU_LEN_MIN &&
             mrt.length <= OSPF_PDU_LEN_MAX)) {
            LOG(ERROR, "Invalid MRT file %s\n", file_path);
            fclose(mrt_file);
            return false;
        }
        if(fread(g_pdu_buf, mrt.length, 1, mrt_file) != 1) {
            LOG(ERROR, "Invalid MRT file %s\n", file_path);
            fclose(mrt_file);
            return false;
        }
        if(ospf_pdu_load(&pdu, g_pdu_buf, mrt.length) != PROTOCOL_SUCCESS) {
            LOG(ERROR, "Invalid MRT file %s (PDU load error)\n", file_path);
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
        if(pdu.pdu_version == OSPF_VERSION_2) {
            if(pdu.pdu_len < OSPFV2_LS_UPDATE_LEN_MIN) {
                LOG(ERROR, "Invalid MRT file %s (wrong PDU len)\n", file_path);
                fclose(mrt_file);
                return false;
            }
            lsa_count = be32toh(*(uint32_t*)OSPF_PDU_OFFSET(&pdu, OSPFV2_OFFSET_LS_UPDATE_COUNT));
            OSPF_PDU_CURSOR_SET(&pdu, OSPFV2_OFFSET_LS_UPDATE_LSA);
        } else {
            if(pdu.pdu_len < OSPFV3_LS_UPDATE_LEN_MIN) {
                LOG(ERROR, "Invalid MRT file %s (wrong PDU len)\n", file_path);
                fclose(mrt_file);
                return false;
            }
            lsa_count = be32toh(*(uint32_t*)OSPF_PDU_OFFSET(&pdu, OSPFV3_OFFSET_LS_UPDATE_COUNT));
            OSPF_PDU_CURSOR_SET(&pdu, OSPFV3_OFFSET_LS_UPDATE_LSA);
        }
        if(!ospf_lsa_load_external(instance, lsa_count, OSPF_PDU_CURSOR(&pdu), OSPF_PDU_CURSOR_LEN(&pdu))) {
            LOG(ERROR, "Invalid MRT file %s (LSA load error)\n", file_path);
            fclose(mrt_file);
            return false;
        }
    }

    fclose(mrt_file);
    return true;
}