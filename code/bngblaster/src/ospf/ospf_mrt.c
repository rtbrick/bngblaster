/*
 * BNG Blaster (BBL) - OSPF MRT Files
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include "ospf.h"

bool
ospf_mrt_load(ospf_instance_s *instance, char *file_path)
{
    FILE *mrt_file;

    ospf_mrt_hdr_t mrt = {0};
    uint8_t lsa_buf[UINT16_MAX];

    ospf_lsa_header_s *hdr;
    ospf_lsa_key_s *key;
    ospf_lsa_s *lsa;

    void **search = NULL;
    dict_insert_result result;

    uint16_t lsa_len;
    uint8_t  lsa_type;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

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
             mrt.length >= OSPF_LSA_HDR_LEN &&
             mrt.length <= UINT16_MAX)) {
            LOG(ERROR, "Invalid MRT file %s\n", file_path);
            fclose(mrt_file);
            return false;
        }
        if(fread(lsa_buf, mrt.length, 1, mrt_file) != 1) {
            LOG(ERROR, "Invalid MRT file %s\n", file_path);
            fclose(mrt_file);
            return false;
        }

        hdr = (ospf_lsa_header_s*)lsa_buf;
        key = (ospf_lsa_key_s*)&hdr->id;

        lsa_type = hdr->type;
        if(lsa_type < OSPF_LSA_TYPE_1 || lsa_type > OSPF_LSA_TYPE_11) {
            LOG(ERROR, "Failed to load LSA from MRT file %s (invalid LSA type)\n", file_path);
            fclose(mrt_file);
            return false;
        }
        lsa_len = be16toh(hdr->length);
        if(lsa_len > mrt.length) {
            LOG(ERROR, "Failed to load LSA from MRT file %s (invalid LSA len)\n", file_path);
            fclose(mrt_file);
            return false;
        }

        search = hb_tree_search(instance->lsdb[lsa_type], key);
        if(search) {
            lsa = *search;
        } else {
            /* NEW LSA */
            lsa = ospf_lsa_new(lsa_type, key, instance);
            result = hb_tree_insert(instance->lsdb[lsa_type], &lsa->key);
            assert(result.inserted);
            if(result.inserted) {
                *result.datum_ptr = lsa;
            } else {
                LOG_NOARG(OSPF, "Failed to add OSPF LSA to LSDB\n");
                return false;
            }
        }

        if(lsa->lsa_buf_len < lsa_len) {
            if(lsa->lsa) free(lsa->lsa);
            lsa->lsa = malloc(lsa_len);
            lsa->lsa_buf_len = lsa_len;
        }
        memcpy(lsa->lsa, hdr, lsa_len);
        lsa->lsa_len = lsa_len;
        lsa->source.type = OSPF_SOURCE_EXTERNAL;
        lsa->source.router_id = 0;
        lsa->seq = be32toh(hdr->seq);
        lsa->age = be16toh(hdr->age)+1;
        lsa->timestamp.tv_sec = now.tv_sec;
        lsa->timestamp.tv_nsec = now.tv_sec;
        ospf_lsa_update_age(lsa, &now);
        ospf_lsa_flood(lsa);
        ospf_lsa_lifetime(lsa);
    }

    fclose(mrt_file);
    return true;
}