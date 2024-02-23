/*
 * BNG Blaster (BBL) - Access Line Profile
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ACCESS_LINE_H__
#define __BBL_ACCESS_LINE_H__

typedef struct bbl_access_line_profile_
{
    uint16_t access_line_profile_id;
    uint8_t pon_access_line_version;
    /* broadband forum tr101 */

    uint32_t act_up; /* Actual Data Rate Upstream */
    uint32_t act_down; /* Actual Data Rate Downstream */
    uint32_t min_up; /* Minimum Data Rate Upstream */
    uint32_t min_down; /* Minimum Data Rate Downstream */
    uint32_t att_up; /* Attainable DataRate Upstream */
    uint32_t att_down; /* Attainable DataRate Downstream */
    uint32_t max_up; /* Maximum Data Rate Upstream */
    uint32_t max_down; /* Maximum Data Rate Downstream */
    uint32_t min_up_low; /* Min Data Rate Upstream in low power state */
    uint32_t min_down_low; /* Min Data Rate Downstream in low power state */
    uint32_t max_interl_delay_up; /* Max Interleaving Delay Upstream */
    uint32_t act_interl_delay_up; /* Actual Interleaving Delay Upstream */
    uint32_t max_interl_delay_down; /* Max Interleaving Delay Downstream */
    uint32_t act_interl_delay_down; /* Actual Interleaving Delay Downstream */
    uint32_t data_link_encaps; /* Data Link Encapsulation */
    uint32_t dsl_type; /* DSL Type */

    /* draft-lihawi-ancp-protocol-access-extension-04 */

    uint32_t pon_type; /* PON-Access-Type */
    uint32_t etr_up; /* Expected Throughput (ETR) Upstream */
    uint32_t etr_down; /* Expected Throughput (ETR) Downstream */
    uint32_t attetr_up; /* Attainable Expected Throughput (ATTETR) Upstream */
    uint32_t attetr_down; /* Attainable Expected Throughput (ATTETR) Downstream */
    uint32_t gdr_up; /* Gamma Data Rate (GDR) Upstream */
    uint32_t gdr_down; /* Gamma Data Rate (GDR) Downstream */
    uint32_t attgdr_up; /* Attainable Gamma Data Rate (ATTGDR) Upstream */
    uint32_t attgdr_down; /* Attainable Gamma Data Rate (ATTGDR) Downstream */
    uint32_t ont_onu_avg_down; /* ONT/ONU-Average-Data-Rate-Downstream */
    uint32_t ont_onu_peak_down; /* ONT/ONU-Peak-Data-Rate-Downstream */
    uint32_t ont_onu_max_up; /* ONT/ONU-Maximum-Data-Rate-Upstream */
    uint32_t ont_onu_ass_up; /* ONT/ONU-Assured-Data-Rate-Upstream */
    uint32_t pon_max_up; /* PON-Tree-Maximum-Data-Rate-Upstream */
    uint32_t pon_max_down; /* PON-Tree-Maximum-Data-Rate-Downstream */

    void *next; /* pointer to next access line profile element */
} bbl_access_line_profile_s;

#endif