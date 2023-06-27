/*
 * BNG Blaster (BBL) - OSPF LSA
 *
 * Christian Giese, May 2023
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_OSPF_LSA_H__
#define __BBL_OSPF_LSA_H__

void
ospf_lsa_gc_job(timer_s *timer);

void
ospf_lsa_update_age(ospf_lsa_s *lsa, struct timespec *now);

#endif