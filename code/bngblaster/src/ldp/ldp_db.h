/*
 * BNG Blaster (BBL) - LDP Database
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_LDP_DB_H__
#define __BBL_LDP_DB_H__

bool
ldb_db_init(ldp_instance_s *instance);

bool
ldb_db_add_ipv4(ldp_session_s *session, ipv4_prefix *prefix, uint32_t label);

#endif