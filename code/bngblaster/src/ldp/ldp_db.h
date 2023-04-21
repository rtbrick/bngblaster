/*
 * BNG Blaster (BBL) - LDP Database
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_LDP_DB_H__
#define __BBL_LDP_DB_H__

bool
ldb_db_init(ldp_instance_s *instance);

bool
ldb_db_add_ipv4(ldp_session_s *session, ipv4_prefix *prefix, uint32_t label);

ldp_db_entry_s *
ldb_db_lookup_ipv4(ldp_instance_s *instance, uint32_t address);

bool
ldb_db_add_ipv6(ldp_session_s *session, ipv6_prefix *prefix, uint32_t label);

ldp_db_entry_s *
ldb_db_lookup_ipv6(ldp_instance_s *instance, ipv6addr_t *address);

#endif