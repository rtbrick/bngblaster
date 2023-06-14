/*
 * BNG Blaster (BBL) - IS-IS LSP
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_LSP_H__
#define __BBL_ISIS_LSP_H__

void
isis_lsp_flood_adjacency(isis_lsp_s *lsp, isis_adjacency_s *adjacency);

void
isis_lsp_flood(isis_lsp_s *lsp);

void
isis_lsp_process_entries(isis_adjacency_s *adjacency, hb_tree *lsdb, isis_pdu_s *pdu, uint64_t csnp_scan);

void
isis_lsp_gc_job(timer_s *timer);

void
isis_lsp_retry_job(timer_s *timer);

void
isis_lsp_refresh(isis_lsp_s *lsp);

void
isis_lsp_refresh_job(timer_s *timer);

void
isis_lsp_lifetime(isis_lsp_s *lsp);

void
isis_lsp_tx_job(timer_s *timer);

isis_lsp_s *
isis_lsp_new(uint64_t id, uint8_t level, isis_instance_s *instance);

bool
isis_lsp_self_update(isis_instance_s *instance, uint8_t level);

void
isis_lsp_handler_rx(bbl_network_interface_s *interface, isis_pdu_s *pdu, uint8_t level);

void
isis_lsp_purge(isis_lsp_s *lsp);

void
isis_lsp_purge_all_external(isis_instance_s *instance, uint8_t level);

bool
isis_lsp_update_external(isis_instance_s *instance, isis_pdu_s *pdu, bool refresh);

bool
isis_lsp_flap(isis_lsp_s *lsp, time_t timer);

#endif