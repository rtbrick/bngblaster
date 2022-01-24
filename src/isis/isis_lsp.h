/*
 * BNG Blaster (BBL) - IS-IS LSP
 *
 * Christian Giese, January 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_LSP_H__
#define __BBL_ISIS_LSP_H__

void
isis_lsp_flood_adjacency(isis_lsp_t *lsp, isis_adjacency_t *adjacency);

void
isis_lsp_flood(isis_lsp_t *lsp);

void
isis_lsp_process_entries(isis_adjacency_t *adjacency, hb_tree *lsdb, isis_pdu_t *pdu, uint64_t csnp_scan);

void
isis_lsp_retry_job(timer_s *timer);

void
isis_lsp_refresh_job(timer_s *timer);

void
isis_lsp_tx_job(timer_s *timer);

bool
isis_lsp_self_update(bbl_ctx_s *ctx, isis_instance_t *instance, uint8_t level);

void
isis_lsp_handler_rx(bbl_interface_s *interface, isis_pdu_t *pdu, uint8_t level);

#endif