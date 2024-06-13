/*
 * BNG Blaster (BBL) - IS-IS PSNP
 *
 * Christian Giese, February 2022
 *
 * Copyright (C) 2020-2024, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_PSNP_H__
#define __BBL_ISIS_PSNP_H__

void
isis_psnp_job (timer_s *timer);

void
isis_psnp_handler_rx(bbl_network_interface_s *interface, isis_pdu_s *pdu, uint8_t level);

void
isis_psnp_tree_add(isis_adjacency_s *adjacency, isis_lsp_s *lsp);

#endif