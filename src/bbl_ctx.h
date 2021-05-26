/*
 * BNG Blaster (BBL) - Global Context
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef __BBL_CONTEXT_H__
#define __BBL_CONTEXT_H__

bbl_ctx_s *
bbl_ctx_add(void);

void
bbl_ctx_del(bbl_ctx_s *ctx);

#endif
