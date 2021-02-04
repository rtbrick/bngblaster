/*
 * BNG Blaster (BBL) - Control Socket
 *
 * Christian Giese, January 2021
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */

#ifndef __BBL_CTRL_H__
#define __BBL_CTRL_H__

bool
bbl_ctrl_socket_open (bbl_ctx_s *ctx);

bool
bbl_ctrl_socket_close (bbl_ctx_s *ctx);

#endif
