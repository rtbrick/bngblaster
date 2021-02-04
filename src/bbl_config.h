/*
 * BNG Blaster (BBL) - Configuration
 *
 * Christian Giese, October 2020
 *
 * Copyright (C) 2020-2021, RtBrick, Inc.
 */
#ifndef __BBL_CONFIG_H__
#define __BBL_CONFIG_H__

bool
bbl_config_load_json(char *filename, bbl_ctx_s *ctx);

void
bbl_config_init_defaults(bbl_ctx_s *ctx);

#endif
