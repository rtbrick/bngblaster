/*
 * BNG Blaster (BBL) - LDP Interface
 *
 * Christian Giese, November 2022
 *
 * Copyright (C) 2020-2026, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_LDP_INTERFACE_H__
#define __BBL_LDP_INTERFACE_H__

bool 
ldp_interface_init(bbl_network_interface_s *interface,
                   bbl_network_config_s *interface_config,
                   ldp_instance_s *instance);

#endif