/*
 * BNG Blaster (BBL) - IS-IS CTRL (Control Commands)
 *
 * Christian Giese, January 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#ifndef __BBL_ISIS_CTRL_H__
#define __BBL_ISIS_CTRL_H__

json_t *
isis_ctrl_adjacency_p2p(isis_adjacency_p2p_t *adjacency);

json_t *
isis_ctrl_adjacency(isis_adjacency_t *adjacency);

json_t *
isis_ctrl_database(hb_tree *lsdb);

#endif