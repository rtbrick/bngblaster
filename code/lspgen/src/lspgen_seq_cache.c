/*
 * Cache Sequence Numbers across LSPGEN incarnations.
 *
 * Hannes Gredler, November 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <jansson.h>
#include "lspgen.h"
#include "lspgen_lsdb.h"
#include "lspgen_isis.h"

void
lspgen_write_node_seq_cache(lsdb_node_t *node, json_t *level_arr)
{
    json_t *node_obj, *str;

    node_obj = json_object();
    str = json_string(lsdb_format_node_id(node->key.node_id));
    json_object_set_new(node_obj, "node_id", str);
    json_object_set_new(node_obj, "hostname", json_string(node->node_name));
    if (node->sequence) {
        char seq[12];
        snprintf(seq, sizeof(seq), "0x%08x", node->sequence);
        json_object_set_new(node_obj, "sequence", json_string(seq));
    }

    json_array_append(level_arr, node_obj);
    json_decref(node_obj);
}

void
lspgen_write_seq_cache(lsdb_ctx_t *ctx)
{
    struct lsdb_node_ *node;
    dict_itor *itor;
    json_t *root_obj, *arr;
    int res;
    uint32_t num_nodes;
    char seq_cache_filename[32];

    snprintf(seq_cache_filename, sizeof(seq_cache_filename),
	     "level%u-sequence-cache.json", ctx->topology_id.level);

    ctx->seq_cache_file = fopen(seq_cache_filename, "w");
    if (!ctx->seq_cache_file) {
        LOG(ERROR, "Error opening sequence cache file %s\n", seq_cache_filename);
        return;
    }

    /* Walk the node DB. */
    itor = dict_itor_new(ctx->node_dict);
    if (!itor) {
        return;
    }

    /* Node DB empty? */
    if (!dict_itor_first(itor)) {
        dict_itor_free(itor);
        LOG_NOARG(ERROR, "Empty LSDB.\n");
        return;
    }

    root_obj = json_object();
    arr = json_array();
    json_object_set_new(root_obj, val2key(isis_level_names, ctx->topology_id.level), arr);

    num_nodes = 0;
    do {
        node = *dict_itor_datum(itor);
        lspgen_write_node_seq_cache(node, arr);
	num_nodes++;
    } while (dict_itor_next(itor));
    dict_itor_free(itor);

    res = json_dumpf(root_obj, ctx->seq_cache_file, JSON_INDENT(2));
    if (res == -1) {
        LOG(ERROR, "Error writing sequence cache file %s\n", seq_cache_filename);
    }

    /* Done */
    json_decref(root_obj);
    fclose(ctx->seq_cache_file);
    ctx->seq_cache_file = NULL;

    LOG(NORMAL, "Wrote %d nodes to file %s\n", num_nodes, seq_cache_filename);
}
