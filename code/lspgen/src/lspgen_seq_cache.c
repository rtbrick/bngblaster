/*
 * Cache Sequence Numbers across LSPGEN incarnations.
 *
 * Hannes Gredler, November 2022
 *
 * Copyright (C) 2020-2023, RtBrick, Inc.
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

void
lspgen_read_node_seq_cache(lsdb_ctx_t *ctx, json_t *node_obj)
{
    struct lsdb_node_ node_template;
    struct lsdb_node_ *node;
    char *s;

    /*
     * Read the node sequence information and bump it by one in the LSDB.
     */
    memset(&node_template, 0, sizeof(node_template));
    if (json_unpack(node_obj, "{s:s}", "node_id", &s) == 0) {
        lsdb_scan_node_id(node_template.key.node_id, s);

        if (json_unpack(node_obj, "{s:s}", "hostname", &s) == 0) {
            node_template.node_name = s;
        }

        node = lsdb_get_node(ctx, &node_template);
	if (!node) {
	    return;
	}

        if (json_unpack(node_obj, "{s:s}", "sequence", &s) == 0) {
            node->sequence = strtol(s, NULL, 0) + 1;
        }
    }
}

void
lspgen_read_level_seq_cache(lsdb_ctx_t *ctx, json_t *level_arr)
{
    uint32_t num_nodes, idx;

    num_nodes = json_array_size(level_arr);
    for (idx = 0; idx < num_nodes; idx++) {
        lspgen_read_node_seq_cache(ctx, json_array_get(level_arr, idx));
    }
}

void
lspgen_read_seq_cache(lsdb_ctx_t *ctx)
{
    json_t *root_obj;
    json_error_t error;
    json_t *level;

    char seq_cache_filename[32];

    snprintf(seq_cache_filename, sizeof(seq_cache_filename),
	     "level%u-sequence-cache.json", ctx->topology_id.level);

    root_obj = json_load_file(seq_cache_filename, 0, &error);
    if (!root_obj) {

	/* Probably no file found */
        return;
    }

    if (json_typeof(root_obj) != JSON_OBJECT) {
        LOG(ERROR, "Error reading sequence cache file %s, root element must be object\n",
            seq_cache_filename);
        return;
    }

    LOG(NORMAL, "Reading sequence cache file %s\n", seq_cache_filename);

    switch(ctx->topology_id.level) {
    case 1:
	level = json_object_get(root_obj, "level1");
	if (level && json_is_array(level)) {
	    lspgen_read_level_seq_cache(ctx, level);
	}
	break;
    case 2:
	level = json_object_get(root_obj, "level2");
	if (level && json_is_array(level)) {
	    lspgen_read_level_seq_cache(ctx, level);
	}
	break;
    default:
	break;
    }

    json_decref(root_obj);
}
