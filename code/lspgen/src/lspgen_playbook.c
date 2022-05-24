/*
 * LSPGEN - Playbook handling
 *
 * Hannes Gredler, April 2022
 *
 * Copyright (C) 2020-2022, RtBrick, Inc.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <jansson.h>
#include "lspgen.h"
#include "lspgen_lsdb.h"

/*
 * playbook merge style / name translation table.
 */
struct keyval_ merge_style_names[] = {
    { MERGE_STYLE_REPLACE, "replace" },
    { MERGE_STYLE_ADD, "add" },
    { MERGE_STYLE_DELETE, "delete" },
    { 0, NULL}
};

void
lspgen_read_playbook_step(playbook_act_t *act, json_t *obj)
{
    playbook_step_t *step;
    json_t *value;
    char step_name[128];

    step = calloc(1, sizeof(playbook_step_t));
    if (!step) {
	return;
    }

    CIRCLEQ_INSERT_TAIL(&act->step_qhead, step, step_qnode);
    step->wait_s = 1; /* default wait */

    value = json_object_get(obj, "config_file");
    if (value && json_is_string(value)) {
	step->config_file = strdup(json_string_value(value));
    }

    value = json_object_get(obj, "merge_style");
    if (value && json_is_string(value)) {
	step->merge_style = key2val(merge_style_names, json_string_value(value));
    }

    value = json_object_get(obj, "wait_s");
    if (value && json_is_integer(value)) {
	step->wait_s = json_integer_value(value);
    }

    LOG(NORMAL, "Add playbook step, config-file %s, merge-style %s, wait %us\n",
	step->config_file, val2key(merge_style_names, step->merge_style), step->wait_s);

    /*
     * Set up a context for storing the changes in this file.
     */
    snprintf(step_name, sizeof(step_name), "act %u, step %s", act->act_num, step->config_file);
    step->change_ctx = lsdb_alloc_ctx("playbook", "isis", step_name);
    if (!step->change_ctx) {
	return;
    }
    step->change_ctx->config_filename = strdup(step->config_file);
    lspgen_read_config(step->change_ctx);
}

void
lspgen_read_playbook_act(lsdb_ctx_t *ctx, json_t *obj, uint32_t act_num)
{
    playbook_act_t *act;
    json_t *value, *step;
    uint32_t num_steps, idx;

    step = json_object_get(obj, "step");
    if (!step || !json_is_array(step)) {
	return;
    }

    act = calloc(1, sizeof(playbook_act_t));
    if (!act) {
	return;
    }

    CIRCLEQ_INSERT_TAIL(&ctx->act_qhead, act, act_qnode);
    CIRCLEQ_INIT(&act->step_qhead);
    act->act_num = act_num;

    value = json_object_get(obj, "loop_act");
    if (value && json_is_integer(value)) {
	act->loop_act = json_integer_value(value);
    }

    LOG(NORMAL, "Add playbook act #%u, loop %ux\n",
	act->act_num, act->loop_act);

    /*
     * Read all the steps.
     */
    num_steps = json_array_size(step);
    for (idx = 0; idx < num_steps; idx++) {
        lspgen_read_playbook_step(act, json_array_get(step, idx));
    }
}

void
lspgen_read_playbook_array(lsdb_ctx_t *ctx, json_t *array)
{
    uint32_t num_acts, idx;

    /*
     * Read all the acts.
     */
    num_acts = json_array_size(array);
    for (idx = 0; idx < num_acts; idx++) {
        lspgen_read_playbook_act(ctx, json_array_get(array, idx), idx);
    }
}

void
lspgen_read_playbook(lsdb_ctx_t *ctx)
{
    json_t *root_obj;
    json_error_t error;
    json_t *value, *playbook;

    root_obj = json_load_file(ctx->playbook_filename, 0, &error);
    if (!root_obj) {
        LOG(ERROR, "Error reading playbook file %s, line %d: %s\n",
            ctx->playbook_filename, error.line, error.text);
        return;
    }

    if (json_typeof(root_obj) != JSON_OBJECT) {
        LOG(ERROR, "Error reading playbook file %s, root element must be object\n",
            ctx->playbook_filename);
        return;
    }

    ctx->loop_playbook = 1; /* default */
    value = json_object_get(root_obj, "loop_playbook");
    if (value && json_is_integer(value)) {
	ctx->loop_playbook = json_integer_value(value);
    }

    LOG(NORMAL, "Reading playbook file %s, loop %ux\n", ctx->playbook_filename, ctx->loop_playbook);

    playbook = json_object_get(root_obj, "playbook");
    if (playbook && json_is_array(playbook)) {
	lspgen_read_playbook_array(ctx, playbook);
    } else {
        LOG(ERROR, "Error reading playbook file %s, no playbook object found\n",
            ctx->playbook_filename);
    }

    json_decref(root_obj);
}

void
lspgen_playbook_cb(timer_s *timer)
{
    lsdb_ctx_t *ctx;

    ctx = timer->data;

    if (CIRCLEQ_EMPTY(&ctx->act_qhead)) {
	lspgen_read_playbook(ctx);
    }
}
