/*
 * Generic Link State Packet generation for link-state protocols.
 *
 * Hannes Gredler, January 2022
 *
 * Copyright (C) 2015-2022, RtBrick, Inc.
 */

/*
 *  Graph generation code extracted from
 *
 *                  A Graph Generation Package
 *             Richard Johnsonbaugh and Martin Kalin
 *    Department of Computer Science and Information Systems
 *                       DePaul University
 *                      Chicago, IL  60604
 *           johnsonbaugh@cs.depaul.edu, kalin@cs.depaul.edu
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "lspgen.h"
#include "lspgen_lsdb.h"

int weights[13] = { 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 20000, 50000, 100000 };

/*
 * Return a random integer between 0 and k-1 inclusive.
 */
int
ran(int k)
{
    return rand() % k;
}

void
swap(int *a, int *b)
{
    int temp;

    temp = *a;
    *a = *b;
    *b = temp;
}

/*
 * randomly permute a[ 0 ],...,a[ n - 1 ]
 */
void
permute(int *a, int n)
{
    int i;

    for (i = 0; i < n - 1; i++) {
        swap(a + i + ran(n - i), a + i);
    }
}

/*
 * set a[ i ] = i, for i = 0,...,end - 1
 */
void
init_array(int *a, int end)
{
    int i;
    for (i = 0; i < end; i++) {
        *a++ = i;
    }
}

void
print_graph(lsdb_ctx_t *ctx, int v, int e, int *adj_matrix)
{
    struct lsdb_node_ node_template;
    struct lsdb_link_ link_template;
    struct lsdb_node_ *local_node, *remote_node;
    char node_name[32];
    int i, j, index;
    unsigned int root = 0;
    __uint128_t addr;

    UNUSED(e);

    memset(&node_template, 0, sizeof(node_template));
    memset(&link_template, 0, sizeof(link_template));

    for (i = 1; i < v; i++) {
        for (j = i + 1; j <= v; j++) {
            index = (i - 1) * v + j - 1;
            if (adj_matrix[index]) {

            if (!root) {
                root = i;
            }

            /*
             * Add local node.
             */
            addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t)) + i - 1;
	    if (ctx->protocol_id == PROTO_ISIS) {
		lspgen_store_bcd_addr(addr, node_template.key.node_id, 4);
	    } else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
		lspgen_store_addr(addr, node_template.key.node_id, 4);
	    }
	    snprintf(node_name, sizeof(node_name), "node%u", i);
            node_template.node_name = node_name;
            local_node = lsdb_add_node(ctx, &node_template);

            /*
             * Add remote node.
             */
            addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t)) + j - 1;
	    if (ctx->protocol_id == PROTO_ISIS) {
		lspgen_store_bcd_addr(addr, node_template.key.node_id, 4);
	    } else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
		lspgen_store_addr(addr, node_template.key.node_id, 4);
	    }
	    snprintf(node_name, sizeof(node_name), "node%u", j);
            node_template.node_name = node_name;
            remote_node = lsdb_add_node(ctx, &node_template);

            /*
             * Add outgoing link.
             */
            link_template.link_metric = weights[adj_matrix[index]];
            addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t)) + i - 1;
	    if (ctx->protocol_id == PROTO_ISIS) {
		lspgen_store_bcd_addr(addr, link_template.key.local_node_id, 4);
	    } else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
		lspgen_store_addr(addr, link_template.key.local_node_id, 4);
	    }
	    addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t)) + j - 1;
	    if (ctx->protocol_id == PROTO_ISIS) {
		lspgen_store_bcd_addr(addr, link_template.key.remote_node_id, 4);
	    } else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
		lspgen_store_addr(addr, link_template.key.remote_node_id, 4);
            }
	    lsdb_add_link(ctx, local_node, &link_template);

            /*
             * Add incoming link.
             */
            addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t)) + j - 1;
	    if (ctx->protocol_id == PROTO_ISIS) {
		lspgen_store_bcd_addr(addr, link_template.key.local_node_id, 4);
	    } else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
		lspgen_store_addr(addr, link_template.key.local_node_id, 4);
	    }
            addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t)) + i - 1;
	    if (ctx->protocol_id == PROTO_ISIS) {
		lspgen_store_bcd_addr(addr, link_template.key.remote_node_id, 4);
	    } else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
		lspgen_store_addr(addr, link_template.key.remote_node_id, 4);
            }
	    lsdb_add_link(ctx, remote_node, &link_template);
            }
        }
    }

    /*
     * Store root.
     */
    addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t)) + root - 1;
    lspgen_store_bcd_addr(addr, ctx->root_node_id, 4);
}

/*
 * This function generates a random connected simple graph with v vertices and max(v-1,e) edges.  The graph can be
 * weighted (weight_flag == 1) or unweighted (weight_flag != 1). If it is weighted, the weights are in the range 1 to
 * max_wgt. It is assumed that e <= v(v-1)/2. (In this program, this assured because of the call to
 * fix_imbalanced_graph.)
 *
 * To generate a random connected graph, we begin by generating a random spanning tree.  To generate a random spanning
 * tree, we first generate a random permutation tree[0],...,tree[v-1]. (v = number of vertices.) We then iteratively
 * add edges to form a tree.  We begin with the tree consisting of vertex tree[0] and no edges.  At the iterative step,
 * we assume that tree[0],tree[1],...,tree[i-1] are in the tree.  We then add vertex tree[i] to the tree by adding the
 * edge (tree[i],tree[rand(i)]). (This construction is similar to that of Prim's algorithm.) Finally, we add random
 * edges to produce the desired number of edges.
 */
static void
lsdb_random_connected_graph(lsdb_ctx_t *ctx, int v, int e, int max_wgt, int weight_flag)
{
    int i, j, count, index, *adj_matrix, *tree;

    LOG(NORMAL, "Generating a graph of %d nodes and %d links\n", v, e);

    if ((adj_matrix = (int *) calloc(v * v, sizeof(int))) == NULL) {
        LOG(ERROR, "Not enough room for %d nodes %d links  graph\n", v, e);
        return;
    }

    if ((tree = (int *) calloc(v, sizeof(int))) == NULL) {
        LOG(ERROR, "Not enough room for %d nodes %d links graph\n", v, e);
        free(adj_matrix);
        return;
    }

    /*
     * Generate a random permutation in the array tree.
     */
    init_array(tree, v);
    permute(tree, v);

    /*
     * Next generate a random spanning tree. The algorithm is:
     *
     * Assume that vertices tree[ 0 ],...,tree[ i - 1 ] are in the tree.  Add an edge incident on tree[ i ] and a
     * random vertex in the set {tree[ 0 ],...,tree[ i - 1 ]}.
     */
    for (i = 1; i < v; i++) {
        j = ran(i);
        adj_matrix[tree[i] * v + tree[j]] = adj_matrix[tree[j] * v + tree[i]] = weight_flag ? 1 + ran(max_wgt) : 1;
    }

    /*
     * Add additional random edges until achieving at least desired number
     */
    for (count = v - 1; count < e;) {
        i = ran(v);
        j = ran(v);

        if (i == j)
            continue;

        if (i > j)
            swap(&i, &j);

        index = i * v + j;
        if (!adj_matrix[index]) {
            adj_matrix[index] = weight_flag ? 1 + ran(max_wgt) : 1;
            count++;
        }
    }

    print_graph(ctx, v, count, adj_matrix);

    free(tree);
    free(adj_matrix);
}

void
lsdb_init_graph(lsdb_ctx_t *ctx)
{
    struct lsdb_node_ node_template;
    struct lsdb_link_ link_template;
    struct lsdb_node_ *node;
    uint32_t idx;

    srand(ctx->seed);

    lsdb_random_connected_graph(ctx, ctx->num_nodes, ctx->num_nodes << 1,
                sizeof(weights) / sizeof(int) - 1, 1);

    /*
     * First lookup the root node.
     */
    memset(&node_template, 0, sizeof(node_template));
    memcpy(&node_template.key, ctx->root_node_id, sizeof(node_template.key));
    node = lsdb_get_node(ctx, &node_template);
    if (!node) {
        LOG(ERROR, "Could not find root node %s\n", lsdb_format_node_id(node_template.key.node_id));
        return;
    }

    LOG(NORMAL, " Root node %s\n", lsdb_format_node_id(node_template.key.node_id));

    /*
     * Add connectors to the topology
     */
    if (ctx->num_connector) {
        /*
         * Next add outgoing edges from the root node.
         */
        for (idx = 0; idx < ctx->num_connector; idx++) {
            memset(&link_template, 0, sizeof(link_template));
            memcpy(&link_template.key.local_node_id, ctx->root_node_id,
            sizeof(link_template.key.local_node_id));
            memcpy(&link_template.key.remote_node_id, ctx->connector[idx].node_id,
            sizeof(link_template.key.remote_node_id));
            link_template.link_metric = 100;
            lsdb_add_link(ctx, node, &link_template);
        }
    }
}
