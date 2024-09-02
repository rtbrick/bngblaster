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

#define MAX_SUBGRAPH_SIZE 1000 /* nodes */

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
connect_node (lsdb_ctx_t *ctx, uint32_t base, int i, int j, uint32_t link_metric)
{
    struct lsdb_node_ node_template;
    struct lsdb_link_ link_template;
    struct lsdb_node_ *local_node, *remote_node;
    char node_name[32];
    uint32_t link_index;
    __uint128_t addr;

    memset(&node_template, 0, sizeof(node_template));
    memset(&link_template, 0, sizeof(link_template));

    /*
     * Add local node.
     */
    addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t)) +
	base + i - 1;
    if (ctx->protocol_id == PROTO_ISIS) {
	lspgen_store_bcd_addr(addr, node_template.key.node_id, 4);
    } else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
	lspgen_store_addr(addr, node_template.key.node_id, 4);
    }
    snprintf(node_name, sizeof(node_name), "node%u", base+i);
    node_template.node_name = node_name;
    local_node = lsdb_add_node(ctx, &node_template);

    /*
     * Add remote node.
     */
    addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t)) +
	base + j - 1;
    if (ctx->protocol_id == PROTO_ISIS) {
	lspgen_store_bcd_addr(addr, node_template.key.node_id, 4);
    } else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
	lspgen_store_addr(addr, node_template.key.node_id, 4);
    }
    snprintf(node_name, sizeof(node_name), "node%u", base+j);
    node_template.node_name = node_name;
    remote_node = lsdb_add_node(ctx, &node_template);

    for (link_index = 0; link_index < ctx->link_multiplier; link_index++) {

	/*
	 * Add outgoing link.
	 */
	link_template.link_metric = link_metric;
	addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t)) +
	    base + i - 1;
	if (ctx->protocol_id == PROTO_ISIS) {
	    lspgen_store_bcd_addr(addr, link_template.key.local_node_id, 4);
	} else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
	    lspgen_store_addr(addr, link_template.key.local_node_id, 4);
	}
	addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t)) +
	    base + j - 1;
	if (ctx->protocol_id == PROTO_ISIS) {
	    lspgen_store_bcd_addr(addr, link_template.key.remote_node_id, 4);
	} else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
	    lspgen_store_addr(addr, link_template.key.remote_node_id, 4);
	}
	lspgen_store_addr(link_index, link_template.key.local_link_id, 4);
	lsdb_add_link(ctx, local_node, &link_template);

	/*
	 * Add incoming link.
	 */
	addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t)) +
	    base + j - 1;
	if (ctx->protocol_id == PROTO_ISIS) {
	    lspgen_store_bcd_addr(addr, link_template.key.local_node_id, 4);
	} else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
	    lspgen_store_addr(addr, link_template.key.local_node_id, 4);
	}
	addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t)) +
	    base + i - 1;
	if (ctx->protocol_id == PROTO_ISIS) {
	    lspgen_store_bcd_addr(addr, link_template.key.remote_node_id, 4);
	} else if (ctx->protocol_id == PROTO_OSPF2 || ctx->protocol_id == PROTO_OSPF3) {
	    lspgen_store_addr(addr, link_template.key.remote_node_id, 4);
	}
	lspgen_store_addr(link_index, link_template.key.local_link_id, 4);
	lsdb_add_link(ctx, remote_node, &link_template);
    }
}

uint32_t
convert_matrix_graph(lsdb_ctx_t *ctx, uint32_t base, int v, int *adj_matrix)
{
    int i, j, index;
    uint32_t root;

    root = 0;
    for (i = 1; i < v; i++) {
        for (j = i + 1; j <= v; j++) {
            index = (i - 1) * v + j - 1;
            if (!adj_matrix[index]) {
		continue;
	    }

	    if (!root) {
		root = i;
	    }

	    connect_node(ctx, base, i, j, weights[adj_matrix[index]]);
	}
    }

    return root;
}

/*
 * This function generates a random connected simple graph with v vertices and max(v-1,e) edges.
 * The graph can be weighted (weight_flag == 1) or unweighted (weight_flag != 1).
 * If it is weighted, the weights are in the range 1 to max_wgt.
 * It is assumed that e <= v(v-1)/2. (In this program, this assured because of the call to fix_imbalanced_graph.)
 *
 * To generate a random connected graph, we begin by generating a random spanning tree.
 * To generate a random spanning tree, we first generate a random permutation tree[0],...,tree[v-1].
 * (v = number of vertices.) We then iteratively add edges to form a tree.
 * We begin with the tree consisting of vertex tree[0] and no edges.  At the iterative step,
 * we assume that tree[0],tree[1],...,tree[i-1] are in the tree.
 * We then add vertex tree[i] to the tree by adding the edge (tree[i],tree[rand(i)]).
 * (This construction is similar to that of Prim's algorithm.)
 * Finally, we add random edges to produce the desired number of edges.
 *
 * Returns root node index.
 */
uint32_t
lsdb_random_connected_graph(lsdb_ctx_t *ctx, int *tree, int *adj_matrix,
			    uint32_t base, int v, int e, int max_wgt, int weight_flag)
{
    int i, j, count, index;

    if (v < 5) {
	LOG(ERROR, " Minimal node count (5) not reached, %d.\n", v);
	return 0;
    }

    LOG(NORMAL, " Generating a subgraph of %d nodes and %d links\n", v, e);

    /*
     * Generate a random permutation in the array tree.
     */
    init_array(tree, v);
    permute(tree, v);
    memset(adj_matrix, 0, v * v * sizeof(int));

    /*
     * Next generate a random spanning tree. The algorithm is:
     *
     * Assume that vertices tree[ 0 ],...,tree[ i - 1 ] are in the tree.
     * Add an edge incident on tree[ i ] and a
     * random vertex in the set {tree[ 0 ],...,tree[ i - 1 ]}.
     */
    for (i = 1; i < v; i++) {
        j = ran(i);
        adj_matrix[tree[i] * v + tree[j]] =
	    adj_matrix[tree[j] * v + tree[i]] = weight_flag ? 1 + ran(max_wgt) : 1;
    }

    /*
     * Add additional random edges until achieving at least desired number
     */
    for (count = v - 1; count < e;) {
        i = ran(v);
        j = ran(v);

        if (i == j) {
            continue;
	}

        if (i > j) {
            swap(&i, &j);
	}

        index = i * v + j;
        if (!adj_matrix[index]) {
            adj_matrix[index] = weight_flag ? 1 + ran(max_wgt) : 1;
            count++;
        }
    }

    return convert_matrix_graph(ctx, base, v, adj_matrix);
}

void
lsdb_init_graph(lsdb_ctx_t *ctx)
{
    int remaining_nodes, v, e, max_wgt, *adj_matrix, *tree;
    struct lsdb_node_ node_template;
    struct lsdb_link_ link_template;
    struct lsdb_node_ *node;
    uint32_t idx, root, base;
    __uint128_t addr;

    srand(ctx->seed);

    base = 0;
    v = ctx->num_nodes;
    e = ctx->num_nodes*2;
    remaining_nodes = v;
    max_wgt = sizeof(weights) / sizeof(int) - 1;

    LOG(NORMAL, "Generating a graph of %d nodes and %d links\n", v, e);

    /*
     * For a large number of nodes do not create a v^2 matrix, but rather
     * break it down to smaller v=1000 matrixes and connect them.
     */
    if (v > MAX_SUBGRAPH_SIZE) {
	v = MAX_SUBGRAPH_SIZE;
	e = v*2;
    }

    if ((adj_matrix = (int *) malloc(v * v * sizeof(int))) == NULL) {
        LOG(ERROR, "Not enough room for %d nodes %d links graph\n", v, e);
        return;
    }

    if ((tree = (int *) malloc(v * sizeof(int))) == NULL) {
        LOG(ERROR, "Not enough room for %d nodes %d links graph\n", v, e);
        free(adj_matrix);
        return;
    }

    root = lsdb_random_connected_graph(ctx, tree, adj_matrix, 0, v, e, max_wgt, 1);
    remaining_nodes -= v;
    base += v;

    /*
     * Store root.
     */
    switch (ctx->protocol_id) {
    case PROTO_ISIS:
	/* BCD notation for IS-IS */
	addr = lspgen_load_addr((uint8_t*)&ctx->ipv4_node_prefix.address, sizeof(ipv4addr_t)) + root - 1;
	lspgen_store_bcd_addr(addr, ctx->root_node_id, 4);
	break;
    default:
	/* dotted decimal notation for everybody else */
	memcpy(&ctx->root_node_id, &ctx->ipv4_node_prefix.address, 4);
	break;
    }

    /*
     * Are there outstanding nodes that have not yet been created in the first pass ?
     */
    while (remaining_nodes > 0) {

	/* last pass ? */
	if (remaining_nodes < v) {
	    v = remaining_nodes;
	    e = v*2;
	}

	lsdb_random_connected_graph(ctx, tree, adj_matrix, base, v, e, max_wgt, 1);

	/*
	 * Connect the first node of this subgraph
	 * with the last node of the previous subgraph
	 */
	connect_node(ctx, base, -1, 0, 99);
	/*
	 * Connect the second node of this subgraph
	 * with the penultimatenode of the previous subgraph
	 */
	connect_node(ctx, base, -2, 1, 99);

	remaining_nodes -= v;
	base += v;
    }

    /*
     * First lookup the root node.
     */
    memset(&node_template, 0, sizeof(node_template));
    memcpy(&node_template.key, ctx->root_node_id, sizeof(node_template.key));
    node = lsdb_get_node(ctx, &node_template);
    if (!node) {
        LOG(ERROR, "Could not find root node %s\n", lsdb_format_node_id(node_template.key.node_id));
	goto cleanup;
    }

    LOG(NORMAL, " Root node %s\n", lsdb_format_node(node));
    node->is_root = true;

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
            memcpy(&link_template.key.remote_node_id, ctx->connector[idx].remote_node_id,
		   sizeof(link_template.key.remote_node_id));
            memcpy(&link_template.key.local_link_id, ctx->connector[idx].local_link_id,
		   sizeof(link_template.key.local_link_id));
	    link_template.key.remote_link_id[3] = idx+1;
	    link_template.key.remote_node_id[7] = CONNECTOR_MARKER;
            link_template.link_metric = 100;
            lsdb_add_link(ctx, node, &link_template);
        }
    }

cleanup:

    free(tree);
    free(adj_matrix);

}
