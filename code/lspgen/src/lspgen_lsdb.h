/*
 * Generic LSDB implementation for link-state protocols.
 *
 * Hannes Gredler, January 2022
 *
 * Copyright (C) 2015-2022, RtBrick, Inc.
 */

#ifndef __LSPGEN_LSDB_H__
#define __LSPGEN_LSDB_H__

/*
 * Keep the link_id and node_id arrays a multiple of 8
 */
#define LSDB_MAX_NODE_ID_SIZE  8    /* enough space for various protocols */
#define LSDB_MAX_LINK_ID_SIZE 16    /* enough space for various protocols */

/*
 * Inital hash bucket size. Good to pick prime numbers.
 * Should give enough initial space for roughly 1000 nodes and 5000 links.
 */
#define LSDB_NODE_HSIZE 997    /* hash table initial bucket size */
#define LSDB_LINK_HSIZE 9973   /* hash table initial bucket size */

typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_ISIS = 1,
    PROTO_OSPF2 = 2,
    PROTO_OSPF3 = 3
} lsdb_proto_id_t;

typedef struct lsdb_node_id_ {
    uint8_t node_id[LSDB_MAX_NODE_ID_SIZE];
} lsdb_node_id_t;

/*
 * An Linkstate database context.
 */
typedef struct lsdb_ctx_
{
    dict *node_dict; /* dict for nodes */
    dict *link_dict; /* dict for links */

    timer_root_s timer_root; /* timers */

    /* List of changed packets for incremental LSP generation  */
    CIRCLEQ_HEAD(lsdb_packet_head_, lsdb_packet_ ) packet_change_qhead;

    /*
     * Root node.
     */
    uint8_t root_node_id[LSDB_MAX_NODE_ID_SIZE];

    char *instance_name;    /* Name for this instance e.g. "default" */
    lsdb_proto_id_t protocol_id; /* e.g. "isis, ospf2, ospf3" */
    union {
        uint8_t level;      /* IS-IS */
	uint32_t area;      /* OSPF */
    } topology_id;

    /*
     * Generator related.
     */
    uint32_t num_nodes;
    ipv4_prefix ipv4_node_prefix;
    ipv4_prefix ipv4_link_prefix;
    ipv4_prefix ipv4_ext_prefix;
    ipv6_prefix ipv6_node_prefix;
    ipv6_prefix ipv6_link_prefix;
    ipv6_prefix ipv6_ext_prefix;
    iso_prefix area[3];
    uint32_t num_area;
    uint32_t sequence;
    uint32_t srgb_base;
    uint32_t srgb_range;
    char *authentication_key;
    uint8_t authentication_type;
    uint32_t seed;
    struct lsdb_node_id_ connector[3];
    uint32_t num_connector;
    uint32_t num_ext; /* number of external prefixes */
    bool no_sr;
    bool no_ipv4;
    bool no_ipv6;
    uint16_t lsp_lifetime;

    uint32_t node_index;
    uint32_t link_index;

    /* MRT file */
    time_t now; /* epoch */
    char *mrt_filename;         /* File name for dumping LSDB in MRT format. */
    FILE *mrt_file;             /* File handle for dumping LSDB in MRT format. */

    uint32_t nodecount;
    uint32_t linkcount;

    /* BNG blaster Control socket */
    char *ctrl_socket_path;
    timer_s *ctrl_socket_connect_timer;
    timer_s *ctrl_socket_wakeup_timer; /* dummy timer */
    timer_s *ctrl_socket_write_timer;
    timer_s *ctrl_socket_close_timer;
    struct io_buffer_ ctrl_io_buf;
    int ctrl_socket_sockfd;
    bool ctrl_packet_first;
    bool quit_loop; /* Terminate loop after draining the LSDB */
    struct {
    uint32_t octets_sent;
    uint32_t packets_sent;
    uint32_t packets_queued;    /* # packets on the change_list */
    } ctrl_stats;

    char *graphviz_filename;    /* File name for dumping LSDB in graphviz format. */
    char *pcap_filename;        /* File name for dumping LSDB in pcapng format. */
    FILE *pcap_file;            /* File handle for dumping LSDB in pcapng format. */
    char *stream_filename;        /* File name for writing traffic streams. */
    FILE *stream_file;          /* File handle for writing traffic streams. */
    char *config_filename;        /* File name for configuration. */
    FILE *config_file;          /* File handle for configuration. */
    bool config_read;
    bool config_write;
    FILE *seq_cache_file;       /* File handle for sequence number cache file. */
} lsdb_ctx_t;

/*
 * A node in the link-state database.
 */
typedef struct lsdb_node_ {
    uint32_t node_index;
    uint16_t linkcount;

    /*
     * Misc flags.
     */
    uint16_t overload:1,
    attach:1,
    is_root:1;    /* root node */

    uint32_t sequence;
    uint16_t lsp_lifetime;

    timer_s *refresh_timer;

    /*
     * List of links
     */
    CIRCLEQ_HEAD(lsdb_link_head_, lsdb_link_) link_qhead;

    dict *attr_dict; /* dict for node attributes */
    uint32_t attr_count;

    dict *packet_dict; /* dict for serialized packets */

    /*
     * Key in the dict
     */
    struct {
    uint8_t node_id[LSDB_MAX_NODE_ID_SIZE];
    } key;

    char *node_name;    /* Name of node if protocol supports it. */

    struct lsdb_ctx_ *ctx;    /* where this node is attached to */
} lsdb_node_t;

/*
 * A link in the link-state database.
 */
typedef struct lsdb_link_ {

    /*
     * Key in the dict
     */
    struct {
    uint8_t local_node_id[LSDB_MAX_NODE_ID_SIZE];
    uint8_t remote_node_id[LSDB_MAX_NODE_ID_SIZE];

    /*
     * optional, put interface index or ipv4/ipv6 address here
     */
    uint8_t local_link_id[LSDB_MAX_LINK_ID_SIZE];

    /*
     * optional, put interface index or ipv4/ipv6 address here
     */
    uint8_t remote_link_id[LSDB_MAX_LINK_ID_SIZE];
    } key;

    uint32_t link_index;
    uint32_t link_metric;

    /*
     * List of links hanging off a node
     */
    CIRCLEQ_ENTRY(lsdb_link_) link_qnode;

    dict *attr_dict; /* dict for link attributes */

    /*
     * Speed trick. When inserting a node, try to find the inverse link that
     * is pointing to us. That way we can quickly perform the 2-way check
     * during SPF calculation using a simple NULL check.
     */
    struct lsdb_link_ *inverse_link;

    struct lsdb_node_ *node;    /* where this link is attached to */
} lsdb_link_t;

/*
 * Shared for ipv4 and ipv6 prefix generation
 */
typedef struct lsdb_attr_prefix_ {
    union {
        ipv4_prefix ipv4_prefix;
        ipv6_prefix ipv6_prefix;
    };
    uint16_t ext_flag:1, /* External */
    r_flag:1, /* Re-advertisement */
    node_flag:1, /* Node */
    updown_flag:1, /* Up/Down bit*/
    no_php_flag:1, /* no PHP */
    exp_null_flag:1, /* Explicit NULL */
    value_flag:1, /* SID is a value */
    local_flag:1, /* SID has local significance */
    family_flag:1, /* false for ipv4, true for ipv6 */
    s_flag:1, /* domain wide flooding */
    adv_range:1, /* Advertise range (binding TLV) */
    adv_sid:1, /* Advertise SID */
    adv_tag:1, /* Advertise Tag */
    small_metrics:1; /* old-style 6-bit metrics */

    uint8_t sid_algo;
    uint32_t metric;
    uint32_t sid;
    uint32_t tag;   /* only used in ISIS_TLV_EXTD_IPVX_REACH */
    uint16_t range; /* only used in ISIS_TLV_BINDING */
} lsdb_attr_prefix_t;

typedef struct lsdb_attr_link_ {
    uint8_t remote_node_id[LSDB_MAX_NODE_ID_SIZE];
    uint32_t metric;
    bool small_metrics; /* old-style 6-bit metrics */

} lsdb_attr_link_t;

typedef struct lsdb_attr_cap_ {
    uint8_t router_id[4];
    uint32_t srgb_base;
    uint32_t srgb_range;
    uint8_t d_flag:1,
    s_flag:1,
    mpls_ipv4_flag:1,
    mpls_ipv6_flag:1;
} lsdb_attr_cap_t;

/*
 * A message stack is used for hierarchical encoding of messages.
 */
typedef struct msg_stack_ {
    uint16_t num_buffer;
    struct io_buffer_ buf[1]; /* variable length */
} msg_stack_t;

/*
 * An Attribute hanging off a node or link
 */
typedef struct lsdb_attr_ {

    /*
     * Key in the dict
     */
    struct {
	uint8_t ordinal; /* Used for ordering message generation */
	uint8_t msg[4]; /* code points for multiple levels */
	uint8_t attr_type; /* Type */
	bool start_tlv; /* Always start a fresh TLV */
	union {
	    struct lsdb_attr_prefix_ prefix;
	    iso_prefix area;
	    struct lsdb_attr_cap_ cap;
	    struct lsdb_attr_link_ link;
	    uint8_t ipv4_addr[IPV4_ADDR_LEN];
	    uint8_t ipv6_addr[IPV6_ADDR_LEN];
	    uint32_t srlg;
	    char hostname[36];
	    uint8_t protocol;
	};
    } key;

    uint32_t size; /* on-the wire space required in bytes */
} lsdb_attr_t;

/*
 * An serialized LSA/LSP hanging off a node.
 */
typedef struct lsdb_packet_ {

    /* List of changed packets for incremental LSP generation  */
    CIRCLEQ_ENTRY(lsdb_packet_ ) packet_change_qnode;
    struct lsdb_node_ *parent;
    bool on_change_list;

    /*
     * Key in the dict
     */
    struct {
	uint32_t id; /* Fragment # for IS-IS, LS-Update Packet # for OSPF */
    } key;

    struct io_buffer_ buf;
    uint8_t data[1500]; /* fixed buffer */
    uint8_t redzone[8]; /* Overwrite detection */

    uint8_t prev_attr_cp[4]; /* cached code points for previous attr */

} lsdb_packet_t;

/*
 * lspgen_lsdb.c - Prototypes for manipulating the LSDB
 */
char *lsdb_format_node(lsdb_node_t *);
char *lsdb_format_node_no_name(lsdb_node_t *);
char *lsdb_format_node_id(unsigned char *);
char *lsdb_format_link(lsdb_link_t *);
void lsdb_scan_node_id(uint8_t *, char *);
const char *lsdb_format_proto(struct lsdb_ctx_ *);

lsdb_link_t *lsdb_add_link(lsdb_ctx_t *, lsdb_node_t *, lsdb_link_t *);
lsdb_link_t *lsdb_get_link(lsdb_ctx_t *, lsdb_link_t *);
lsdb_node_t *lsdb_add_node(lsdb_ctx_t *, lsdb_node_t *);
lsdb_node_t *lsdb_get_node(lsdb_ctx_t *, lsdb_node_t *);
lsdb_attr_t *lsdb_add_node_attr(lsdb_node_t *, lsdb_attr_t *);
void lsdb_reset_attr_template(lsdb_attr_t *);
void lsdb_delete_link(lsdb_ctx_t *, lsdb_link_t *);
void lsdb_delete_node(lsdb_ctx_t *, lsdb_node_t *);
lsdb_ctx_t *lsdb_alloc_ctx(char *);
void lsdb_delete_ctx(lsdb_ctx_t *);
void lsdb_dump_graphviz(lsdb_ctx_t *);
int lsdb_compare_node(void *, void *);
int lsdb_compare_link(void *, void *);
int lsdb_compare_packet(void *, void *);
void lsdb_free_packet(void *, void *);
void lsdb_free_attr(void *, void *);

/*
 * lspgen_forest.c - Prototypes for random graph generation
 */
void lsdb_init_graph(lsdb_ctx_t *);

#endif /*__LSPGEN_LSDB_H__*/
