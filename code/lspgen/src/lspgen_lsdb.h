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
 * Initial hash bucket size. Good to pick prime numbers.
 * Should give enough initial space for roughly 1000 nodes and 5000 links.
 */
#define LSDB_NODE_HSIZE 997    /* hash table initial bucket size */
#define LSDB_LINK_HSIZE 9973   /* hash table initial bucket size */

#define LSP_LIFETIME_MIN 120 /* secs */

typedef enum {
    PROTO_UNKNOWN = 0,
    PROTO_ISIS = 1,
    PROTO_OSPF2 = 2,
    PROTO_OSPF3 = 3
} lsdb_proto_id_t;

typedef struct lsdb_node_id_ {
    uint8_t local_link_id[LSDB_MAX_NODE_ID_SIZE];
    uint8_t remote_node_id[LSDB_MAX_NODE_ID_SIZE];
} lsdb_node_id_t;

/*
 * Per algorithm prefix entries with Prefix-SID and/or Flex-Algo
 * prefix metric (FAPM). Kept small as part of the attribute key.
 */
#define LSDB_MAX_PREFIX_ALGO 4

/* Prefix-SID flags, R and N follow the prefix flags */
#define LSDB_PREFIX_SID_FLAG_NO_PHP   0x20
#define LSDB_PREFIX_SID_FLAG_EXP_NULL 0x10
#define LSDB_PREFIX_SID_FLAG_VALUE    0x08
#define LSDB_PREFIX_SID_FLAG_LOCAL    0x04
#define LSDB_PREFIX_SID_FLAG_MASK     0x3c

/* Internal flags (reserved bits of the Prefix-SID flags) */
#define LSDB_PREFIX_ALGO_SID          0x02 /* Advertise Prefix-SID */
#define LSDB_PREFIX_ALGO_FAPM         0x01 /* Advertise Flex-Algo prefix metric */

/* Maximum SID depth (RFC 8491) entries per node or link */
#define LSDB_MAX_MSD                  2
#define LSDB_MSD_TYPE_BMI             1

typedef struct lsdb_msd_ {
    uint8_t type;
    uint8_t value;
} lsdb_msd_t;

/* Flex-Algo definition (RFC 9350) */
#define LSDB_MAX_FLEX_ALGO            LSDB_MAX_PREFIX_ALGO
#define LSDB_FAD_METRIC_IGP           0
#define LSDB_FAD_METRIC_MIN_DELAY     1
#define LSDB_FAD_METRIC_TE            2
#define LSDB_FAD_DEFAULT_PRIORITY     128

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
    uint8_t sr_algo[LSDB_MAX_PREFIX_ALGO]; /* SR algorithms for generated node SIDs */
    uint8_t sr_algo_count; /* 0 means algorithm 0 only, without SR-Algorithm subTLV */
    struct lsdb_attr_fad_ *fad; /* Flex-Algo definitions for generated topologies */
    uint8_t fad_count;
    uint32_t link_delay_min; /* Random link delay range in microseconds */
    uint32_t link_delay_max;
    uint32_t te_metric_min; /* Random TE metric range */
    uint32_t te_metric_max;
    uint8_t node_msd; /* Base MPLS imposition MSD of all nodes, 0 = not advertised */
    bool elc; /* Set the E-flag (ELC) of node prefixes */
    char *authentication_key;
    uint8_t authentication_type;
    uint32_t seed;
    struct lsdb_node_id_ connector[3];
    uint32_t num_connector;
    uint32_t num_ext; /* number of external prefixes */
    uint32_t link_multiplier; /* parallel links */
    bool no_sr;
    bool no_ipv4;
    bool no_ipv6;
    bool purge;
    uint16_t lsp_lifetime;
    uint16_t lsp_buffer_size;

    uint32_t node_index;
    uint32_t link_index;

    /* MRT file */
    time_t now; /* epoch */
    char *mrt_filename;         /* File name for dumping LSDB in MRT format. */
    FILE *mrt_file;             /* File handle for dumping LSDB in MRT format. */

    uint32_t nodecount;
    uint32_t linkcount;

    /* BNG Blaster Control socket */
    uint8_t ctrl_instance; /* ISIS or OSPF instance-id */
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
    bool overload:1;
    bool attach:1;
    bool is_direct_neighbor;
    bool is_pseudonode;
    bool is_local_pseudonode; /* direct adjacent Pseudonodes */
    bool is_root;    /* root node */

    uint32_t sequence;
    uint16_t lsp_lifetime;
    uint16_t lsp_buffer_size;

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

typedef struct lsdb_prefix_algo_ {
    uint32_t sid;
    uint32_t metric; /* Flex-Algo prefix metric */
    uint8_t algo;
    uint8_t flags; /* Prefix-SID and internal flags */
} lsdb_prefix_algo_t;

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
    family_flag:1, /* false for ipv4, true for ipv6 */
    s_flag:1, /* domain wide flooding */
    adv_range:1, /* Advertise range (binding TLV) */
    adv_tag:1, /* Advertise Tag */
    small_metrics:1, /* old-style 6-bit metrics */
    elc_flag:1; /* Entropy label capability (RFC 9088) */

    uint8_t algo_count; /* Number of per algorithm entries */
    lsdb_prefix_algo_t algos[LSDB_MAX_PREFIX_ALGO];
    uint32_t metric;
    uint32_t tag;   /* only used in ISIS_TLV_EXTD_IPVX_REACH */
    uint16_t range; /* only used in ISIS_TLV_BINDING */
} lsdb_attr_prefix_t;

typedef struct lsdb_attr_link_ {
    uint8_t local_link_id[4];
    uint8_t remote_link_id[4];
    uint8_t remote_node_id[LSDB_MAX_NODE_ID_SIZE];
    uint32_t metric;
    uint16_t adjacency_sid;
    bool small_metrics; /* old-style 6-bit metrics */

    /* Application-specific link attributes (ASLA) for Flex-Algo, 0 = not advertised */
    bool asla;
    uint32_t te_metric;
    uint32_t min_delay; /* microseconds */
    uint32_t max_delay; /* microseconds */
    uint32_t admin_group;
    lsdb_msd_t msd[LSDB_MAX_MSD]; /* Link MSD, type 0 = unused */
} lsdb_attr_link_t;

/*
 * Flex-Algo definition (FAD), advertised as subTLV
 * of a dedicated IS-IS router capability TLV.
 */
typedef struct lsdb_attr_fad_ {
    uint8_t router_id[4];
    uint8_t algo;
    uint8_t metric_type;
    uint8_t calc_type;
    uint8_t priority;
    bool m_flag; /* Flex-Algo prefix metric required for inter-area */
    uint32_t exclude_any; /* Admin groups, 0 = not advertised */
    uint32_t include_any;
    uint32_t include_all;
} lsdb_attr_fad_t;

typedef struct lsdb_attr_cap_ {
    uint8_t router_id[4];
    uint32_t srgb_base;
    uint32_t srgb_range;
    uint8_t d_flag:1,
    s_flag:1,
    mpls_ipv4_flag:1,
    mpls_ipv6_flag:1;
    uint8_t sr_algo[8];
    uint8_t sr_algo_len;
    lsdb_msd_t msd[LSDB_MAX_MSD]; /* Node MSD, type 0 = unused */
} lsdb_attr_cap_t;

#define MAX_MSG_LEVEL 4

/* bits used in the serializer */
#define OPEN_LEVEL0 0x01
#define OPEN_LEVEL1 0x02
#define OPEN_LEVEL2 0x04
#define OPEN_LEVEL3 0x08
#define CLOSE_LEVEL0 0x100
#define CLOSE_LEVEL1 0x200
#define CLOSE_LEVEL2 0x400
#define CLOSE_LEVEL3 0x800

/*
 * Return true if the prefix entry advertises a Prefix-SID.
 */
#define LSDB_PREFIX_HAS_SID(prefix_algo_) ((prefix_algo_)->flags & LSDB_PREFIX_ALGO_SID)

/*
 * An Attribute hanging off a node or link
 */
typedef struct lsdb_attr_ {

    /*
     * Key in the dict
     */
    struct {
	uint8_t ordinal; /* Used for ordering message generation */
	uint8_t attr_cp[MAX_MSG_LEVEL]; /* code points for multiple levels */
	uint8_t attr_type; /* Type */
	bool start_tlv; /* Always start a fresh TLV */
	union {
	    struct lsdb_attr_prefix_ prefix;
	    iso_prefix area;
	    struct lsdb_attr_cap_ cap;
	    struct lsdb_attr_fad_ fad;
	    struct lsdb_attr_link_ link;
	    uint8_t ipv4_addr[IPV4_ADDR_LEN];
	    uint8_t ipv6_addr[IPV6_ADDR_LEN];
	    uint32_t srlg;
	    char hostname[36];
	    uint16_t lsp_buffer_size;
	    uint8_t protocol;
	};
    } key;

    uint32_t size; /* on-the wire space required in bytes */
    struct lsdb_node_ *parent;
} lsdb_attr_t;

#define MAX_OSPF_PACKET  1000 /* 16384 * 1000 bytes total LSA advertisement size */
#define MAX_ISIS_FRAGMENT 256 /*  1462 *  256 bytes total LSP advertisement size */

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

    struct io_buffer_ buf[MAX_MSG_LEVEL];
    uint8_t data[16384]; /* fixed buffer */

    uint8_t prev_attr_cp[MAX_MSG_LEVEL]; /* cached code points for previous attr */

} lsdb_packet_t;

/*
 * lspgen_lsdb.c - Prototypes for manipulating the LSDB
 */
char *lsdb_format_node(lsdb_node_t *);
char *lsdb_format_node_no_name(lsdb_node_t *);
char *lsdb_format_node_id(unsigned char *);
char *lsdb_format_ospf_node_id(unsigned char *);
char *lsdb_format_link(lsdb_link_t *);
void lsdb_scan_node_id(uint8_t *, char *);
const char *lsdb_format_proto(struct lsdb_ctx_ *);
lsdb_proto_id_t lsdb_scan_proto(const char *);

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
