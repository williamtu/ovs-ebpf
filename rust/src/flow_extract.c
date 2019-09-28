#include <config.h>
#include <stdint.h>
#include <arpa/inet.h>

#define DP_PACKET_CONTEXT_SIZE 64 
// FIXME
#define ovs_be32 uint32_t
#define ovs_be16 uint16_t
#define ovs_be64 uint64_t

enum dp_packet_source {
    DPBUF_MALLOC,              /* Obtained via malloc(). */
    DPBUF_STACK,               /* Un-movable stack space or static buffer. */
    DPBUF_STUB,                /* Starts on stack, may expand into heap. */
    DPBUF_DPDK,                /* buffer data is from DPDK allocated memory.
                                * ref to dp_packet_init_dpdk() in dp-packet.c.
                                */
    DPBUF_AFXDP,               /* Buffer data from XDP frame. */
};
struct dp_packet {
    void *base_;                /* First byte of allocated space. */
    uint16_t allocated_;        /* Number of bytes allocated. */
    uint16_t data_ofs;          /* First byte actually in use. */
    uint32_t size_;             /* Number of bytes in use. */
    uint32_t ol_flags;          /* Offloading flags. */
    uint32_t rss_hash;          /* Packet hash. */
    uint32_t flow_mark;         /* Packet flow mark. */
    enum dp_packet_source source;  /* Source of memory allocated as 'base'. */

    /* All the following elements of this struct are copied in a single call
     * of memcpy in dp_packet_clone_with_headroom. */
    uint8_t l2_pad_size;           /* Detected l2 padding size.
                                    * Padding is non-pullable. */
    uint16_t l2_5_ofs;             /* MPLS label stack offset, or UINT16_MAX */
    uint16_t l3_ofs;               /* Network-level header offset,
                                    * or UINT16_MAX. */
    uint16_t l4_ofs;               /* Transport-level header offset,
                                      or UINT16_MAX. */
    uint32_t cutlen;               /* length in bytes to cut from the end. */
    ovs_be32 packet_type;          /* Packet type as defined in OpenFlow */
    union {
//        struct pkt_metadata md;   // FIXME 
        uint64_t data[DP_PACKET_CONTEXT_SIZE / 8];
    };
};

typedef unsigned long long map_t;

//FIXME
// (gdb) p (sizeof(struct flow))
// $2 = 672
// FLOW_U64S = (sizeof(struct flow) / sizeof(uint64_t))
// $1 = 84
//  #define MAP_T_BITS (sizeof(map_t) * CHAR_BIT) = 64
//  #define FLOWMAP_UNITS DIV_ROUND_UP(FLOW_U64S, MAP_T_BITS)
// 84/64 = 2
// (gdb) p sizeof(struct flowmap)
// $2 = 16

#define FLOWMAP_UNITS 2 

struct flowmap {
    map_t bits[FLOWMAP_UNITS];
};

struct miniflow {
    struct flowmap map;
    /* Followed by:
     *     uint64_t values[n];
     * where 'n' is miniflow_n_values(miniflow). */
};
static uint16_t
__packet_data(const struct dp_packet *b)
{
    return b->data_ofs;
}

static void *
dp_packet_base(const struct dp_packet *b)
{
    return b->base_;
}

static void *
dp_packet_data(const struct dp_packet *b)
{
    if (__packet_data(b) != UINT16_MAX) {
           return (char *) dp_packet_base(b) + __packet_data(b);
    } else {
       return NULL;
    }
}

static uint32_t
dp_packet_size(const struct dp_packet *b)
{
    return b->size_;
}
static inline void
dp_packet_reset_offsets(struct dp_packet *b)
{   
    b->l2_pad_size = 0;
    b->l2_5_ofs = UINT16_MAX;
    b->l3_ofs = UINT16_MAX;
    b->l4_ofs = UINT16_MAX;
}

#define OVS_BE16_MAX 0xffff


#define PT_ETH 0
void miniflow_extract(struct dp_packet *packet, struct miniflow *dst)
{
//    const struct pkt_metadata *md = &packet->md;
    const void *data = dp_packet_data(packet);
    size_t size = dp_packet_size(packet);
    ovs_be32 packet_type = packet->packet_type;
//    uint64_t *values = miniflow_values(dst);
//    struct mf_ctx mf = { FLOWMAP_EMPTY_INITIALIZER, values,
//                         values + FLOW_U64S };
    const char *frame; 
    ovs_be16 dl_type = OVS_BE16_MAX; 
    uint8_t nw_frag, nw_tos, nw_ttl, nw_proto;
    uint8_t *ct_nw_proto_p = NULL;
    ovs_be16 ct_tp_src = 0, ct_tp_dst = 0;

    /* Metadata. */
    // skip

    /* Initialize packet's layer pointer and offsets. */
    frame = data;
    dp_packet_reset_offsets(packet);
    
    if (packet_type == htonl(PT_ETH)) {
        goto out;
        }
out:
    return;
}


