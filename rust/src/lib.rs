#![allow(dead_code,
         mutable_transmutes,
         non_camel_case_types,
         non_snake_case,
         non_upper_case_globals,
         unused_assignments,
         unused_mut)]
extern crate libc;
extern "C" {
    #[no_mangle]
    fn htonl(__hostlong: uint32_t) -> uint32_t;
}
pub type uint8_t = libc::c_uchar;
pub type uint16_t = libc::c_ushort;
pub type uint32_t = libc::c_uint;
pub type uint64_t = libc::c_ulong;
pub type size_t = libc::c_ulong;
// FIXME
pub type dp_packet_source = libc::c_uint;
/* Buffer data from XDP frame. */
/* buffer data is from DPDK allocated memory.
                                * ref to dp_packet_init_dpdk() in dp-packet.c.
                                */
pub const DPBUF_AFXDP: dp_packet_source = 4;
/* Starts on stack, may expand into heap. */
pub const DPBUF_DPDK: dp_packet_source = 3;
/* Un-movable stack space or static buffer. */
pub const DPBUF_STUB: dp_packet_source = 2;
/* Obtained via malloc(). */
pub const DPBUF_STACK: dp_packet_source = 1;
pub const DPBUF_MALLOC: dp_packet_source = 0;
#[derive ( Copy , Clone )]
#[repr(C)]
pub struct dp_packet {
    pub base_: *mut libc::c_void,
    pub allocated_: uint16_t,
    pub data_ofs: uint16_t,
    pub size_: uint32_t,
    pub ol_flags: uint32_t,
    pub rss_hash: uint32_t,
    pub flow_mark: uint32_t,
    pub source: dp_packet_source,
    pub l2_pad_size: uint8_t,
    pub l2_5_ofs: uint16_t,
    pub l3_ofs: uint16_t,
    pub l4_ofs: uint16_t,
    pub cutlen: uint32_t,
    pub packet_type: uint32_t,
    pub c2rust_unnamed: C2RustUnnamed,
}
#[derive ( Copy , Clone )]
#[repr ( C )]
pub union C2RustUnnamed {
    pub data: [uint64_t; 8],
}
pub type map_t = libc::c_ulonglong;
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
#[derive ( Copy , Clone )]
#[repr(C)]
pub struct flowmap {
    pub bits: [map_t; 2],
}
#[derive ( Copy , Clone )]
#[repr(C)]
pub struct miniflow {
    pub map: flowmap,
    /* Followed by:
     *     uint64_t values[n];
     * where 'n' is miniflow_n_values(miniflow). */
}
unsafe extern "C" fn __packet_data(mut b: *const dp_packet) -> uint16_t {
    return (*b).data_ofs;
}
unsafe extern "C" fn dp_packet_base(mut b: *const dp_packet)
 -> *mut libc::c_void {
    return (*b).base_;
}
unsafe extern "C" fn dp_packet_data(mut b: *const dp_packet)
 -> *mut libc::c_void {
    if __packet_data(b) as libc::c_int != 65535i32 {
        return (dp_packet_base(b) as
                    *mut libc::c_char).offset(__packet_data(b) as libc::c_int
                                                  as isize) as
                   *mut libc::c_void
    }
    panic!("Reached end of non-void function without returning");
}
unsafe extern "C" fn dp_packet_size(mut b: *const dp_packet) -> uint32_t {
    return (*b).size_;
}
#[inline]
unsafe extern "C" fn dp_packet_reset_offsets(mut b: *mut dp_packet) {
    (*b).l2_pad_size = 0i32 as uint8_t;
    (*b).l2_5_ofs = 65535i32 as uint16_t;
    (*b).l3_ofs = 65535i32 as uint16_t;
    (*b).l4_ofs = 65535i32 as uint16_t;
}
#[no_mangle]
pub unsafe extern "C" fn miniflow_extract(mut packet: *mut dp_packet,
                                          mut dst: *mut miniflow) {
    //    const struct pkt_metadata *md = &packet->md;
    let mut data: *const libc::c_void = dp_packet_data(packet);
    let mut size: size_t = dp_packet_size(packet) as size_t;
    let mut packet_type: uint32_t = (*packet).packet_type;
    //    uint64_t *values = miniflow_values(dst);
//    struct mf_ctx mf = { FLOWMAP_EMPTY_INITIALIZER, values,
//                         values + FLOW_U64S };
    let mut frame: *const libc::c_char = 0 as *const libc::c_char;
    let mut dl_type: uint16_t = 0xffffi32 as uint16_t;
    let mut nw_frag: uint8_t = 0;
    let mut nw_tos: uint8_t = 0;
    let mut nw_ttl: uint8_t = 0;
    let mut nw_proto: uint8_t = 0;
    let mut ct_nw_proto_p: *mut uint8_t = 0 as *mut uint8_t;
    let mut ct_tp_src: uint16_t = 0i32 as uint16_t;
    let mut ct_tp_dst: uint16_t = 0i32 as uint16_t;
    /* Metadata. */
    // skip
    /* Initialize packet's layer pointer and offsets. */
    frame = data as *const libc::c_char;
    dp_packet_reset_offsets(packet);
    packet_type == htonl(0i32 as uint32_t);
}

