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
    fn isspace(_: libc::c_int) -> libc::c_int;
}
#[no_mangle]
pub unsafe extern "C" fn skip_spaces(mut p: *const libc::c_char)
 -> *mut libc::c_char {
    while isspace(*p as libc::c_uchar as libc::c_int) != 0 { p = p.offset(1) }
    return p as *mut libc::c_char;
}
