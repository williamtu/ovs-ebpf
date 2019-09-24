
lib_libopenvswitch_la_LIBADD += -lovsrust
ofproto_libofproto_la_LIBADD += -lovsrust

EXTRA_DIST += \
    rust/Cargo.toml \
    rust/src/lib.rs

RUST_FILES =

