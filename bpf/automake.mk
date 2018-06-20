bpf_sources = bpf/datapath.c
bpf_headers = \
	bpf/api.h \
	bpf/datapath.h \
	bpf/odp-bpf.h \
	bpf/ovs-p4.h \
	bpf/helpers.h \
	bpf/openvswitch.h \
	bpf/maps.h \
	bpf/parser.h \
	bpf/lookup.h \
	bpf/action.h \
	bpf/generated_headers.h \
	bpf/xdp.h
bpf_extra = \
	bpf/ovs-proto.p4

# Regardless of configuration with GCC, we must compile the BPF with clang
# since GCC doesn't have a BPF backend.  Clang dones't support these flags,
# so we filter them out.

bpf_FILTER_FLAGS := $(filter-out -Wbool-compare, $(AM_CFLAGS))
bpf_FILTER_FLAGS2 := $(filter-out -Wduplicated-cond, $(bpf_FILTER_FLAGS))
bpf_FILTER_FLAGS3 := $(filter-out --coverage, $(bpf_FILTER_FLAGS2))
bpf_CFLAGS := $(bpf_FILTER_FLAGS3)
bpf_CFLAGS += -D__NR_CPUS__=$(shell nproc) -O2 -Wall -Werror -emit-llvm
bpf_CFLAGS += -I$(top_builddir)/include -I$(top_srcdir)/include
bpf_CFLAGS += -Wno-error=pointer-arith  # Allow skb->data arithmetic
bpf_CFLAGS += -I${IPROUTE2_SRC_PATH}/include/uapi/
# FIXME:
#bpf_CFLAGS += -D__KERNEL__

dist_sources = $(bpf_sources)
dist_headers = $(bpf_headers)
build_sources = $(dist_sources)
build_headers = $(dist_headers)
build_objects = $(patsubst %.c,%.o,$(build_sources))

LLC ?=  llc-3.8
CLANG ?= clang-3.8

bpf: $(build_objects)
bpf/datapath.o: $(bpf_sources) $(bpf_headers)
	$(MKDIR_P) $(dir $@)
	@which $(CLANG) >/dev/null 2>&1 || \
		(echo "Unable to find clang, Install clang (>=3.7) package"; exit 1)
	$(AM_V_CC) $(CLANG) $(bpf_CFLAGS) -c $< -o - | \
	$(LLC) -march=bpf -filetype=obj -o $@

bpf/datapath_dbg.o: $(bpf_sources) $(bpf_headers)
	@which clang-4.0 > /dev/null 2>&1 || \
		(echo "Unable to find clang-4.0 for debugging"; exit 1)
	clang-4.0 $(bpf_CFLAGS) -g -c $< -o -| llc-4.0 -march=bpf -filetype=obj -o $@_dbg
	llvm-objdump-4.0 -S -no-show-raw-insn $@_dbg > $@_dbg.objdump

EXTRA_DIST += $(dist_sources) $(dist_headers) $(bpf_extra)
if HAVE_BPF
dist_bpf_DATA += $(build_objects)
endif

