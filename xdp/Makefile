obj- := dummy.o


INCLUDEFLAGS = -I$(obj)/src

always += obj/sample.o


LIBBPF_DIR ?= ../libbpf/src/
OBJECT_LIBBPF = $(LIBBPF_DIR)/libbpf.a


BPF_CFLAGS ?= -I$(LIBBPF_DIR)/build/usr/include/ -I../headers/

HOSTCFLAGS += -I$(objtree)/usr/include
HOSTCFLAGS += -I$(srctree)/tools/lib/
HOSTCFLAGS += -I$(srctree)/tools/perf
HOSTCFLAGS_bpf_load.o += -I$(objtree)/usr/include -Wno-unused-variable
HOSTLOADLIBES_sockex1 += -lelf

# Allows pointing LLC/CLANG to a LLVM backend with bpf support, redefine on cmdline:
#  make samples/bpf/ LLC=~/git/llvm/build/bin/llc CLANG=~/git/llvm/build/bin/clang
LLVM_PREFIX ?= /usr/bin
CLANG ?= $(LLVM_PREFIX)/clang
LLC ?= $(LLVM_PREFIX)/llc

# Trick to allow make to be run from this directory
all:
	$(MAKE) $(CURDIR)/

clean:
	$(MAKE) M=$(CURDIR) clean
	@rm -f *~

.PHONY: verify_cmds verify_target_bpf $(CLANG) $(LLC)

verify_cmds: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if ! (which -- "$${TOOL}" > /dev/null 2>&1); then \
			echo "*** ERROR: Cannot find LLVM tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

verify_target_bpf: verify_cmds
	@if ! (${LLC} -march=bpf -mattr=help > /dev/null 2>&1); then \
		echo "*** ERROR: LLVM (${LLC}) does not support 'bpf' target" ;\
		echo "   NOTICE: LLVM version >= 3.7.1 required" ;\
		exit 2; \
	else true; fi

$(src)/src/*.c: verify_target_bpf

# asm/sysreg.h - inline assembly used by it is incompatible with llvm.
# But, there is no easy way to fix it, so just exclude it since it is
# useless for BPF samples.
$(obj)/obj/%.o: $(src)/src/%.c
	$(CLANG) $(BPF_CFLAGS) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
	  -D __BPF_TRACING__ \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-O2 -S -emit-llvm -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@
