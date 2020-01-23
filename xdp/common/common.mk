# Common Makefile parts for BPF-building with libbpf
# --------------------------------------------------
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
#
# This file should be included from your Makefile like:
#  COMMON_DIR = ../common/
#  include $(COMMON_DIR)/common.mk
#
# It is expected that you define the variables:
#  XDP_TARGETS and USER_TARGETS
# as a space-separated list
#
LLC ?= llc
CLANG ?= clang
CC ?= gcc

XDP_C = ${XDP_TARGETS:=.c}
XDP_OBJ = ${XDP_C:.c=.o}

# Expect this is defined by including Makefile, but define if not
LIBBPF_DIR ?= ../libbpf/src/

COPY_LOADER ?=

EXTRA_DEPS +=

BPF_CFLAGS ?= -I$(LIBBPF_DIR)build/usr/include/ -I$(LIBBPF_DIR)include/ -I$(LIBBPF_DIR)../include/uapi
BPF_CFLAGS += -I/usr/include/$(shell arch)-linux-gnu

all: llvm-check $(USER_TARGETS) $(XDP_OBJ) $(COPY_LOADER) $(COPY_STATS)

.PHONY: clean $(CLANG) $(LLC)

clean:
	rm -rf $(LIBBPF_DIR)/build
	$(MAKE) -C $(LIBBPF_DIR) clean
	rm -f $(USER_TARGETS) $(XDP_OBJ) $(USER_OBJ) $(COPY_LOADER) $(COPY_STATS)
	rm -f *.ll
	rm -f *~

# For build dependency on this file, if it gets updated
COMMON_MK = $(COMMON_DIR)/common.mk

libbpf:
	@if [ ! -d $(LIBBPF_DIR) ]; then \
		echo "Error: Need libbpf submodule"; \
		echo "May need to run git submodule update --init"; \
		exit 1; \
	else \
		cd $(LIBBPF_DIR) && $(MAKE) all; \
		mkdir -p build; DESTDIR=build $(MAKE) install_headers; \
	fi

llvm-check: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if [ ! $$(command -v $${TOOL} 2>/dev/null) ]; then \
			echo "*** ERROR: Cannot find tool $${TOOL}" ;\
			exit 1; \
		else true; fi; \
	done

$(XDP_OBJ): %.o: %.c  Makefile $(COMMON_MK) $(KERN_USER_H) $(EXTRA_DEPS) libbpf
	$(CLANG) -S \
	    -target bpf \
	    -D __BPF_TRACING__ \
	    $(BPF_CFLAGS) \
	    -Wall \
	    -Wno-unused-value \
	    -Wno-pointer-sign \
	    -Wno-compare-distinct-pointer-types \
	    -Werror \
	    -O2 -emit-llvm -c -g -o ${@:.o=.ll} $<
	$(LLC) -march=bpf -filetype=obj -o $@ ${@:.o=.ll}


GOCMD=go

OUT_NAME := $(shell basename $(CURDIR))

build-go: *.go
	mkdir -p obj
	$(GOCMD) build -o obj/$(OUT_NAME) .

test-go: *.go xdp/*.o
	mkdir -p obj
	go test -c -o obj/$(OUT_NAME)_test .
	sudo chown root obj/$(OUT_NAME)_test
	sudo chmod +s obj/$(OUT_NAME)_test
	go test -o obj/$(OUT_NAME)_test -count=1

FORCE:
