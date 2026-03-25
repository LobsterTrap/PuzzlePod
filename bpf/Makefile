# BPF LSM programs for PuzzlePod
#
# Requirements:
#   dnf install clang llvm bpftool kernel-devel
#
# Usage:
#   make          — Compile BPF programs
#   make clean    — Remove build artifacts
#
# The vmlinux.h header is generated from the running kernel's BTF data.
# If not present, generate it with:
#   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

CLANG ?= clang
BPFTOOL ?= bpftool
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH)
INCLUDES := -I. -I/usr/include

PROGS := exec_guard.bpf.o

.PHONY: all clean vmlinux

all: vmlinux.h $(PROGS)

# Generate vmlinux.h from kernel BTF (one-time setup)
vmlinux.h:
	@if [ ! -f vmlinux.h ]; then \
		echo "Generating vmlinux.h from /sys/kernel/btf/vmlinux..."; \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	fi

%.bpf.o: %.bpf.c %.h vmlinux.h
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

clean:
	rm -f *.bpf.o
	rm -f vmlinux.h
