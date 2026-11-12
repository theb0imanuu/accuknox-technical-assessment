CLANG ?= clang
CFLAGS ?= -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86
INCLUDES ?= -I./common/bpf_headers
GO ?= go

BPF_TARGETS = problem1-drop-port/bpf/xdp_drop_port.o problem2-process-filter/bpf/cgroup_process_filter.o
GO_TARGETS = problem1-drop-port/drop-port problem2-process-filter/proc-filter problem2-process-filter/myprocess

.PHONY: all bpf go clean test test-p1 test-p2 test-p3 docker-build

all: bpf go

bpf: $(BPF_TARGETS)

problem1-drop-port/bpf/xdp_drop_port.o: problem1-drop-port/bpf/xdp_drop_port.c
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

problem2-process-filter/bpf/cgroup_process_filter.o: problem2-process-filter/bpf/cgroup_process_filter.c
	$(CLANG) $(CFLAGS) $(INCLUDES) -c $< -o $@

go:
	cd problem1-drop-port && $(GO) build -o drop-port main.go
	cd problem2-process-filter && $(GO) build -o proc-filter main.go
	cd problem2-process-filter && $(GO) build -o myprocess ./dummy_process
	cd problem3-code-explanation/buggy && $(GO) build -o buggy main.go
	cd problem3-code-explanation/fixed && $(GO) build -o fixed main.go

test-p1: bpf
	bash problem1-drop-port/test.sh

test-p2: bpf
	bash problem2-process-filter/test.sh

test-p3:
	@echo "=== Running Buggy Problem 3 (Notice HERE1 missing intermittently) ==="
	@cd problem3-code-explanation/buggy && $(GO) run main.go
	@echo "=== Running Fixed Problem 3 (Guaranteed completion) ==="
	@cd problem3-code-explanation/fixed && $(GO) run main.go

docker-build:
	docker build -t accuknox-ebpf-interview .

docker-run:
	docker run --rm -it --privileged -v /sys/fs/cgroup:/sys/fs/cgroup:ro accuknox-ebpf-interview

clean:
	rm -f $(BPF_TARGETS)
	rm -f problem1-drop-port/drop-port
	rm -f problem2-process-filter/proc-filter
	rm -f problem2-process-filter/myprocess
	rm -f problem3-code-explanation/buggy/buggy*
	rm -f problem3-code-explanation/fixed/fixed*

