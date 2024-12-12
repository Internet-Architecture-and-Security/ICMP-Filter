CC := clang
COMMON_CFLAGS := -Wall -O2
BPF_CFLAGS := $(COMMON_CFLAGS) -target bpf -g -c -Iinclude
LOADER_CFLAGS := $(COMMON_CFLAGS)
LOGGER_CFLAGS := $(COMMON_CFLAGS)
BPF_LDFLAGS := -lbpf
BPF_LDFLAGS := -lbpf
BPF_LOADER := icmp_filter_loader
BPF_LOGGER := icmp_filter_logger
BPF_PROG := icmp_filter

INT_FILES := $(BPF_LOADER) $(BPF_LOGGER) $(BPF_PROG).o

.PHONY: all clean load unload log

all: $(BPF_LOADER) $(BPF_LOGGER)

$(BPF_LOADER): $(BPF_LOADER).c $(BPF_PROG).o
	@$(CC) $(LOADER_CFLAGS) -o $@ $< $(BPF_LDFLAGS)

$(BPF_LOGGER): $(BPF_LOGGER).c $(BPF_PROG).o
	@$(CC) $(LOGGER_CFLAGS) -o $@ $< $(BPF_LDFLAGS)

$(BPF_PROG).o: $(BPF_PROG).c
	@if ! test -f include/vmlinux.h; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h || exit 1; \
	fi
	@$(CC) $(BPF_CFLAGS) -o $@ $^

clean:
	@rm -f $(INT_FILES)

load: $(BPF_LOADER)
	@if ! sudo test -f /sys/fs/bpf/icmp_filter_link; then \
		sudo ./$(BPF_LOADER); \
	else \
		echo "The BPF program has already been loaded!"; \
	fi
	

unload:
	@if sudo test -f /sys/fs/bpf/icmp_filter_link; then \
		sudo rm -f /sys/fs/bpf/icmp_filter_link; \
		sudo rm -f /sys/fs/bpf/icmp_filter_log_map; \
		echo "Unloaded successfully!"; \
	else \
		echo "Nothing to unload."; \
	fi

log: $(BPF_LOGGER)
	@if ! sudo test -f /sys/fs/bpf/icmp_filter_log_map; then \
		echo "No log map found! Please run 'make load' first!"; \
	else \
		sudo ./$(BPF_LOGGER); \
	fi