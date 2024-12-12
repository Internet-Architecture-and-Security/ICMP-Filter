CC := clang
BPF_CFLAGS := -O2 -target bpf -g -c -Iinclude
LOADER_CFLAGS := -O2
LOGGER_CFLAGS := -O2
LOADER_LDFLAGS := -lbpf
LOGGER_LDFLAGS := -lbpf
BPF_LOADER := icmp_filter_loader
BPF_LOGGER := icmp_filter_logger
BPF_PROG := icmp_filter

INT_FILES := $(BPF_LOADER) $(BPF_LOGGER) $(BPF_PROG).o

.PHONY: all clean load unload

all: $(BPF_LOADER) $(BPF_LOGGER)

$(BPF_LOADER): $(BPF_LOADER).c $(BPF_PROG).o
	@$(CC) $(LOADER_CFLAGS) -o $@ $< $(LOADER_LDFLAGS)

$(BPF_LOGGER): $(BPF_LOGGER).c $(BPF_PROG).o
	@$(CC) $(LOGGER_CFLAGS) -o $@ $< $(LOGGER_LDFLAGS)

$(BPF_PROG).o: $(BPF_PROG).c
	@if ! test -f include/vmlinux.h; then \
		bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h || exit 1; \
	fi
	@$(CC) $(BPF_CFLAGS) -o $@ $^

clean:
	@rm -f $(INT_FILES)

load: $(BPF_LOADER)
	@sudo ./$(BPF_LOADER)

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
		echo "No log map found!"; \
		exit 1; \
	fi
	@sudo ./$(BPF_LOGGER)