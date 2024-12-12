#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <time.h>
#include <stdint.h>
#include <errno.h>

struct log_event {
    char ip[256];
    __u8 type;
    __u64 timestamp;
};

void print_log(struct log_event event) {
    struct timespec boot_time, real_time;
    clock_gettime(CLOCK_BOOTTIME, &boot_time);
    clock_gettime(CLOCK_REALTIME, &real_time);

    time_t boot_sec = boot_time.tv_sec;
    time_t real_sec = real_time.tv_sec;
    time_t offset_sec = real_sec - boot_sec;

    time_t user_time_sec = event.timestamp / 1e9 + offset_sec;

    struct tm user_time_tm;
    if (localtime_r(&user_time_sec, &user_time_tm) == NULL) {
        perror("localtime_r");
        return;
    }

    char time_str[30];

    if (strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &user_time_tm) == 0) {
        fprintf(stderr, "strftime failed\n");
        return;
    }

    printf("[%s] ICMP Filter: ", time_str);
    switch (event.type) {
        case 0:
            printf("Dropped an ICMP packet from %s according to rate limit!\n", event.ip);
            break;
        case 1:
            printf("Dropped an ICMP Redirect packet from %s!\n", event.ip);
            break;
        case 2:
            printf("Dropped an ICMP Fragment Needed packet from %s!\n", event.ip);
            break;
    }
}

int handle_event(void *ctx, void *data, size_t size) {
    print_log(*(struct log_event *)data);
    return 0;
}

int main() {
    struct ring_buffer *rb;
    struct bpf_object *obj;

    int map_fd = bpf_obj_get("/sys/fs/bpf/icmp_filter_log_map");
    if (map_fd < 0) {
        fprintf(stderr, "Failed to open pinned map: %s\n", strerror(errno));
        return 1;
    }

    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer\n");
        return 1;
    }

    while (1) {
        int ret = ring_buffer__poll(rb, 100);
        if (ret < 0) {
            fprintf(stderr, "Error polling ring buffer: %d\n", ret);
            break;
        }
    }

    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}