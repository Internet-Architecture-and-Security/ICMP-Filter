#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/netfilter.h>
#include <linux/if_link.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <time.h>

#define PATH_MAX 4096

struct perdst_entry {
    long long credit;
    __u64 accum;
    __u64 stamp;
};

int main(int argc, char **argv) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    char filename[PATH_MAX];
    int ret;

    obj = bpf_object__open_file("icmp_filter.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "ERROR: opening BPF object file failed\n");
        return 1;
    }

    ret = bpf_object__load(obj);
    if (ret) {
        fprintf(stderr, "ERROR: loading BPF object file failed\n");
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "icmp_filter");
    if (!prog) {
        fprintf(stderr, "ERROR: finding a program in BPF object file failed\n");
        bpf_object__close(obj);
        return 1;
    }

    int map_fd = bpf_object__find_map_fd_by_name(obj, "hash_key");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: finding hash_key in BPF object file failed\n");
        bpf_object__close(obj);
        return 1;
    }

    srand(time(0));

    __u32 key = 0;
    __u32 value = random();
    ret = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
    if (ret) {
        fprintf(stderr, "ERROR: updating map in BPF object file failed\n");
        bpf_object__close(obj);
        return 1;
    }
    printf("Set hash key: %u\n", value);

    map_fd = bpf_object__find_map_fd_by_name(obj, "icmp_map");
    if (map_fd < 0) {
        fprintf(stderr, "ERROR: finding icmp_map in BPF object file failed\n");
        bpf_object__close(obj);
        return 1;
    }

    for (int i = 0; i < 2048; ++i) {
        struct perdst_entry entry = {
            .credit = 500,
            .accum = 0,
            .stamp = 0,
        };
        ret = bpf_map_update_elem(map_fd, &i, &entry, BPF_ANY);
        if (ret) {
            fprintf(stderr, "ERROR: updating map in BPF object file failed\n");
            bpf_object__close(obj);
            return 1;
        }
    }

    int log_map_fd = bpf_object__find_map_fd_by_name(obj, "log_map");
    if (log_map_fd < 0) {
        fprintf(stderr, "ERROR: finding log_map in BPF object file failed\n");
        bpf_object__close(obj);
        return 1;
    }

    int err = bpf_obj_pin(log_map_fd, "/sys/fs/bpf/icmp_filter_log_map");
    if (err) {
        fprintf(stderr, "ERROR: pinning log_map failed\n");
        bpf_object__close(obj);
        return 1;
    }

    struct bpf_netfilter_opts opts = {
        .sz = sizeof(struct bpf_netfilter_opts),
        .pf = NFPROTO_IPV4,
        .hooknum = NF_INET_LOCAL_IN,
        .priority = 1,
        .flags = 0,
    };

    link = bpf_program__attach_netfilter(prog, &opts);
    if (!link) {
        fprintf(stderr, "ERROR: attaching BPF program to Netfilter hook failed\n");
        bpf_object__close(obj);
        return 1;
    }

    ret = bpf_link__pin(link, "/sys/fs/bpf/icmp_filter_link");
    if (ret) {
        fprintf(stderr, "ERROR: pinning BPF link failed\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    printf("eBPF program icmp_filter successfully attached to Netfilter hook and pinned\n");

    bpf_object__close(obj);

    return 0;
}