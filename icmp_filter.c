#include "vmlinux.h"
#include "common.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ONE_SECOND 1000000000
struct perdst_entry {
    long long credit;
    __u64 accum;
    __u64 stamp;
};

struct log_event {
    char ip[20];
    __u8 type;
    __u64 timestamp;
};

__u64 mymin64(__u64 a, __u64 b) {
    return a < b ? a : b;
}

__u32 mymin32(__u32 a, __u32 b) {
    return a < b ? a : b;
}

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, struct perdst_entry);
	__uint(max_entries, 2048);
} icmp_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, 1);
} hash_key SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} log_map SEC(".maps");

__u32 hash_calc (__u32 ip) {
    __u32 x = 0;
    __u32* key = bpf_map_lookup_elem(&hash_key, &x);
    if (!key) {
        __u32 tmp = bpf_get_prandom_u32();
        key = &tmp;
        bpf_map_update_elem(&hash_key, &x, key, BPF_ANY);
    }
    return (ip ^ *key) % 2048;
}

void ipv4_to_string(char *buf, __u32 ip) {
    int a = (ip >> 24) & 0xFF;
    int b = (ip >> 16) & 0xFF;
    int c = (ip >> 8) & 0xFF;
    int d = ip & 0xFF;

    BPF_SNPRINTF(buf, 16, "%d.%d.%d.%d", a, b, c, d);
}

SEC("netfilter")
int icmp_filter(struct bpf_nf_ctx *ctx) {
    struct sk_buff *skb = ctx->skb;
    struct iphdr iph, inner_iph;
    struct icmphdr icmph, inner_icmph;

    if (ctx->state->pf != NFPROTO_IPV4) {
        return NF_ACCEPT;
    }

    if (bpf_probe_read_kernel(&iph, sizeof(iph), skb->head + skb->network_header) < 0) {
        return NF_ACCEPT;
    }

    if (iph.protocol != IPPROTO_ICMP) {
        return NF_ACCEPT;
    }

    if (bpf_probe_read_kernel(&icmph, sizeof(icmph), skb->head + skb->network_header + sizeof(iph)) < 0) {
        return NF_ACCEPT;
    }

    __u64 cur_stamp = bpf_ktime_get_ns();
    __u32 hash = hash_calc(bpf_ntohl(iph.saddr) & 0xFFFFFF00);

    char buf[20] = {0};
    ipv4_to_string(buf, bpf_ntohl(iph.saddr));

    if (hash >= 2048) {
        hash = 0;
    }

    struct perdst_entry *entry = bpf_map_lookup_elem(&icmp_map, &hash);
    if (!entry) {
        struct perdst_entry new_entry = {
            .credit = 1000,
            .accum = 0,
            .stamp = cur_stamp,
        };
        bpf_map_update_elem(&icmp_map, &hash, &new_entry, BPF_ANY);
        entry = &new_entry;
    }
    
    __u64 old_stamp, new_stamp;
    __u8 drop = 0;
    __u32 consume = bpf_get_prandom_u32() % 2 + 1;
    old_stamp = entry->stamp;
    new_stamp = cur_stamp;
    if (__sync_val_compare_and_swap(&entry->stamp, old_stamp, new_stamp) == old_stamp) {
        __u64 accum = __sync_add_and_fetch(&entry->accum, mymin64(ONE_SECOND, new_stamp - old_stamp));
        if (accum >= ONE_SECOND / 2) {
            if (__sync_val_compare_and_swap(&entry->accum, accum, mymin64(ONE_SECOND / 2, accum - ONE_SECOND / 2)) == accum) {
                long long credit = __sync_add_and_fetch(&entry->credit, 500);
                if (credit > 1000) {
                    __sync_sub_and_fetch(&entry->credit, credit - 1000);
                }
            }
        }
    }

    if (__sync_sub_and_fetch(&entry->credit, consume) < 0) {
        drop = 1;
        __sync_add_and_fetch(&entry->credit, consume);
    }

    if (drop) {
        struct log_event event = {
            .type = 0,
            .timestamp = cur_stamp,
        };
        bpf_probe_read_kernel_str(event.ip, sizeof(event.ip), buf);
        bpf_ringbuf_output(&log_map, &event, sizeof(event), 0);
        return NF_DROP;
    }


    if ((icmph.type != ICMP_DEST_UNREACH || icmph.code != ICMP_FRAG_NEEDED) && icmph.type != ICMP_REDIRECT) {
        return NF_ACCEPT;
    }

    if (bpf_probe_read_kernel(&inner_iph, sizeof(inner_iph), skb->head + skb->network_header + sizeof(iph) + sizeof(icmph)) < 0) {
        return NF_ACCEPT;
    }

    if (icmph.type == ICMP_REDIRECT) {
        if (inner_iph.protocol == IPPROTO_UDP || inner_iph.protocol == IPPROTO_ICMP) {
            struct log_event event = {
                .type = 1,
                .timestamp = cur_stamp,
            };
            bpf_probe_read_kernel_str(event.ip, sizeof(event.ip), buf);
            bpf_ringbuf_output(&log_map, &event, sizeof(event), 0);
            return NF_DROP;
        }
    } else {
        if (inner_iph.protocol == IPPROTO_ICMP) {
            if (bpf_probe_read_kernel(&inner_icmph, sizeof(inner_icmph), skb->head + skb->network_header + sizeof(iph) + sizeof(icmph) + sizeof(inner_iph)) < 0) {
                return NF_ACCEPT;
            }
            if (inner_icmph.type == ICMP_ECHOREPLY || inner_icmph.type == ICMP_DEST_UNREACH || inner_icmph.type == ICMP_REDIRECT) {
                struct log_event event = {
                    .type = 2,
                    .timestamp = cur_stamp,
                };
                bpf_probe_read_kernel_str(event.ip, sizeof(event.ip), buf);
                bpf_ringbuf_output(&log_map, &event, sizeof(event), 0);
                return NF_DROP;
            }
        }
    }

    return NF_ACCEPT;
}

char _license[] SEC("license") = "GPL";