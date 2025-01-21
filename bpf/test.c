// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"


char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u8 payload[1500];
};

const struct event *_ __attribute__((unused));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} perf_output SEC(".maps");

SEC("tp_btf/netif_receive_skb")
int BPF_PROG(tp_btf_netif_receive_skb, struct sk_buff *skb)
{
	if (BPF_CORE_READ(skb, dev, ifindex) != 1)
		return 0;

	static struct event event = {};
	u64 flags = ((__u64) BPF_CORE_READ(skb, len)) << 32 | BPF_F_CURRENT_CPU;
        bpf_skb_output(skb, &perf_output, flags, &event, 0);
	return 0;
}

