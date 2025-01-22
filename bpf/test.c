// +build ignore

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"
#include "bpf_tracing.h"

#define MAX_PAYLOAD 0x0fff

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u8 payload[MAX_PAYLOAD];
};

const struct event *_ __attribute__((unused));

#define vmemmap 0xffffe80440000000
#define page_offset 0xffff96a6c0000000

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} perf_output SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1<<29);
} ringbuf_output SEC(".maps");

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


SEC("kprobe/__netif_receive_skb_core")
int kprobe___netif_receive_skb_core(struct pt_regs *ctx)
{
	struct sk_buff **pskb = (struct sk_buff **)PT_REGS_PARM1(ctx);
	struct sk_buff *skb;
	bpf_probe_read_kernel(&skb, sizeof(skb), pskb);
	if (BPF_CORE_READ(skb, dev, ifindex) != 1)
		return 0;

	static struct event event = {};
	u64 submit_len = 0;

	void *skb_head = (void *)BPF_CORE_READ(skb, head);
	u16 network_header = BPF_CORE_READ(skb, network_header);
	u32 linear_len = BPF_CORE_READ(skb, tail) - (u32)network_header;
	linear_len &= MAX_PAYLOAD;
	bpf_probe_read_kernel(&event.payload, linear_len, (void *)(skb_head + network_header));
	submit_len += linear_len;
	if (submit_len >= MAX_PAYLOAD || BPF_CORE_READ(skb, data_len) == 0)
		goto submit;

	struct page *bv_page;
	u32 bv_offset, bv_len;
	u64 vaddr;

	struct skb_shared_info *shinfo = (struct skb_shared_info *)(skb_head + BPF_CORE_READ(skb, end));
	for (u8 i = 0; i < 17; i++) {
		if (i > BPF_CORE_READ(shinfo, nr_frags))
			break;

		BPF_CORE_READ_INTO(&bv_page, shinfo, frags[i].bv_page);
		BPF_CORE_READ_INTO(&bv_len, shinfo, frags[i].bv_len);
		BPF_CORE_READ_INTO(&bv_offset, shinfo, frags[i].bv_offset);

		vaddr = ((((u64)bv_page - (u64)vmemmap) >> 6) << 0xc) + page_offset;
		bv_len = submit_len + bv_len > MAX_PAYLOAD ? MAX_PAYLOAD - submit_len : bv_len;
		bv_len &= MAX_PAYLOAD;
		bpf_probe_read_kernel((void *)&event.payload + submit_len, bv_len, (void *)(vaddr + bv_offset));
		submit_len += bv_len;
		if (submit_len >= MAX_PAYLOAD)
			break;
	}

submit:
	bpf_ringbuf_output(&ringbuf_output, &event, submit_len & MAX_PAYLOAD, 0);
	return 0;
}
