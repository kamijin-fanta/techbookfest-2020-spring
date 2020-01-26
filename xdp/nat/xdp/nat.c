#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define NAT_FLAG_EGRESS 0
#define NAT_FLAG_INGRESS 1

struct v4_nat_key {
	__u32 saddr;
	__u32 daddr;
	__u16 sport;  // or ICMP echo id
	__u16 dport;
	__u8 protocol;  // IPPROTO_*
	__u8 flag;  // NAT_FLAG_EGRESS, NAT_FLAG_INGRESS
};
struct v4_nat_entry {
	__u64 created;  // kernel time
	__u32 addr;
	__u16 port;
};

struct bpf_map_def SEC("v4_nat") v4_nat = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(struct v4_nat_key),
	.value_size = sizeof(struct v4_nat_entry),
	.max_entries = 1024*1024,
};

static __always_inline __u8 create_nat_entry(struct v4_nat_key* out_key, struct v4_nat_entry* out_entry) {
	struct v4_nat_key ret_key = {};
	struct v4_nat_entry ret_entry = {};

	// out_entry->addr = global_addr  // todo

	ret_entry.addr = out_key->saddr;
	ret_entry.port = out_key->sport;

	ret_key.protocol = out_key->protocol;
	ret_key.saddr = out_key->daddr;
	ret_key.sport = out_key->dport;
	ret_key.daddr = out_entry->addr; // todo
	ret_key.dport = out_entry->port; // todo
	ret_key.flag = NAT_FLAG_INGRESS;

	return 0;
}

SEC("xdp")
int xdp_prog_nat(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	
	struct ethhdr *eth = data;
	if (data_end < ((void*)eth) + sizeof(*eth)) {
		return XDP_DROP;
	}

	__be16 h_proto = eth->h_proto;
	if (h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_DROP; // support only ipv4
	}

	struct iphdr *ipv4 = data + sizeof(*eth);
	if (data_end < ((void*)ipv4) + sizeof(*ipv4)) {
		return XDP_DROP;
	}

	struct tcphdr *tcp;
	struct udphdr *udp;
	switch (ipv4->protocol) {
		case IPPROTO_TCP:
			tcp = (void*)ipv4 + sizeof(*ipv4);
			if (data_end < ((void*)tcp) + sizeof(*tcp)) {
				return XDP_DROP;
			}
			if (tcp->dest == bpf_htons(80)) {
				return XDP_PASS;
			} else {
				return XDP_DROP;
			}
		case IPPROTO_UDP:
			udp = (void*)ipv4 + sizeof(*ipv4);
			if (data_end < ((void*)udp) + sizeof(*udp)) {
				return XDP_DROP;
			}
			if (udp->dest == bpf_htons(53)) {
				return XDP_PASS;
			} else {
				return XDP_DROP;
			}
	}

	bpf_printk("drop packet\n");
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
