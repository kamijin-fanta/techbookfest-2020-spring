#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>

SEC("xdp")
int xdp_prog_static_firewall(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	
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
	switch (ipv4->protocol) {
		case IPPROTO_TCP:
			tcp = data;
			if (data_end < ((void*)tcp) + sizeof(*tcp)) {
				return XDP_DROP;
			}
			if (tcp->dest == 80) {
				return XDP_PASS;
			} else {
				return XDP_DROP;
			}
		case IPPROTO_UDP:
			return XDP_PASS;
	}

	bpf_printk("drop packet\n");
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
