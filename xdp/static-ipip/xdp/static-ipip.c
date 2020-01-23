#include <linux/bpf.h>  // SEC, xdp_md, bpf_htonl, bpf_fib_lookup
#include <bpf/bpf_endian.h>  // bpf_htonl
#include <bpf/bpf_helpers.h> // SEC, bpf_printk
#include <linux/if_ether.h> // ethhdr
#include <linux/ip.h> // iphdr
#include <linux/in.h> // IPPROTO_IPIP
#include <sys/socket.h>  // AF_INET

#ifndef memset
# define memset(dest, chr, n)   __builtin_memset((dest), (chr), (n))
#endif

#ifndef memcpy
# define memcpy(dest, src, n)   __builtin_memcpy((dest), (src), (n))
#endif

#ifndef memmove
# define memmove(dest, src, n)  __builtin_memmove((dest), (src), (n))
#endif

#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/

const __be32 target_start_ip = 0x0A000000; // 10.0.0.0
const __be32 target_end_ip =   0x0AFFFFFF; // 10.255.255.255
const __be32 tunnel_src_ip =   0xAC180105; // 172.24.1.5
const __be32 tunnel_dst_ip =   0xAC180106; // 172.24.1.6

SEC("xdp")
int xdp_prog_static_ipip_decap(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	
	struct ethhdr *eth = data;
	if (data_end < ((void*)eth) + sizeof(*eth)) {
		return XDP_PASS;
	}

	__be16 h_proto = eth->h_proto;
	if (h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS; // support only ipv4
	}

	struct iphdr *ipv4 = data + sizeof(*eth);
	if (data_end < ((void*)ipv4) + sizeof(*ipv4)) {
		return XDP_PASS;
	}

	// 宛先IPアドレスが範囲内か確認
	__be32 daddr = bpf_htonl(ipv4->daddr);
	if (daddr < target_start_ip || target_end_ip < daddr) {
		return XDP_PASS;
	}

  // ヘッダの拡張
	int ipip_header_size = sizeof(struct iphdr);
	if(bpf_xdp_adjust_head(ctx, 0 - ipip_header_size)){
			return XDP_DROP;
	}

  // 各アドレスの再設定
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	struct ethhdr *old_eth = data + ipip_header_size;
	struct iphdr *outer_ipv4 = data + sizeof(*eth);

	memcpy(eth->h_source, old_eth->h_source, sizeof(eth->h_source));
	eth->h_proto = old_eth->h_proto;

	outer_ipv4->version = 4;
	outer_ipv4->ihl = sizeof(*outer_ipv4) >> 2;
	outer_ipv4->frag_off = bpf_htons(IP_DF);
	outer_ipv4->protocol = IPPROTO_IPIP;
	outer_ipv4->check = 0;
	outer_ipv4->tos = 0;
	outer_ipv4->tot_len = bpf_htons((void*)data_end - (void*)outer_ipv4);
	outer_ipv4->saddr = bpf_htonl(tunnel_src_ip);
	outer_ipv4->daddr = bpf_htonl(tunnel_dst_ip);
	outer_ipv4->ttl = 64;

	struct bpf_fib_lookup fib_params = {};
	fib_params.family = AF_INET;
	fib_params.family = outer_ipv4->tos;
	fib_params.l4_protocol = outer_ipv4->protocol;
	fib_params.sport = 0;
	fib_params.dport = 0;
	fib_params.tot_len = bpf_ntohs(outer_ipv4->tot_len);
	fib_params.ipv4_src = tunnel_src_ip;
	fib_params.ipv4_dst = tunnel_dst_ip;

	// csum_update //todo

	int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT | BPF_FIB_LOOKUP_OUTPUT);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
		return XDP_DROP;
	}

	memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
	memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);

	bpf_printk("tunnel packet\n");
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
