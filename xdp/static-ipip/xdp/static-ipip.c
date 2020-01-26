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

static __always_inline void csum_update(struct iphdr *iph)
{
	__u16 *next_iph_u16;
	__u32 csum = 0;
	int i;
	iph->check = 0;
	next_iph_u16 = (__u16 *)iph;
#pragma clang loop unroll(full)
	for (i = 0; i<sizeof(*iph)>> 1; i++)
		csum += *next_iph_u16++;

	iph->check = ~((csum & 0xffff) + (csum >> 16));
}

#define IP_DF		0x4000		/* Flag: "Don't Fragment"	*/

// const __u32 target_start_ip = 0x0A000000; // 10.0.0.0
// const __u32 target_end_ip =   0x0AFFFFFF; // 10.255.255.255
const __u32 target_start_ip = 0xC0A80000; // 192.168.0.0
const __u32 target_end_ip =   0xC0A8FFFF; // 192.168.255.255
// const __u32 tunnel_src_ip =   0xAC180105; // 172.24.1.5
const __u32 tunnel_src_ip =   0xC0A8C901; // 192.168.201.1
// const __u32 tunnel_dst_ip =   0xAC180106; // 172.24.1.6
const __u32 tunnel_dst_ip =   0xC0A8CA02; // 192.168.202.2

SEC("xdp_encap")
int xdp_prog_static_ipip_encap(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	
	struct ethhdr *eth = data;
	if (data_end < ((void*)eth) + sizeof(*eth)) {
		return XDP_PASS;
	}

	__u16 h_proto = eth->h_proto;
	if (h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS; // support only ipv4
	}

	struct iphdr *ipv4 = data + sizeof(*eth);
	if (data_end < ((void*)ipv4) + sizeof(*ipv4)) {
		return XDP_PASS;
	}

	// 宛先IPアドレスが範囲内か確認
	__u32 daddr = bpf_htonl(ipv4->daddr);
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

	if (data_end < (void*)outer_ipv4 + sizeof(*outer_ipv4)) {
		return XDP_DROP;
	}

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
	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	fib_params.family = AF_INET;
	fib_params.tos = outer_ipv4->tos;
	fib_params.l4_protocol = outer_ipv4->protocol;
	fib_params.sport = 0;
	fib_params.dport = 0;
	fib_params.tot_len = bpf_ntohs(outer_ipv4->tot_len);
	fib_params.ipv4_src = outer_ipv4->saddr;  // network byte order
	fib_params.ipv4_dst = outer_ipv4->daddr;
	fib_params.ifindex = ctx->ingress_ifindex;

	csum_update(outer_ipv4);

	int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
		bpf_printk("encap: fib_lookup failed %d %d\n", rc, ctx->ingress_ifindex);
		return XDP_DROP;
	}

	memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
	memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);

	bpf_printk("encap: tunnel packet %d -> %d\n", ctx->ingress_ifindex, fib_params.ifindex);
	return XDP_PASS;
}


SEC("xdp_decap")
int xdp_prog_static_ipip_decap(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	
	struct ethhdr *eth = data;
	if (data_end < ((void*)eth) + sizeof(*eth)) {
		return XDP_PASS;
	}

	__u16 h_proto = eth->h_proto;
	if (h_proto != bpf_htons(ETH_P_IP)) {
		return XDP_PASS; // support only ipv4
	}

	struct iphdr *ipv4 = data + sizeof(*eth);
	if (data_end < ((void*)ipv4) + sizeof(*ipv4)) {
		return XDP_PASS;
	}

	// 送信元IPアドレス・プロトコルを確認
	__u32 saddr = bpf_ntohl(ipv4->saddr);
	if (saddr != tunnel_src_ip || ipv4->protocol != IPPROTO_IPIP) {
		return XDP_PASS;
	}

  // IPIPヘッダの削除
	int ipip_header_size = sizeof(struct iphdr);
	if(bpf_xdp_adjust_head(ctx, ipip_header_size)){
			return XDP_DROP;
	}

  // 各アドレスの再設定
	data = (void *)(long)ctx->data;
	data_end = (void *)(long)ctx->data_end;
	eth = data;
	ipv4 = data + sizeof(*eth);

	if (data_end < (void*)ipv4 + sizeof(*ipv4)) {
		return XDP_DROP;
	}

	eth->h_proto = bpf_htons(ETH_P_IP);

	struct bpf_fib_lookup fib_params = {};
	__builtin_memset(&fib_params, 0, sizeof(fib_params));
	fib_params.family = AF_INET;
	fib_params.tos = ipv4->tos;
	fib_params.l4_protocol = ipv4->protocol;
	fib_params.sport = 0;
	fib_params.dport = 0;
	fib_params.tot_len = bpf_ntohs(ipv4->tot_len);
	fib_params.ipv4_src = ipv4->saddr;  // network byte order
	fib_params.ipv4_dst = ipv4->daddr;
	fib_params.ifindex = ctx->ingress_ifindex;

	int rc = bpf_fib_lookup(ctx, &fib_params, sizeof(fib_params), BPF_FIB_LOOKUP_DIRECT);
	if (rc != BPF_FIB_LKUP_RET_SUCCESS) {
		bpf_printk("decap: fib_lookup failed %d %d\n", rc, ctx->ingress_ifindex);
		return XDP_DROP;
	}

	memcpy(eth->h_source, fib_params.smac, ETH_ALEN);
	memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);

	bpf_printk("decap: tunnel packet %d -> %d\n", ctx->ingress_ifindex, fib_params.ifindex);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
