#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_prog_dynamic_firewall(struct xdp_md *ctx)
{
	bpf_printk("drop packet\n");
	return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
