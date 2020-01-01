# xdp

## 概要

- XDP+GO言語で作る高速パケット処理
- Linux Kernelの仕組みで、高速なNetwork Functionを自作できるようになる
- テストを回しながら作る お手軽自作NAT/ファイアウォール/トンネリング

## 内容

- チュートリアル
  - DROP, PASS + printk
  - ファイアウォール
  - IPIP Tunnel
  - NAT (bpf_ktime_get_ns)
- go
  - github.com/newtools/ebpf
  - github.com/vishvananda/netlink
  - github.com/stretchr/testify
  - github.com/google/gopacket
- other
  - jit
  - tailcall
  - ip link


## refs

- blog
  - takeio http://takeio.hatenablog.com/entry/2019/12/05/212945
  - 
  XDPを触ってみる http://yunazuno.hatenablog.com/entry/2016/10/11/090245
- references
  - Cilium BPF: https://docs.cilium.io/en/v1.6/bpf/
  - BPF Helpers: https://github.com/iovisor/bpf-docs/blob/master/bpf_helpers.rst
- 

