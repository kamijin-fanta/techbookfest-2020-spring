# xdp

## 概要

- XDP+GO言語で作る高速パケット処理
- Linux Kernelの仕組みで、高速なNetwork Functionを自作できるようになる
- テストを回しながら作る お手軽自作NAT/ファイアウォール/トンネリング
- Go言語でテストを書きながら作る　高速パケット処理XDP

## 内容

- チュートリアル
  - DROP, PASS + printk
  - ファイアウォール (static)
  - ファイアウォール (Map利用)
  - IPIP Tunnel
  - IPIP Tunnel (Map利用)
  - NAT (bpf_ktime_get_ns, map, checksum)
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
- tutorial
  - https://github.com/xdp-project/xdp-tutorial

## how to debug

- CLI
  - `trace-cmd start -e 'xdp:*'`
  - `trace-cmd show`
  - `cat /sys/kernel/debug/tracing/trace_pipe`
- GUI
  - `trace-cmd record -e 'xdp:*' -O trace_printk`
  - `kernelshark`

```
[882316.042280] **********************************************************
[882316.042280] **   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **
[882316.042281] **                                                      **
[882316.042281] ** trace_printk() being used. Allocating extra memory.  **
[882316.042282] **                                                      **
[882316.042282] ** This means that this is a DEBUG kernel and it is     **
[882316.042283] ** unsafe for production use.                           **
[882316.042283] **                                                      **
[882316.042284] ** If you see this message and you are not debugging    **
[882316.042284] ** the kernel, report this immediately to your vendor!  **
[882316.042285] **                                                      **
[882316.042285] **   NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE NOTICE   **
[882316.042286] **********************************************************
```

## 開発環境

- editor
  - VS Code
  - https://marketplace.visualstudio.com/items?itemName=ms-vscode.cpptools
- さくらのクラウド
  - マルチキューサポート
  - https://cloud-news.sakura.ad.jp/2019/03/14/hostserver-irqbalance-enhanced/

## 表紙

- かわいい https://www.amazon.co.jp/dp/B07LGN6M86
