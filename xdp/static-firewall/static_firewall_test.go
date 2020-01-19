package main

import (
	"github.com/k0kubun/pp"
	"github.com/kamijin-fanta/techbookfest-2020-spring/xdp/pkg/xdp"
	"github.com/stretchr/testify/assert"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
	"net"
	"github.com/newtools/ebpf"
	"testing"
)

func TestHttpTrafic(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec("./xdp/static-firewall.o")
	if err != nil {
		panic(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(err)
	}
	defer coll.Close()

	xdpFwdProg := coll.Programs["xdp_prog_static_firewall"]

	dstMac, _ := net.ParseMAC("11:22:33:44:55:aa")
	srcMac, _ := net.ParseMAC("11:22:33:44:55:bb")

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
	}

	eth := &layers.Ethernet{
		DstMAC:       dstMac,
		SrcMAC:       srcMac,
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		Protocol: layers.IPProtocolTCP,
		Flags:    layers.IPv4DontFragment,
		SrcIP:    net.IP{192, 168, 100, 10},
		DstIP:    net.IP{192, 168, 100, 20},
		TTL:      64,
		IHL:      5,
		Id:       1160,
	}
	tcp := &layers.TCP{
		SrcPort: 12345,
		DstPort: 80,
		Seq: 111,
		DataOffset: 0x5,
	}
	tcp.SetNetworkLayerForChecksum(ip)
	payload := gopacket.Payload([]byte("hello"))

	gopacket.SerializeLayers(buf, opts,
		eth,
		ip,
		tcp,
		payload,
	)

	inputPacket := buf.Bytes()
	ret, res, err := xdpFwdProg.Test(inputPacket)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, xdp.XDP_PASS, ret)
	t.Logf("input: %v", inputPacket)
	t.Logf("res: %v", res)

	parsed := gopacket.NewPacket(res, layers.LayerTypeEthernet, gopacket.Default)
	t.Logf("layers: %s", pp.Sprint(parsed.Layers())) 
}
