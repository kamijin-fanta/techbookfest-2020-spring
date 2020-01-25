package main

import (
	"github.com/bradleyjkemp/cupaloy"
	"github.com/stretchr/testify/assert"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
	"github.com/kamijin-fanta/techbookfest-2020-spring/xdp/pkg/xdp"
	"net"
	"github.com/newtools/ebpf"
	"testing"
)

func TestHttpTrafic(t *testing.T) {
	spec, err := ebpf.LoadCollectionSpec("./xdp/static-ipip.o")
	if err != nil {
		panic(err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		panic(err)
	}
	defer coll.Close()

	xdpFwdProg := coll.Programs["xdp_prog_static_ipip_decap"]


	dstMac, _ := net.ParseMAC("11:22:33:44:55:aa")
	srcMac, _ := net.ParseMAC("11:22:33:44:55:bb")

	
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			DstMAC:       dstMac,
			SrcMAC:       srcMac,
			EthernetType: layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			Protocol: layers.IPProtocolICMPv4,
			Flags:    layers.IPv4DontFragment,
			SrcIP:    net.IP{192, 168, 201, 1},
			DstIP:    net.IP{192, 168, 202, 2},
			TTL:      64,
			IHL:      5,
			Id:       1160,
		},
		&layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			Id:       1,
			Seq:      1,
		},
	)

	inputPacket := buf.Bytes()
	ret, res, err := xdpFwdProg.Test(inputPacket)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, xdp.XDP_PASS.String(), xdp.XdpAction(ret).String())

	parsed := gopacket.NewPacket(res, layers.LayerTypeEthernet, gopacket.Default)
	cupaloy.SnapshotT(t, parsed.Layers()) // if update snapshot: UPDATE_SNAPSHOTS=true

	t.Log("has problem? you need 'echo 1 >/proc/sys/net/ipv4/ip_forward'")
}
