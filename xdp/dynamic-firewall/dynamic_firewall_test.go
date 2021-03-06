package main

import (
	"github.com/stretchr/testify/assert"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
	"net"
	"github.com/newtools/ebpf"
	"testing"
)


const (
	XDP_ABORTED = uint32(iota)
	XDP_DROP
	XDP_PASS
	XDP_TX
	XDP_REDIRECT
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
	gopacket.SerializeLayers(buf, opts,
		&layers.Ethernet{
			DstMAC:       dstMac,
			SrcMAC:       srcMac,
			EthernetType: layers.EthernetTypeDot1Q,
		},
		&layers.Dot1Q{
			VLANIdentifier: 11,
			Type:           layers.EthernetTypeIPv4,
		},
		&layers.IPv4{
			Version:  4,
			Protocol: layers.IPProtocolICMPv4,
			Flags:    layers.IPv4DontFragment,
			SrcIP:    net.IP{192, 168, 100, 10},
			DstIP:    net.IP{1, 1, 1, 1},
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
	ret, _, err := xdpFwdProg.Test(inputPacket)
	if err != nil {
		panic(err)
	}
	assert.Equal(t, XDP_DROP, ret)
}
