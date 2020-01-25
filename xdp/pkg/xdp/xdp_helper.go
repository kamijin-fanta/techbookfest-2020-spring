package xdp

import (
	"fmt"
)

type XdpAction uint32

const (
	XDP_ABORTED = XdpAction(iota)
	XDP_DROP
	XDP_PASS
	XDP_TX
	XDP_REDIRECT
)

func (a XdpAction) String() string {
	switch a {
	case XDP_ABORTED:
		return "XDP_ABORTED"
	case XDP_DROP:
		return "XDP_DROP"
	case XDP_PASS:
		return "XDP_PASS"
	case XDP_TX:
		return "XDP_TX"
	case XDP_REDIRECT:
		return "XDP_REDIRECT"
	default:
		return fmt.Sprintf("XDP_UNKNOWN_%d", a)
	}
}
