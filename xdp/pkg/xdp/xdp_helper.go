package xdp

const (
	XDP_ABORTED = uint32(iota)
	XDP_DROP
	XDP_PASS
	XDP_TX
	XDP_REDIRECT
)

