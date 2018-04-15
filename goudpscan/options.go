package goudpscan

type Options struct {
	fast           bool
	timeout        uint
	recheck        uint8
	maxConcurrency int
	iface          string
}

func NewOptions(
	fast bool,
	timeout uint,
	recheck uint8,
	maxConcurrency int,
	iface string,
) Options {
	o := Options{fast, timeout, recheck, maxConcurrency, iface}
	return o
}
