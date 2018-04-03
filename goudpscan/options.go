package goudpscan

type Options struct {
	fast           bool
	timeout        uint
	recheck        uint8
	maxConcurrency int
}

func NewOptions(
	fast bool,
	timeout uint,
	recheck uint8,
	maxConcurrency int,
) Options {
	o := Options{fast, timeout, recheck, maxConcurrency}
	return o
}
