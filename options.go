package main

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
) *Options {
	return &Options{fast, timeout, recheck, maxConcurrency}
}
