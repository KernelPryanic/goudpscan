package main

import (
	"fmt"
	"github.com/FromZeus/goudpscan/goudpscan"
	"github.com/mcuadros/go-version"
	"gopkg.in/alecthomas/kingpin.v2"
	"sync"
	"time"
)

var (
	fast = kingpin.Flag(
		"fast",
		"Fast scan mode. Only \"Open\" or \"Unknown\" statuses.",
	).Default("false").Short('f').Bool()
	timeout = kingpin.Flag(
		"timeout",
		"Timeout. How long to wait for response.",
	).Default("1").Short('t').Uint()
	recheck = kingpin.Flag(
		"recheck",
		"Recheck. How many times to check every port.",
	).Default("0").Short('r').Uint8()
	maxConcurrency = kingpin.Flag(
		"maxConcurrency",
		"Maximum concurrency. How many to scan concurrently every timeout.",
	).Default("768").Short('c').Int()
	sort = kingpin.Flag(
		"sort",
		"Sort results.",
	).Default("false").Short('s').Bool()
	ports = kingpin.Flag(
		"ports",
		"Ports to scan.",
	).Default("19").Short('p').Strings()
	hosts = kingpin.Arg(
		"hosts",
		"Hosts to scan.",
	).Required().Strings()
)

func MergeSortAsync(arr []string, resultChan chan []string) {
	l := len(arr)
	if l <= 1 {
		resultChan <- arr
		return
	}

	m := l / 2

	lchan := make(chan []string, 1)
	rchan := make(chan []string, 1)

	go MergeSortAsync(arr[0:m], lchan)
	go MergeSortAsync(arr[m:l], rchan)
	go MergeAsync(<-lchan, <-rchan, resultChan)
}

func MergeAsync(left []string, right []string, resultChannel chan []string) {
	leftLength := len(left)
	rightLength := len(right)

	if leftLength == 0 {
		resultChannel <- right
		return
	}
	if rightLength == 0 {
		resultChannel <- left
		return
	}

	result := make([]string, (leftLength + rightLength))
	li := 0
	ri := 0
	resulti := 0
	var r, l string

	for li < leftLength || ri < rightLength {
		if li < leftLength && ri < rightLength {
			l = left[li]
			r = right[ri]

			if version.CompareSimple(r, l) == 1 {
				result[resulti] = l
				li++
			} else {
				result[resulti] = r
				ri++
			}

		} else if li < leftLength {
			l = left[li]
			result[resulti] = l
			li++
		} else if ri < rightLength {
			r = right[ri]
			result[resulti] = r
			ri++
		}

		resulti++
	}

	resultChannel <- result
}

func main() {
	kingpin.Parse()
	opts := goudpscan.NewOptions(*fast, *timeout, *recheck, *maxConcurrency)
	ch := make(chan bool)

	var wg sync.WaitGroup
	if !*fast {
		wg.Add(1)
		go goudpscan.SniffICMP(ch, &wg)
	}
	sc := goudpscan.New(*hosts, *ports, &opts)

	start := time.Now()
	result := sc.Scan(ch)
	keys := make([]string, len(result))
	i := 0
	for k := range result {
		keys[i] = k
		i++
	}
	if *sort {
		resultChan := make(chan []string, 1)
		MergeSortAsync(keys, resultChan)
		keys = <-resultChan
	}
	elapsed := time.Since(start)
	for _, k := range keys {
		t := "\t"
		if len(k)/8 <= 1 {
			t = "\t\t"
		}
		fmt.Println(fmt.Sprintf("%s%s%v", k, t, result[k]))
	}
	fmt.Println("Elapsed time: ", elapsed)
	wg.Wait()
}
