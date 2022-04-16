package main

import (
	"embed"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KernelPryanic/goudpscan/goudpscan"
	"github.com/mcuadros/go-version"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v3"
)

var (
	print = kingpin.Flag(
		"print",
		"Print payloads.",
	).Default("false").Bool()
	payloads = kingpin.Flag(
		"payloads",
		"Paylaods yml config file.",
	).Short('l').String()
	fast = kingpin.Flag(
		"fast",
		"Fast scan mode. Only \"Open\" or \"Unknown\" statuses.",
	).Default("false").Short('f').Bool()
	timeout = kingpin.Flag(
		"timeout",
		"Timeout. Time to wait for response in seconds.",
	).Default("1").Short('t').Uint()
	recheck = kingpin.Flag(
		"recheck",
		"Recheck. How many times to check every port.",
	).Default("0").Short('r').Uint8()
	maxConcurrency = kingpin.Flag(
		"maxConcurrency",
		"Maximum concurrency. Number of concurrent requests.",
	).Default("768").Short('c').Int()
	sort = kingpin.Flag(
		"sort",
		"Sort results.",
	).Default("false").Short('s').Bool()
	ports = kingpin.Flag(
		"ports",
		"Ports to scan.",
	).Default("7-1024").Short('p').Strings()
	hosts = kingpin.Arg(
		"hosts",
		"Hosts to scan.",
	).Default("127.0.0.1").Strings()
)

//go:embed payloads.yml
var payloadsFS embed.FS

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

func FormPayload(payloadData map[string][]string) (map[uint16][]string, error) {
	payload := map[uint16][]string{}

	for k, v := range payloadData {
		ports, err := goudpscan.BreakUPPort(k)
		if err != nil {
			return nil, fmt.Errorf("breaking up port: %w", err)
		}
		for _, p := range ports {
			for _, data := range v {
				s, _ := strconv.Unquote(fmt.Sprintf(`"%s"`, strings.ReplaceAll(data, " ", "")))
				payload[p] = append(payload[p], s)
			}
		}
	}

	return payload, nil
}

func main() {
	kingpin.Parse()
	opts := goudpscan.NewOptions(*fast, *timeout, *recheck, *maxConcurrency)
	ch := make(chan bool)

	errl := log.New(os.Stdout, "ERR", log.LstdFlags)

	var payloadFile []byte
	var err error
	if *payloads == "" {
		payloadFile, err = payloadsFS.ReadFile("payloads.yml")
	} else {
		payloadFile, err = os.ReadFile(*payloads)
	}
	if err != nil {
		errl.Fatalf("reading file with payloads: %s", err)
	}
	if *print {
		fmt.Printf(string(payloadFile))
		return
	}
	payloadData := make(map[string][]string)
	if err = yaml.Unmarshal(payloadFile, &payloadData); err != nil {
		errl.Fatalf("parsing payloads file: %s", err)
	}

	var wg sync.WaitGroup
	if !*fast {
		wg.Add(1)
		go func() {
			if err := goudpscan.SniffICMP(ch, &wg); err != nil {
				errl.Printf("sniffing ICMP: %s", err)
			}
		}()
	}
	pl, err := FormPayload(payloadData)
	if err != nil {
		errl.Fatalf("forming payload: %s", err)
	}
	sc := goudpscan.New(*hosts, *ports, pl, &opts)

	start := time.Now()
	result, err := sc.Scan(errl, ch)
	if err != nil {
		errl.Fatalf("scanning: %s", err)
	}
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
