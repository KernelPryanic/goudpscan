package main

import (
	"context"
	"embed"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KernelPryanic/goudpscan/goudpscan"
	"github.com/KernelPryanic/goudpscan/unsafe"
	"github.com/mcuadros/go-version"
	"github.com/rs/zerolog"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v3"
)

var (
	cli      = kingpin.New("goudpscan", "A pretty fast UDP scanner.")
	logLevel = cli.Flag(
		"log-level",
		"Set the log level",
	).Default("info").Envar("GOUDPSCAN_LOG_LEVEL").String()
	logJson = cli.Flag(
		"log-json",
		"Output logs in JSON format.",
	).Default("false").Envar("GOUDPSCAN_JSON_LOG").Bool()
	print = cli.Flag(
		"print",
		"Print payloads.",
	).Default("false").Envar("GOUDPSCAN_PRINT").Bool()
	payloads = cli.Flag(
		"payloads",
		"Paylaods yml config file.",
	).Short('l').Envar("GOUDPSCAN_PAYLOADS").String()
	fast = cli.Flag(
		"fast",
		"Fast scan mode. Only \"Open\" or \"Unknown\" statuses.",
	).Default("false").Short('f').Envar("GOUDPSCAN_FAST").Bool()
	timeout = cli.Flag(
		"timeout",
		"Timeout. Time to wait for response in seconds.",
	).Default("1").Short('t').Envar("GOUDPSCAN_TIMEOUT").Uint()
	recheck = cli.Flag(
		"recheck",
		"Recheck. How many times to check every port.",
	).Default("0").Short('r').Envar("GOUDPSCAN_RECHECK").Uint8()
	maxConcurrency = cli.Flag(
		"max-concurrency",
		"Maximum concurrency. Number of concurrent requests.",
	).Default("768").Short('c').Envar("GOUDPSCAN_MAX_CONCURRENCY").Int()
	sort = cli.Flag(
		"sort",
		"Sort results.",
	).Default("false").Short('s').Envar("GOUDPSCAN_SORT").Bool()
	ports = cli.Flag(
		"ports",
		"Ports to scan.",
	).Default("7-1024").Short('p').Envar("GOUDPSCAN_PORTS").Strings()
	hosts = cli.Arg(
		"hosts",
		"Hosts to scan.",
	).Default("127.0.0.1").Envar("GOUDPSCAN_HOSTS").Strings()
)

//go:embed payloads.yml
var payloadsFS embed.FS

func main() {
	if _, err := cli.Parse(os.Args[1:]); err != nil {
		panic(err)
	}
	opts := goudpscan.NewOptions(*fast, *timeout, *recheck, *maxConcurrency)
	log := initLogger()

	var payloadFile []byte
	var err error
	if *payloads == "" {
		payloadFile, err = payloadsFS.ReadFile("payloads.yml")
	} else {
		payloadFile, err = os.ReadFile(*payloads)
	}
	if err != nil {
		log.Panic().Err(err).Msg("read file with payloads")
	}
	if *print {
		fmt.Println(string(payloadFile))
		return
	}

	payloadData := make(map[string][]string)
	if err = yaml.Unmarshal(payloadFile, &payloadData); err != nil {
		log.Error().Err(err).Msg("unmarshal payloads")
		return
	}
	pl, err := FormPayload(log, payloadData)
	if err != nil {
		log.Error().Err(err).Msg("form payload")
		return
	}
	sc := goudpscan.New(*hosts, *ports, pl, opts)

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	if !*fast {
		wg.Add(1)
		go func() {
			if err := sc.SniffICMP(ctx, &wg); err != nil {
				log.Error().Err(err).Msg("sniff ICMP")
			}
		}()
	}

	time.Sleep(250 * time.Millisecond)

	start := time.Now()
	result, err := sc.Scan(log)
	if err != nil {
		log.Error().Err(err).Msg("scan")
		return
	}

	// Stop the sniffer
	cancel()
	wg.Wait()

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
		hp := strings.Split(k, ":")
		log.Info().Str("host", hp[0]).Str("port", hp[1]).
			Bytes("status", result[k]).Msg("")
	}
	log.Info().Int("entities-scanned", len(result)).Msg("")
	log.Info().Dur("elapsed-time", elapsed).Msg("")
}

func FormPayload(log *zerolog.Logger, payloadData map[string][]string) (map[uint16][]string, error) {
	payload := map[uint16][]string{}

	for k, v := range payloadData {
		ports, err := goudpscan.BreakUPPort(unsafe.S2B(k))
		if err != nil {
			return nil, fmt.Errorf("break up port: %w", err)
		}
		for _, p := range ports {
			for i, data := range v {
				d := fmt.Sprintf("`%s`", strings.ReplaceAll(data, " ", ""))
				s, err := strconv.Unquote(d)
				if err != nil {
					log.Error().Err(err).Uint16("port", p).Int("payload-index", i).Str("payload", d).Msg("parse payload")
					continue
				}
				payload[p] = append(payload[p], s)
			}
		}
	}

	return payload, nil
}

func initLogger() *zerolog.Logger {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	var log zerolog.Logger
	if *logJson {
		log = zerolog.New(os.Stdout).With().Timestamp().Logger()
	} else {
		output := zerolog.ConsoleWriter{Out: os.Stdout, PartsExclude: []string{"time"}}
		log = zerolog.New(output).With().Logger()
	}

	switch *logLevel {
	case "debug":
		log = log.Level(zerolog.DebugLevel)
	case "info":
		log = log.Level(zerolog.InfoLevel)
	case "warn":
		log = log.Level(zerolog.WarnLevel)
	case "error":
		log = log.Level(zerolog.ErrorLevel)
	case "fatal":
		log = log.Level(zerolog.FatalLevel)
	case "panic":
		log = log.Level(zerolog.PanicLevel)
	default:
		log = log.Level(zerolog.InfoLevel)
	}

	return &log
}

func MergeSortAsync(arr []string, resultChan chan []string) {
	l := len(arr)
	if l <= 1 {
		resultChan <- arr
		return
	}

	m := l / 2

	lchan := make(chan []string, 1)
	rchan := make(chan []string, 1)

	if m >= 16 {
		go MergeSortAsync(arr[0:m], lchan)
		go MergeSortAsync(arr[m:l], rchan)
		go MergeAsync(<-lchan, <-rchan, resultChan)
	} else {
		MergeSortAsync(arr[0:m], lchan)
		MergeSortAsync(arr[m:l], rchan)
		MergeAsync(<-lchan, <-rchan, resultChan)
	}
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
