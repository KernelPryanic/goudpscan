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
	"github.com/mcuadros/go-version"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
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
	cli.Parse(os.Args[1:])
	opts := goudpscan.NewOptions(*fast, *timeout, *recheck, *maxConcurrency)

	initLogger()

	var payloadFile []byte
	var err error
	if *payloads == "" {
		payloadFile, err = payloadsFS.ReadFile("payloads.yml")
	} else {
		payloadFile, err = os.ReadFile(*payloads)
	}
	if err != nil {
		log.Fatal().Err(err).Msg("read file with payloads")
	}
	if *print {
		fmt.Printf(string(payloadFile))
		return
	}
	payloadData := make(map[string][]string)
	if err = yaml.Unmarshal(payloadFile, &payloadData); err != nil {
		log.Fatal().Err(err).Msg("unmarshal payloads")
	}

	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	if !*fast {
		wg.Add(1)
		go func() {
			if err := goudpscan.SniffICMP(ctx, &wg); err != nil {
				log.Error().Err(err).Msg("sniff ICMP")
			}
		}()
	}
	pl, err := FormPayload(payloadData)
	if err != nil {
		log.Fatal().Err(err).Msg("form payload")
	}
	sc := goudpscan.New(*hosts, *ports, pl, opts)

	start := time.Now()
	result, err := sc.Scan(&log.Logger)
	if err != nil {
		log.Fatal().Err(err).Msg("scan")
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
			Str("status", fmt.Sprintf("%v", result[k])).Msg("")
	}
	log.Info().Int("entities-scanned", len(result)).Msg("")
	log.Info().Dur("elapsed-time", elapsed).Msg("")
}

func initLogger() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	if *logJson {
		log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
	} else {
		output := zerolog.ConsoleWriter{Out: os.Stdout, PartsExclude: []string{"time"}}
		log.Logger = log.Output(output)
	}

	setLogLevel(*logLevel)
}

func setLogLevel(logLevel string) {
	switch logLevel {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	case "panic":
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
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
			return nil, fmt.Errorf("break up port: %w", err)
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
