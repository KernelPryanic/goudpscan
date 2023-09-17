package main

import (
	"context"
	"embed"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/KernelPryanic/goudpscan/goudpscan"
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
	).Default("2").Short('t').Envar("GOUDPSCAN_TIMEOUT").Uint()
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
	pl, err := formPayload(log, payloadData)
	if err != nil {
		log.Error().Err(err).Msg("form payload")
		return
	}
	sc := goudpscan.New(opts, *hosts, *ports, pl)

	ctx, cancelSniffer := context.WithCancel(context.Background())
	var snifferWG sync.WaitGroup
	if !*fast {
		snifferWG.Add(1)
		go func() {
			if err := sc.SniffICMP(ctx, &snifferWG); err != nil {
				log.Error().Err(err).Msg("sniff ICMP")
			}
		}()
	}

	time.Sleep(250 * time.Millisecond)

	errors := make(chan goudpscan.ScannerError, 8)
	ctx, cancelErrHandler := context.WithCancel(context.Background())
	go errorHandler(ctx, errors)

	start := time.Now()
	result := sc.Scan(errors, start.UnixNano())

	// Stop the sniffer
	cancelSniffer()
	cancelErrHandler()
	snifferWG.Wait()

	keys := make([]string, len(result))
	i := 0
	for k := range result {
		keys[i] = k
		i++
	}
	if *sort {
		resultChan := make(chan []string, 1)
		mergeSortAsync(keys, resultChan)
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
