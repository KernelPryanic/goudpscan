package main

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KernelPryanic/goudpscan/internal/unsafe"
	"github.com/KernelPryanic/goudpscan/pkg/ctxerr"
	"github.com/KernelPryanic/goudpscan/pkg/log"
	"github.com/mcuadros/go-version"
	"github.com/rs/zerolog"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v3"

	_ "embed"
)

var (
	cli         = kingpin.New("goudpscan", "A pretty fast UDP scanner.")
	optLogLevel = cli.Flag(
		"log-level",
		"Set the log level.",
	).Default("info").Envar("GOUDPSCAN_LOG_LEVEL").String()
	optLogJSON = cli.Flag(
		"log-json",
		"Output logs in JSON format.",
	).Default("false").Envar("GOUDPSCAN_JSON_LOG").Bool()
	optPrint = cli.Flag(
		"print",
		"Print payloads.",
	).Default("false").Envar("GOUDPSCAN_PRINT").Bool()
	optPayloads = cli.Flag(
		"payloads",
		"Paylaods yml config file.",
	).Short('l').Envar("GOUDPSCAN_PAYLOADS").String()
	optFast = cli.Flag(
		"fast",
		"Fast scan mode. Only \"Open\" or \"Unknown\" statuses.",
	).Default("false").Short('f').Envar("GOUDPSCAN_FAST").Bool()
	optTimeout = cli.Flag(
		"timeout",
		"Timeout. Time to wait for response in seconds.",
	).Default("2").Short('t').Envar("GOUDPSCAN_TIMEOUT").Uint()
	optRecheck = cli.Flag(
		"recheck",
		"Recheck. How many times to check every port (max 255).",
	).Default("0").Short('r').Envar("GOUDPSCAN_RECHECK").Uint8()
	optMaxConcurrency = cli.Flag(
		"max-concurrency",
		"Maximum concurrency. Number of concurrent requests.",
	).Default("768").Short('c').Envar("GOUDPSCAN_MAX_CONCURRENCY").Int()
	optSort = cli.Flag(
		"sort",
		"Sort results.",
	).Default("false").Short('s').Envar("GOUDPSCAN_SORT").Bool()
	optPorts = cli.Flag(
		"ports",
		"Ports to scan. Separated by commas and/or range: 80,443-1024",
	).Default("7-1024").Short('p').Envar("GOUDPSCAN_PORTS").Strings()
	optHosts = cli.Arg(
		"hosts",
		"Hosts to scan. Separated by spaces and/or range and/or CIDR: 127.1.0.1 127.0.0-32.0/24",
	).Default("127.0.0.1").Envar("GOUDPSCAN_HOSTS").Strings()
)

//go:embed payloads.yml
var payloads []byte

func formPayload(logger zerolog.Logger, payloadData map[string][]string) (map[uint16][]string, error) {
	payload := map[uint16][]string{}

	for k, v := range payloadData {
		ports, err := BreakUPPort(unsafe.S2B(k))
		if err != nil {
			return nil, fmt.Errorf("breaking up port: %w", err)
		}
		var tmp []string
		for i, data := range v {
			d := fmt.Sprintf("\"%s\"", strings.ReplaceAll(data, "\n", ""))
			s, err := strconv.Unquote(d)
			if err != nil {
				logger.Error().Err(err).Str("ports", k).Int("payload-index", i).Str("payload", d).Msg("parse payload")
				continue
			}
			tmp = append(tmp, s)
		}
		for _, p := range ports {
			payload[p] = tmp
		}
	}

	return payload, nil
}

func errorHandler(logger zerolog.Logger, ctx context.Context, errorsCh <-chan error) {
	for {
		select {
		case err := <-errorsCh:
			logger.Error().Ctx(ctxerr.Ctx(ctx, err)).Msg("error")
		case <-ctx.Done():
			return
		}
	}
}

func main() {
	if _, err := cli.Parse(os.Args[1:]); err != nil {
		panic(err)
	}
	opts := NewOptions(*optFast, *optTimeout, *optRecheck, *optMaxConcurrency)
	logger := log.New(!*optLogJSON, os.Stdout)
	log.SetLogLevel(*optLogLevel)

	if *optPrint {
		fmt.Println(string(payloads))
		return
	}

	payloadData := make(map[string][]string)
	if err := yaml.Unmarshal(payloads, &payloadData); err != nil {
		logger.Error().Err(err).Msg("unmarshal payloads")
		return
	}
	pl, err := formPayload(logger, payloadData)
	if err != nil {
		logger.Error().Err(err).Msg("form payload")
		return
	}
	sc := New(opts, *optHosts, *optPorts, pl)

	ctx, cancelSniffer := context.WithCancel(context.Background())
	var snifferWG sync.WaitGroup
	if !*optFast {
		snifferWG.Add(1)
		go func() {
			if err := sc.SniffICMP(ctx, &snifferWG); err != nil {
				logger.Error().Err(err).Msg("sniff ICMP")
			}
		}()
	}

	time.Sleep(250 * time.Millisecond)

	errorsCh := make(chan error, 8)
	ctx, cancelErrHandler := context.WithCancel(context.Background())
	go errorHandler(logger, ctx, errorsCh)

	start := time.Now()
	result := sc.Scan(errorsCh, start.UnixNano())

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
	if *optSort {
		sort.Slice(keys, func(i, j int) bool {
			if version.CompareSimple(keys[i], keys[j]) == 1 {
				return false
			}
			return true
		})
	}
	elapsed := time.Since(start)
	for _, k := range keys {
		hp := strings.Split(k, ":")
		logger.Info().Str("host", hp[0]).Str("port", hp[1]).
			Bytes("status", result[k]).Msg("")
	}
	logger.Info().Int("entities-scanned", len(result)).Msg("")
	logger.Info().Dur("elapsed-time", elapsed).Msg("")
}
