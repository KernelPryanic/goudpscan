package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/KernelPryanic/goudpscan/goudpscan"
	"github.com/KernelPryanic/goudpscan/unsafe"
	"github.com/mcuadros/go-version"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func formPayload(log *zerolog.Logger, payloadData map[string][]string) (map[uint16][]string, error) {
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

func mergeSortAsync(arr []string, resultChan chan []string) {
	l := len(arr)
	if l <= 1 {
		resultChan <- arr
		return
	}

	m := l / 2

	lchan := make(chan []string, 1)
	rchan := make(chan []string, 1)

	if m >= 32 {
		go mergeSortAsync(arr[0:m], lchan)
		go mergeSortAsync(arr[m:l], rchan)
		go mergeAsync(<-lchan, <-rchan, resultChan)
	} else {
		mergeSortAsync(arr[0:m], lchan)
		mergeSortAsync(arr[m:l], rchan)
		mergeAsync(<-lchan, <-rchan, resultChan)
	}
}

func mergeAsync(left []string, right []string, resultChannel chan []string) {
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

func errorHandler(ctx context.Context, errors <-chan goudpscan.ScannerError) {
	for {
		select {
		case err := <-errors:
			e := log.Error().Err(err.OrigError)
			for key, value := range err.Metadata {
				e = e.Interface(key, value)
			}
			e.Msg(err.CustomErrorMsg)
		case <-ctx.Done():
			return
		}
	}
}
