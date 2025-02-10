package tooling

import (
	"context"
	"fmt"
	"github.com/KernelPryanic/goudpscan/goudpscan"
	"github.com/KernelPryanic/goudpscan/unsafe"
	"github.com/mcuadros/go-version"
	"github.com/rs/zerolog"
	"strconv"
	"strings"
)

func FormPayload(log *zerolog.Logger, payloadData map[string][]string) (map[uint16][]string, error) {
	payload := map[uint16][]string{}

	for k, v := range payloadData {
		ports, err := goudpscan.BreakUPPort(unsafe.S2B(k))
		if err != nil {
			return nil, fmt.Errorf("break up port: %w", err)
		}
		var tmp []string
		for i, data := range v {
			d := fmt.Sprintf("\"%s\"", strings.ReplaceAll(data, "\n", ""))
			s, err := strconv.Unquote(d)
			if err != nil {
				log.Error().Err(err).Str("port", k).Int("payload-index", i).Str("payload", d).Msg("parse payload")
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

func MergeSortAsync(arr []string, resultChan chan []string) {
	l := len(arr)
	if l <= 1 {
		resultChan <- arr
		return
	}

	m := l / 2

	lchan := make(chan []string, 1)
	rchan := make(chan []string, 1)

	if m >= 32 {
		go MergeSortAsync(arr[0:m], lchan)
		go MergeSortAsync(arr[m:l], rchan)
		go mergeAsync(<-lchan, <-rchan, resultChan)
	} else {
		MergeSortAsync(arr[0:m], lchan)
		MergeSortAsync(arr[m:l], rchan)
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

func ErrorHandler(log *zerolog.Logger, ctx context.Context, errors <-chan goudpscan.ScannerError) {
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
