package goudpscan

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/KernelPryanic/goudpscan/internal/iana"
	"github.com/KernelPryanic/goudpscan/unsafe"
	"github.com/rs/zerolog"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// Scanner is a UDP scanner.
type Scanner struct {
	hosts           []string
	ports           []string
	payloads        map[uint16][]string
	opts            *Options
	scanData        map[string][]byte
	currentPort     map[string]uint16
	scanDataLock    sync.RWMutex
	currentPortLock sync.RWMutex
}

func New(
	hosts []string,
	ports []string,
	payloads map[uint16][]string,
	opts *Options,
) *Scanner {
	return &Scanner{
		hosts, ports, payloads, opts,
		map[string][]byte{}, map[string]uint16{},
		sync.RWMutex{}, sync.RWMutex{},
	}
}

func writeAsync[K comparable, V any](data map[K]V, key K, value V, lock *sync.RWMutex) {
	lock.Lock()
	defer lock.Unlock()
	data[key] = value
}

func readAsync[K comparable, V any](data map[K]V, key K, lock *sync.RWMutex) V {
	lock.RLock()
	defer lock.RUnlock()
	return data[key]
}

// Segmentation splits a subnet into segments.
func Segmentation(subnet []byte) [][]byte {
	segments := bytes.Split(subnet, []byte{'.'})
	if bytes.Contains(segments[len(segments)-1], []byte{'/'}) {
		a := bytes.Split(segments[len(segments)-1], []byte{'/'})
		segments = segments[:len(segments)-1]
		segments = append(segments, a...)
	}

	return segments
}

// BreakUpIP breaks up an IP address into subnets.
func BreakUpIP(segments [][]byte) ([][]byte, error) {
	subnets := [][]byte{}
	tails := [][]byte{}
	head := []byte{}
	idx := 0

	for {
		if bytes.Contains(segments[idx], []byte{'-'}) {
			break
		}
		if idx < len(segments)-1 {
			head = append(head, segments[idx]...)
			head = append(head, '.')
		} else {
			head = append(head, segments[idx]...)
		}
		if idx+1 == len(segments) {
			break
		}
		idx++
	}

	if bytes.Contains(segments[idx], []byte{'-'}) {
		splitted := bytes.Split(segments[idx], []byte{'-'})
		_start, _end := splitted[0], splitted[1]

		start, err := strconv.Atoi(unsafe.B2S(_start))
		if err != nil {
			return nil, fmt.Errorf("parse start segment: %w", err)
		}
		end, err := strconv.Atoi(unsafe.B2S(_end))
		if err != nil {
			return nil, fmt.Errorf("parse end segment: %w", err)
		}

		for i := start; i <= end; i++ {
			r, err := BreakUpIP(
				append(
					[][]byte{unsafe.S2B(strconv.Itoa(i))}, segments[idx+1:]...,
				),
			)
			if err != nil {
				return nil, fmt.Errorf("break up generated IP: %w", err)
			}
			tails = append(tails, r...)
		}
		for _, el := range tails {
			h := make([]byte, len(head), len(head)+len(el))
			copy(h, head)
			subnets = append(subnets, append(h, el...))
		}
	}

	if len(subnets) == 0 {
		subnets = append(subnets, head)
	}

	return subnets, nil
}

// ParseSubnet parses a subnet into subnets.
func ParseSubnet(subnet []byte) ([][]byte, error) {
	segments := Segmentation(subnet)

	if bytes.Contains(subnet, []byte{'/'}) {
		subnets, err := BreakUpIP(segments[:len(segments)-1])
		if err != nil {
			return nil, fmt.Errorf("break up IP: %w", err)
		}
		for i := 0; i < len(subnets); i++ {
			subnets[i] = append(subnets[i], '/')
			subnets[i] = append(subnets[i], segments[len(segments)-1]...)
		}
		return subnets, nil
	}

	subnets, err := BreakUpIP(segments)
	if err != nil {
		return nil, fmt.Errorf("break up IP: %w", err)
	}

	return subnets, nil
}

// BreakUPPort breaks up a port range into ports.
func BreakUPPort(portRange []byte) ([]uint16, error) {
	ports := []uint16{}

	splitted := bytes.Split(portRange, []byte{','})

	for _, s := range splitted {
		if bytes.Contains(s, []byte{'-'}) {
			splitted := bytes.Split(s, []byte{'-'})
			_start, _end := splitted[0], splitted[1]

			start64, err := strconv.ParseUint(unsafe.B2S(_start), 10, 16)
			if err != nil {
				return nil, fmt.Errorf("parse start port: %w", err)
			}
			start := uint16(start64)

			end64, err := strconv.ParseUint(unsafe.B2S(_end), 10, 16)
			if err != nil {
				return nil, fmt.Errorf("parse end port: %w", err)
			}
			end := uint16(end64)

			for i := start; i <= end && i != 0; i++ {
				ports = append(ports, i)
			}
		} else {
			port64, err := strconv.ParseUint(unsafe.B2S(s), 10, 16)
			if err != nil {
				return nil, fmt.Errorf("parse port: %w", err)
			}
			port := uint16(port64)
			ports = append(ports, port)
		}
	}

	return ports, nil
}

// Hosts returns all hosts in a CIDR.
func Hosts(cidr []byte) ([][]byte, error) {
	if !bytes.Contains(cidr, []byte{'/'}) {
		return [][]byte{cidr}, nil
	}
	ip, ipnet, err := net.ParseCIDR(unsafe.B2S(cidr))
	if err != nil {
		return nil, err
	}

	var ips [][]byte
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, unsafe.S2B(ip.String()))
	}

	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// SendRequests sends UDP requests with a dedicated payloads to the specified targets.
func (s *Scanner) SendRequests(
	log *zerolog.Logger,
	ip []byte,
	ports []uint16,
	payloads map[uint16][]string,
	opts *Options,
	wg *sync.WaitGroup,
	throttle chan struct{},
) {
	defer wg.Done()
	var plds []string
	var wgPorts sync.WaitGroup

	throttleLocal := make(chan struct{}, 1)

	for _, port := range ports {
		for i := uint8(0); i <= opts.recheck; i++ {
			if val, ok := payloads[port]; ok {
				plds = val
			} else {
				plds = []string{""}
			}

			for pi, pld := range plds {
				wgPorts.Add(1)
				throttle <- struct{}{}
				if !opts.fast {
					throttleLocal <- struct{}{}
					writeAsync(s.currentPort, unsafe.B2S(ip), port, &s.currentPortLock)
				}
				conn, err := sendRequest(ip, port, pld)
				if err != nil {
					log.Error().Err(err).Int("payload-index", pi).Bytes("ip", ip).Uint16("port", port).Msg("send payload")
					continue
				}
				go s.waitResponse(conn, ip, port, opts, &wgPorts, throttle, throttleLocal)
			}
		}
	}
	wgPorts.Wait()
}

func sendRequest(
	ip []byte,
	port uint16,
	payload string,
) (net.Conn, error) {
	conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	return conn, nil
}

func (s *Scanner) waitResponse(conn net.Conn,
	ip []byte,
	port uint16,
	opts *Options,
	wg *sync.WaitGroup,
	throttle chan struct{},
	throttleLocal chan struct{},
) {
	defer wg.Done()
	if err := readResponse(conn, opts); err == nil {
		writeAsync(s.scanData, fmt.Sprintf("%s:%d", ip, port), unsafe.S2B("open"), &s.scanDataLock)
	} else {
		status := readAsync(s.scanData, fmt.Sprintf("%s:%d", ip, port), &s.scanDataLock)
		if bytes.Equal(status, []byte{}) {
			writeAsync(s.scanData, fmt.Sprintf("%s:%d", ip, port), unsafe.S2B("unknown"), &s.scanDataLock)
		}
	}

	<-throttle
	if !opts.fast {
		<-throttleLocal
	}
}

func readResponse(conn net.Conn, opts *Options) error {
	defer conn.Close()
	buffer := make([]byte, 1024)
	if err := conn.SetReadDeadline(
		time.Now().Add(time.Duration(opts.timeout) * time.Second),
	); err != nil {
		return err
	}
	if _, err := conn.Read(buffer); err != nil {
		return err
	}
	return nil
}

// SniffICMP listens for ICMP packets and writes the results to the scanData map.
func (s *Scanner) SniffICMP(ctx context.Context, wg *sync.WaitGroup) error {
	defer wg.Done()
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("open ICMP socket: %w", err)
	}
	defer conn.Close()

	go func() {
		<-ctx.Done()
		if err := conn.Close(); err != nil {
			panic(fmt.Errorf(
				"close ICMP socket: %s",
				err,
			))
		}
	}()

	for {
		rb := make([]byte, 65565)
		n, peer, err := conn.ReadFrom(rb)

		if err != nil {
			if netOpError, ok := err.(*net.OpError); ok &&
				netOpError.Err.Error() == "use of closed network connection" {
				break
			}
			return fmt.Errorf("read from ICMP socket: %w", err)
		}
		rm, err := icmp.ParseMessage(iana.ProtocolICMP, rb[:n])
		if err != nil {
			return fmt.Errorf("parse ICMP response: %w", err)
		}

		port := readAsync(s.currentPort, peer.String(), &s.currentPortLock)
		if port == 0 {
			continue
		}
		status := readAsync(s.scanData, fmt.Sprintf("%v:%d", peer.String(), port), &s.scanDataLock)
		if rm.Type == ipv4.ICMPTypeDestinationUnreachable && rm.Code == 3 {
			if !bytes.Equal(status, unsafe.S2B("open")) {
				writeAsync(s.scanData, fmt.Sprintf("%v:%d", peer.String(), port), unsafe.S2B("closed"), &s.scanDataLock)
			}
		} else {
			if bytes.Equal(status, []byte{}) || bytes.Equal(status, unsafe.S2B("unknown")) {
				writeAsync(s.scanData, fmt.Sprintf("%v:%d", peer.String(), port), unsafe.S2B("filtered"), &s.scanDataLock)
			}
		}
	}
	return nil
}

// Scan scans the hosts and ports and returns the results.
func (s *Scanner) Scan(log *zerolog.Logger) (map[string][]byte, error) {
	throttle := make(chan struct{}, s.opts.maxConcurrency)
	subnets := [][]byte{}

	for _, host := range s.hosts {
		r, err := ParseSubnet(unsafe.S2B(host))
		if err != nil {
			return nil, fmt.Errorf("parse subnet: %w", err)
		}
		subnets = append(subnets, r...)
	}

	ports := []uint16{}

	for _, port := range s.ports {
		r, err := BreakUPPort(unsafe.S2B(port))
		if err != nil {
			return nil, fmt.Errorf("break up port: %w", err)
		}
		ports = append(ports, r...)
	}
	rand.Seed(time.Now().UnixNano())

	var wgSubnets sync.WaitGroup
	wgSubnets.Add(len(subnets))
	for _, subnet := range subnets {
		go func(subnet []byte, wgSubnets *sync.WaitGroup) {
			defer wgSubnets.Done()
			ips, err := Hosts(subnet)
			if err != nil {
				log.Error().Err(err).Msg("generate IP")
				return
			}

			var wgIPs sync.WaitGroup
			wgIPs.Add(len(ips))
			for _, ip := range ips {
				rand.Shuffle(len(ports), func(i, j int) { ports[i], ports[j] = ports[j], ports[i] })
				go s.SendRequests(log, ip, ports, s.payloads, s.opts, &wgIPs, throttle)
			}
			wgIPs.Wait()
		}(subnet, &wgSubnets)
	}
	wgSubnets.Wait()

	return s.scanData, nil
}
