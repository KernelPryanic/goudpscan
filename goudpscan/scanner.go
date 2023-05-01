package goudpscan

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KernelPryanic/goudpscan/internal/iana"
	"github.com/rs/zerolog"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type Scanner struct {
	hosts           []string
	ports           []string
	payloads        map[uint16][]string
	opts            *Options
	scanData        map[string]string
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
		map[string]string{}, map[string]uint16{},
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

func Segmentation(subnet string) []string {
	segments := strings.Split(subnet, ".")
	if strings.Contains(segments[len(segments)-1], "/") {
		a := strings.Split(segments[len(segments)-1], "/")
		segments = segments[:len(segments)-1]
		segments = append(segments, a...)
	}

	return segments
}

func BreakUpIP(segments []string) ([]string, error) {
	subnets := []string{}
	tails := []string{}
	head := ""
	idx := 0

	for {
		if strings.Contains(segments[idx], "-") {
			break
		}
		if idx < len(segments)-1 {
			head += segments[idx] + "."
		} else {
			head += segments[idx]
		}
		if idx+1 == len(segments) {
			break
		}
		idx++
	}

	if strings.Contains(segments[idx], "-") {
		splitted := strings.Split(segments[idx], "-")
		_start, _end := splitted[0], splitted[1]

		start, err := strconv.Atoi(_start)
		if err != nil {
			return nil, fmt.Errorf("parse start segment: %w", err)
		}
		end, err := strconv.Atoi(_end)
		if err != nil {
			return nil, fmt.Errorf("parse end segment: %w", err)
		}

		for i := start; i <= end; i++ {
			r, err := BreakUpIP(
				append(
					[]string{strconv.Itoa(i)}, segments[idx+1:]...,
				),
			)
			if err != nil {
				return nil, fmt.Errorf("break up generated IP: %w", err)
			}
			tails = append(tails, r...)
		}
		for _, el := range tails {
			subnets = append(subnets, head+el)
		}
	}

	if len(subnets) == 0 {
		subnets = append(subnets, head)
	}

	return subnets, nil
}

func ParseSubnet(subnet string) ([]string, error) {
	segments := Segmentation(subnet)

	if strings.Contains(subnet, "/") {
		subnets, err := BreakUpIP(segments[:len(segments)-1])
		if err != nil {
			return nil, fmt.Errorf("break up IP: %w", err)
		}
		for i := 0; i < len(subnets); i++ {
			subnets[i] = subnets[i] + "/" + segments[len(segments)-1]
		}
		return subnets, nil
	}

	subnets, err := BreakUpIP(segments)
	if err != nil {
		return nil, fmt.Errorf("break up IP: %w", err)
	}

	return subnets, nil
}

func BreakUPPort(portRange string) ([]uint16, error) {
	ports := []uint16{}

	splitted := strings.Split(portRange, ",")

	for _, s := range splitted {
		if strings.Contains(s, "-") {
			splitted := strings.Split(s, "-")
			_start, _end := splitted[0], splitted[1]

			start64, err := strconv.ParseUint(_start, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("parse start port: %w", err)
			}
			start := uint16(start64)

			end64, err := strconv.ParseUint(_end, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("parse end port: %w", err)
			}
			end := uint16(end64)

			for i := start; i <= end && i != 0; i++ {
				ports = append(ports, i)
			}
		} else {
			port64, err := strconv.ParseUint(s, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("parse port: %w", err)
			}
			port := uint16(port64)
			ports = append(ports, port)
		}
	}

	return ports, nil
}

func Hosts(cidr string) ([]string, error) {
	if !strings.Contains(cidr, "/") {
		return []string{cidr}, nil
	}
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
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

func (s *Scanner) SendRequests(
	log *zerolog.Logger,
	ip string,
	ports []uint16,
	payloads map[uint16][]string,
	opts *Options,
	wg *sync.WaitGroup,
	throttle chan int,
) {
	defer wg.Done()
	var plds []string
	var wgPorts sync.WaitGroup

	throttleLocal := make(chan int, 1)

	for _, port := range ports {
		for i := uint8(0); i <= opts.recheck; i++ {
			if val, ok := payloads[port]; ok {
				plds = val
			} else {
				plds = []string{""}
			}

			for pi, pld := range plds {
				wgPorts.Add(1)
				throttle <- 1
				if !opts.fast {
					throttleLocal <- 1
				}
				conn, err := sendRequest(ip, port, pld)
				if err != nil {
					log.Error().Err(err).Int("payload-index", pi).Str("ip", ip).Uint16("port", port).Msg("send payload")
					continue
				}
				go s.waitResponse(conn, ip, port, opts, &wgPorts, throttle, throttleLocal)
				if !opts.fast {
					writeAsync(s.currentPort, ip, port, &s.currentPortLock)
				}
			}
		}
	}
	wgPorts.Wait()
}

func sendRequest(
	ip string,
	port uint16,
	payload string,
) (net.Conn, error) {
	conn, err := net.Dial("udp", fmt.Sprintf("%v:%v", ip, port))
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		return nil, fmt.Errorf("write: %w", err)
	}
	return conn, nil
}

func (s *Scanner) waitResponse(conn net.Conn,
	ip string,
	port uint16,
	opts *Options,
	wg *sync.WaitGroup,
	throttle chan int,
	throttleLocal chan int,
) {
	defer wg.Done()
	if err := readResponse(conn, opts); err == nil {
		writeAsync(s.scanData, fmt.Sprintf("%v:%v", ip, port), "Open", &s.scanDataLock)
	} else {
		status := readAsync(s.scanData, fmt.Sprintf("%v:%v", ip, port), &s.scanDataLock)
		if status == "" {
			writeAsync(s.scanData, fmt.Sprintf("%v:%v", ip, port), "Unknown", &s.scanDataLock)
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
		status := readAsync(s.scanData, fmt.Sprintf("%v:%v", peer.String(), port), &s.scanDataLock)
		if rm.Type == ipv4.ICMPTypeDestinationUnreachable && rm.Code == 3 {
			if status != "Open" {
				writeAsync(s.scanData, fmt.Sprintf("%v:%v", peer.String(), port), "Closed", &s.scanDataLock)
			}
		} else {
			if status == "" || status == "Unknown" {
				writeAsync(s.scanData, fmt.Sprintf("%v:%v", peer.String(), port), "Filtered", &s.scanDataLock)
			}
		}
	}
	return nil
}

func (s *Scanner) Scan(log *zerolog.Logger) (map[string]string, error) {
	throttle := make(chan int, s.opts.maxConcurrency)
	subnets := []string{}

	for _, host := range s.hosts {
		r, err := ParseSubnet(host)
		if err != nil {
			return nil, fmt.Errorf("parse subnet: %w", err)
		}
		subnets = append(subnets, r...)
	}

	ports := []uint16{}

	for _, port := range s.ports {
		r, err := BreakUPPort(port)
		if err != nil {
			return nil, fmt.Errorf("break up port: %w", err)
		}
		ports = append(ports, r...)
	}
	rand.Seed(time.Now().UnixNano())

	var wgSubnets sync.WaitGroup
	wgSubnets.Add(len(subnets))
	for _, subnet := range subnets {
		go func(subnet string, wgSubnets *sync.WaitGroup) {
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
