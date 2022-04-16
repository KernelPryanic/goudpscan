package goudpscan

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KernelPryanic/goudpscan/internal/iana"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type scanner struct {
	hosts    []string
	ports    []string
	payloads map[uint16][]string
	opts     *Options
}

func New(
	hosts []string,
	ports []string,
	payloads map[uint16][]string,
	opts *Options,
) scanner {
	s := scanner{hosts, ports, payloads, opts}
	return s
}

var scanData = map[string]string{}
var currentPort = map[string]uint16{}
var lock = sync.RWMutex{}

func writeScanDataAsync(key string, value string) {
	lock.Lock()
	defer lock.Unlock()
	scanData[key] = value
}

func readScanDataAsync(key string) string {
	lock.RLock()
	defer lock.RUnlock()
	return scanData[key]
}

func writeCurrentPortAsync(key string, value uint16) {
	lock.Lock()
	defer lock.Unlock()
	currentPort[key] = value
}

func readCurrentPortAsync(key string) uint16 {
	lock.RLock()
	defer lock.RUnlock()
	return currentPort[key]
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

func BreakUPIP(segments []string) ([]string, error) {
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
			return nil, fmt.Errorf("parsing start int: %w", err)
		}
		end, err := strconv.Atoi(_end)
		if err != nil {
			return nil, fmt.Errorf("parsing end int: %w", err)
		}

		for i := start; i <= end; i++ {
			r, err := BreakUPIP(
				append(
					[]string{strconv.Itoa(i)}, segments[idx+1:]...,
				),
			)
			if err != nil {
				return nil, fmt.Errorf("breaking UPIP: %w", err)
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
		subnets, err := BreakUPIP(segments[:len(segments)-1])
		if err != nil {
			return nil, fmt.Errorf("breaking UPIP: %w", err)
		}
		for i := 0; i < len(subnets); i++ {
			subnets[i] = subnets[i] + "/" + segments[len(segments)-1]
		}
	}

	subnets, err := BreakUPIP(segments)
	if err != nil {
		return nil, fmt.Errorf("breaking UPIP: %w", err)
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
				return nil, fmt.Errorf("parsing start uint: %w", err)
			}
			start := uint16(start64)

			end64, err := strconv.ParseUint(_end, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("parsing end uint: %w", err)
			}
			end := uint16(end64)

			for i := start; i <= end && i != 0; i++ {
				ports = append(ports, i)
			}
		} else {
			port64, err := strconv.ParseUint(s, 10, 16)
			if err != nil {
				return nil, fmt.Errorf("breaking up port ranges: %w", err)
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

func SendRequests(
	errl *log.Logger,
	ip string,
	ports *[]uint16,
	payloads *map[uint16][]string,
	opts *Options,
	wg *sync.WaitGroup,
	throttle chan int,
) {
	defer wg.Done()
	var plds []string
	var wgPorts sync.WaitGroup

	throttleLocal := make(chan int, 1)

	for _, port := range *ports {
		for i := uint8(0); i <= opts.recheck; i++ {
			if val, ok := (*payloads)[port]; ok {
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
					errl.Printf(
						"sending payload %d to %s:%d: %s",
						pi, ip, port, err,
					)
					continue
				}
				go waitResponse(conn, ip, port, opts, &wgPorts, throttle, throttleLocal)
				if !opts.fast {
					writeCurrentPortAsync(ip, port)
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
		return nil, fmt.Errorf("connecting: %w", err)
	}
	if _, err := conn.Write([]byte(payload)); err != nil {
		return nil, fmt.Errorf("writing: %w", err)
	}
	return conn, nil
}

func waitResponse(conn net.Conn,
	ip string,
	port uint16,
	opts *Options,
	wg *sync.WaitGroup,
	throttle chan int,
	throttleLocal chan int,
) {
	defer wg.Done()
	if err := readResponse(conn, opts); err == nil {
		writeScanDataAsync(fmt.Sprintf("%v:%v", ip, port), "Open")
	} else {
		status := readScanDataAsync(fmt.Sprintf("%v:%v", ip, port))
		if status == "" {
			writeScanDataAsync(fmt.Sprintf("%v:%v", ip, port), "Unknown")
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

func SniffICMP(ch chan bool, wg *sync.WaitGroup) error {
	defer wg.Done()
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return fmt.Errorf("opening icmp socket: %w", err)
	}
	defer conn.Close()

	go func() {
		<-ch
		if err := conn.Close(); err != nil {
			panic(fmt.Errorf(
				"Close failed: %s",
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
			return fmt.Errorf("reading from ICMP socket: %w", err)
		}
		rm, err := icmp.ParseMessage(iana.ProtocolICMP, rb[:n])
		if err != nil {
			return fmt.Errorf("parsing ICMP response: %w", err)
		}

		port := readCurrentPortAsync(peer.String())
		status := readScanDataAsync(fmt.Sprintf("%v:%v", peer.String(), port))
		if rm.Type == ipv4.ICMPTypeDestinationUnreachable && rm.Code == 3 {
			if status != "Open" {
				writeScanDataAsync(fmt.Sprintf("%v:%v", peer.String(), port), "Closed")
			}
		} else {
			if status == "" || status == "Unknown" {
				writeScanDataAsync(fmt.Sprintf("%v:%v", peer.String(), port), "Filtered")
			}
		}
	}
	return nil
}

func (s scanner) Scan(errLog *log.Logger, ch chan bool) (map[string]string, error) {
	throttle := make(chan int, s.opts.maxConcurrency)
	subnets := []string{}

	for _, host := range s.hosts {
		r, err := ParseSubnet(host)
		if err != nil {
			return nil, fmt.Errorf("parsing subnet: %w", err)
		}
		subnets = append(subnets, r...)
	}

	ports := []uint16{}

	for _, port := range s.ports {
		r, err := BreakUPPort(port)
		if err != nil {
			return nil, fmt.Errorf("breaking up port: %w", err)
		}
		ports = append(ports, r...)
	}

	var wgSubnets sync.WaitGroup
	wgSubnets.Add(len(subnets))
	for _, subnet := range subnets {
		go func(subnet string, wgSubnets *sync.WaitGroup) {
			defer wgSubnets.Done()
			ips, err := Hosts(subnet)
			if err != nil {
				errLog.Printf("generating ip: %s", err)
				return
			}

			var wgIPs sync.WaitGroup
			wgIPs.Add(len(ips))
			for _, ip := range ips {
				go SendRequests(errLog, ip, &ports, &s.payloads, s.opts, &wgIPs, throttle)
			}
			wgIPs.Wait()
		}(subnet, &wgSubnets)
	}
	wgSubnets.Wait()
	if !s.opts.fast {
		ch <- true
	}

	return scanData, nil
}
