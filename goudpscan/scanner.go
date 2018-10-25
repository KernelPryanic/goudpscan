package goudpscan

import (
	"fmt"
	"github.com/FromZeus/goudpscan/internal/iana"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var payload = map[uint16]string{
	7:  `\x0D\x0A\x0D\x0A`,
	19: `\x63\x68\x61\x72\x67\x65\x6e`,
	53: `\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00`,
	80: `\r12345678Q999\x00`,
	111: `\x72\xFE\x1D\x13\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xA0
          \x00\x01\x97\x7C\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
          \x00\x00\x00\x00\x00\x00\x00\x00`,
	123: `\xE3\x00\x04\xFA\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00
          \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
          \x00\x00\x00\x00\x00\x00\x00\x00\xC5\x4F\x23\x4B\x71\xB1\x52\xF3`,
	137: `\x80\xF0\x00\x10\x00\x01\x00\x00\x00\x00\x00\x00
          \x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01`,
	161: `\x30\x3A\x02\x01\x03\x30\x0F\x02\x02\x4A\x69\x02\x03\x00\xFF\xE3
          \x04\x01\x04\x02\x01\x03\x04\x10\x30\x0E\x04\x00\x02\x01\x00\x02
          \x01\x00\x04\x00\x04\x00\x04\x00\x30\x12\x04\x00\x04\x00\xA0\x0C
          \x02\x02\x37\xF0\x02\x01\x00\x02\x01\x00\x30\x00`,
	177: `\x00\x01\x00\x02\x00\x01\x00`,
	389: `\x30\x84\x00\x00\x00\x2d\x02\x01\x07\x63\x84\x00\x00\x00\x24\x04
          \x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x64\x01\x01\x00
          \x87\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x30\x84\x00
          \x00\x00\x00`,
	427: `\x02\x01\x00\x006 \x00\x00\x00\x00\x00\x01\x00\x02en\x00\x00\x00
          \x15service:service-agent\x00\x07default\x00\x00\x00\x00`,
	520: `\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
          \x00\x00\x00\x00\x00\x00\x00\x10`,
	623: `\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x09\x20\x18
          \xc8\x81\x00\x38\x8e\x04\xb5`,
	1194: `8d\xc1x\x01\xb8\x9b\xcb\x8f\0\0\0\0\0`,
	1604: `\x1e\x00\x01\x30\x02\xfd\xa8\xe3\x00\x00\x00\x00\x00\x00\x00\x00
           \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`,
	1645: `\x01\x00\x00\x14
           \x00\x00\x00\x00\x00\x00\x00\x00
           \x00\x00\x00\x00\x00\x00\x00\x00`,
	1812: `\x01\x00\x00\x14
           \x00\x00\x00\x00\x00\x00\x00\x00
           \x00\x00\x00\x00\x00\x00\x00\x00`,
	2049: `\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x01\x86\xA3
           \x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
           \x00\x00\x00\x00\x00\x00\x00\x00`,
	2302: `\x00\x02\xf1\x26\x01\x26\xf0\x90\xa6\xf0\x26\x57\x4e
           \xac\xa0\xec\xf8\x68\xe4\x8d\x21`,
	3283: `\0\x14\0\x01\x03`,
	5351: `\x00\x00`,
	5353: `\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00
           \x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0C\x00\x01`,
	17185: `\x00\x00\x00\x00`,
	27910: `\xff\xff\xff\xffstatus`,
	27911: `\xff\xff\xff\xffstatus`,
	27912: `\xff\xff\xff\xffstatus`,
	27913: `\xff\xff\xff\xffstatus`,
	27914: `\xff\xff\xff\xffstatus`,
	64738: `\x00\x00\x00\x00abcdefgh`,
	3784: `\x01\xe7\xe5\x75\x31\xa3\x17\x0b\x21\xcf\xbf\x2b\x99\x4e\xdd\x19
           \xac\xde\x08\x5f\x8b\x24\x0a\x11\x19\xb6\x73\x6f\xad\x28\x13\xd2
           \x0a\xb9\x12\x75`,
	8767: `\xf4\xbe\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00
           \x002x\xba\x85\tTeamSpeak\x00\x00\x00\x00\x00\x00\x00\x00\x00
           \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\nWindows XP\x00\x00
           \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
           \x00\x02\x00\x00\x00 \x00<\x00\x00\x01\x00\x00\x00\x00\x00\x00
           \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
           \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
           \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00
           \x00\x00\x00\x00\x00\x00\x08nickname\x00\x00\x00\x00\x00\x00\x00
           \x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00`,
	9987: `\x05\xca\x7f\x16\x9c\x11\xf9\x89\x00\x00\x00\x00\x02\x9d\x74\x8b
           \x45\xaa\x7b\xef\xb9\x9e\xfe\xad\x08\x19\xba\xcf\x41\xe0\x16\xa2
           \x32\x6c\xf3\xcf\xf4\x8e\x3c\x44\x83\xc8\x8d\x51\x45\x6f\x90\x95
           \x23\x3e\x00\x97\x2b\x1c\x71\xb2\x4e\xc0\x61\xf1\xd7\x6f\xc5\x7e
           \xf6\x48\x52\xbf\x82\x6a\xa2\x3b\x65\xaa\x18\x7a\x17\x38\xc3\x81
           \x27\xc3\x47\xfc\xa7\x35\xba\xfc\x0f\x9d\x9d\x72\x24\x9d\xfc\x02
           \x17\x6d\x6b\xb1\x2d\x72\xc6\xe3\x17\x1c\x95\xd9\x69\x99\x57\xce
           \xdd\xdf\x05\xdc\x03\x94\x56\x04\x3a\x14\xe5\xad\x9a\x2b\x14\x30
           \x3a\x23\xa3\x25\xad\xe8\xe6\x39\x8a\x85\x2a\xc6\xdf\xe5\x5d\x2d
           \xa0\x2f\x5d\x9c\xd7\x2b\x24\xfb\xb0\x9c\xc2\xba\x89\xb4\x1b\x17
		   \xa2\xb6`,
}

type scanner struct {
	hosts []string
	ports []string
	opts  *Options
}

func New(
	hosts []string,
	ports []string,
	opts *Options,
) scanner {
	s := scanner{hosts, ports, opts}
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

func BreakUPIP(segments []string) []string {
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
			panic(fmt.Errorf(
				"Error in breaking up ip ranges: %s",
				err,
			))
		}
		end, err := strconv.Atoi(_end)
		if err != nil {
			panic(fmt.Errorf(
				"Error in breaking up ip ranges: %s",
				err,
			))
		}

		for i := start; i <= end; i++ {
			tails = append(tails,
				BreakUPIP(
					append(
						[]string{strconv.Itoa(i)}, segments[idx+1:]...,
					),
				)...,
			)
		}
		for _, el := range tails {
			subnets = append(subnets, head+el)
		}
	}

	if len(subnets) == 0 {
		subnets = append(subnets, head)
	}

	return subnets
}

func ParseSubnet(subnet string) []string {
	segments := Segmentation(subnet)
	subnets := []string{}

	if strings.Contains(subnet, "/") {
		subnets = BreakUPIP(segments[:len(segments)-1])
		for i := 0; i < len(subnets); i++ {
			subnets[i] = subnets[i] + "/" + segments[len(segments)-1]
		}
	} else {
		subnets = BreakUPIP(segments)
	}

	return subnets
}

func BreakUPPort(port_range string) []uint16 {
	ports := []uint16{}

	splitted := strings.Split(port_range, "-")
	_start, _end := splitted[0], splitted[1]

	start64, err := strconv.ParseUint(_start, 10, 16)
	if err != nil {
		panic(fmt.Errorf(
			"Error in breaking up port ranges: %s",
			err,
		))
	}
	start := uint16(start64)

	end64, err := strconv.ParseUint(_end, 10, 16)
	if err != nil {
		panic(fmt.Errorf(
			"Error in breaking up port ranges: %s",
			err,
		))
	}
	end := uint16(end64)

	for i := start; i <= end && i != 0; i++ {
		ports = append(ports, i)
	}

	return ports
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

func SendRequests(ip string,
	ports *[]uint16,
	opts *Options,
	wg *sync.WaitGroup,
	throttle chan int,
) {
	defer wg.Done()
	pld := ""
	var subwg sync.WaitGroup
	subwg.Add(len(*ports))

	throttleLocal := make(chan int, 1)

	for _, port := range *ports {
		for i := uint8(0); i <= opts.recheck; i++ {
			throttle <- 1
			if val, ok := payload[port]; ok {
				pld = val
			}
			conn, err := net.Dial("udp", fmt.Sprintf("%v:%v", ip, port))
			if err != nil {
				panic(fmt.Errorf(
					"Error while connecting: %s",
					err,
				))
			}
			defer conn.Close()

			conn.Write([]byte(pld))
			if !opts.fast {
				throttleLocal <- 1
			}
			go waitResponse(conn, ip, port, opts, &subwg, throttle, throttleLocal)
			if !opts.fast {
				writeCurrentPortAsync(ip, port)
			}
		}
	}
	subwg.Wait()
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
	ch := make(chan bool, 1)
	go readResponse(conn, opts, ch)

	response := <-ch
	if response {
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

func readResponse(conn net.Conn, opts *Options, ch chan bool) {
	defer close(ch)
	defer conn.Close()
	buffer := make([]byte, 1024)
	conn.SetReadDeadline(time.Now().Add(time.Duration(opts.timeout) * time.Second))
	_, err := conn.Read(buffer)
	if err != nil {
		ch <- false
	}
	conn = nil
	ch <- true
}

func SniffICMP(ch chan bool, wg *sync.WaitGroup) {
	defer wg.Done()
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		panic(fmt.Errorf(
			"Can't open icmp socket to listen on: %s",
			err,
		))
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
			panic(fmt.Errorf(
				"Something wrong with reading from icmp socket: %s",
				err,
			))
		}
		rm, err := icmp.ParseMessage(iana.ProtocolICMP, rb[:n])
		if err != nil {
			panic(fmt.Errorf(
				"Something wrong with parsing icmp response: %s",
				err,
			))
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
}

func (s scanner) Scan(ch chan bool) map[string]string {
	throttle := make(chan int, s.opts.maxConcurrency)
	subnets := []string{}

	for _, host := range s.hosts {
		subnets = append(subnets, ParseSubnet(host)...)
	}

	ports := []uint16{}

	for _, port := range s.ports {
		if strings.Contains(port, "-") {
			ports = append(ports, BreakUPPort(port)...)
		} else {
			port64, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				panic(fmt.Errorf(
					"Error in parsing up port: %s",
					err,
				))
			}
			ports = append(ports, uint16(port64))
		}
	}

	var wg sync.WaitGroup
	wg.Add(len(subnets))
	for _, subnet := range subnets {
		go func(subnet string, wg *sync.WaitGroup) {
			defer wg.Done()
			ips, err := Hosts(subnet)
			if err != nil {
				panic(fmt.Errorf(
					"Error in ip generating: %s",
					err,
				))
			}

			var wgLocal sync.WaitGroup
			wgLocal.Add(len(ips))
			for _, ip := range ips {
				go SendRequests(ip, &ports, s.opts, &wgLocal, throttle)
			}
			wgLocal.Wait()
		}(subnet, &wg)
	}
	wg.Wait()
	if !s.opts.fast {
		ch <- true
	}

	return scanData
}
