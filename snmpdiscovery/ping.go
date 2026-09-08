package snmpdiscovery

import (
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// icmpAlive returns the subset of ips that answer ICMP echo. Used to cheap-filter
// a CIDR sweep (ktranslate / LibreNMS snmp-scan). Not applied to crawl candidates.
// Dual-stack: IPv4 and IPv6 use separate sockets.
func icmpAlive(ips []string, timeout time.Duration) ([]string, error) {
	if len(ips) == 0 {
		return nil, nil
	}
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}

	var v4, v6 []string
	for _, ip := range ips {
		c, err := canonIP(ip)
		if err != nil {
			continue
		}
		parsed := net.ParseIP(c)
		if parsed == nil {
			continue
		}
		if parsed.To4() != nil {
			v4 = append(v4, c)
		} else {
			v6 = append(v6, c)
		}
	}

	alive := map[string]struct{}{}
	var mu sync.Mutex
	mark := func(ip string) {
		mu.Lock()
		alive[ip] = struct{}{}
		mu.Unlock()
	}

	if len(v4) > 0 {
		if err := pingFamily(false, v4, timeout, mark); err != nil {
			return nil, err
		}
	}
	if len(v6) > 0 {
		if err := pingFamily(true, v6, timeout, mark); err != nil {
			return nil, err
		}
	}

	out := make([]string, 0, len(alive))
	for _, ip := range ips {
		c := mustCanonIP(ip)
		mu.Lock()
		_, ok := alive[c]
		mu.Unlock()
		if ok {
			out = append(out, c)
		}
	}
	return out, nil
}

func pingFamily(v6 bool, ips []string, timeout time.Duration, mark func(string)) error {
	conn, err := listenICMP(v6)
	if err != nil {
		return err
	}
	defer conn.Close()

	want := map[string]struct{}{}
	for _, ip := range ips {
		want[ip] = struct{}{}
	}

	proto := 1
	echoType := icmp.Type(ipv4.ICMPTypeEcho)
	replyType := icmp.Type(ipv4.ICMPTypeEchoReply)
	if v6 {
		proto = 58
		echoType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
	}

	aliveLocal := map[string]struct{}{}
	var mu sync.Mutex
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 1500)
		for {
			n, peer, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			msg, err := icmp.ParseMessage(proto, buf[:n])
			if err != nil || msg.Type != replyType {
				continue
			}
			ip := peerIP(peer, v6)
			if ip == "" {
				continue
			}
			mu.Lock()
			if _, ok := want[ip]; ok {
				aliveLocal[ip] = struct{}{}
				mark(ip)
				if len(aliveLocal) == len(want) {
					_ = conn.SetReadDeadline(time.Now())
				}
			}
			mu.Unlock()
		}
	}()

	id := os.Getpid() & 0xffff
	for i, ip := range ips {
		body := &icmp.Echo{ID: id, Seq: i, Data: []byte("snmp-discovery")}
		msg := icmp.Message{Type: echoType, Code: 0, Body: body}
		wb, err := msg.Marshal(nil)
		if err != nil {
			continue
		}
		dst := net.ParseIP(ip)
		if dst == nil {
			continue
		}
		_, _ = conn.WriteTo(wb, &net.UDPAddr{IP: dst})
		_, _ = conn.WriteTo(wb, &net.IPAddr{IP: dst})
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	<-done
	return nil
}

func listenICMP(v6 bool) (*icmp.PacketConn, error) {
	if v6 {
		c, err := icmp.ListenPacket("udp6", "::")
		if err == nil {
			return c, nil
		}
		c2, err2 := icmp.ListenPacket("ip6:ipv6-icmp", "::")
		if err2 == nil {
			return c2, nil
		}
		return nil, fmt.Errorf("icmp6 listen failed (need CAP_NET_RAW or ping_group_range, or set ping: false): unprivileged: %v; privileged: %v", err, err2)
	}
	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err == nil {
		return c, nil
	}
	c2, err2 := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err2 == nil {
		return c2, nil
	}
	return nil, fmt.Errorf("icmp listen failed (need CAP_NET_RAW or ping_group_range, or set ping: false): unprivileged: %v; privileged: %v", err, err2)
}

func peerIP(peer net.Addr, wantV6 bool) string {
	var ip net.IP
	switch a := peer.(type) {
	case *net.IPAddr:
		ip = a.IP
	case *net.UDPAddr:
		ip = a.IP
	default:
		host, _, err := net.SplitHostPort(peer.String())
		if err != nil {
			host = peer.String()
		}
		ip = net.ParseIP(host)
	}
	if ip == nil {
		return ""
	}
	c, err := canonIP(ip.String())
	if err != nil {
		return ""
	}
	parsed := net.ParseIP(c)
	if parsed == nil {
		return ""
	}
	isV4 := parsed.To4() != nil
	if wantV6 && isV4 {
		return ""
	}
	if !wantV6 && !isV4 {
		return ""
	}
	return c
}
