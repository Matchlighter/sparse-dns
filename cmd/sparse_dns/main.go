package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	// MaxUDPBufferSize UDP buffer size
	MaxUDPBufferSize = 16 * 1024 * 1024
)

// QueuedResponse Response to an asynchronous query
type QueuedResponse struct {
	resolved *dns.Msg
	rtt      time.Duration
	err      error
}

// QueuedRequest Asynchronous DNS request
type QueuedRequest struct {
	ts           time.Time
	req          *dns.Msg
	responseChan chan QueuedResponse
}

var (
	address            = flag.String("listen", ":53", "Address to listen to (TCP and UDP)")
	upstreamServersStr = flag.String("upstream", "8.8.8.8:53,8.8.4.4:53", "Comma-delimited list of upstream servers")
	upstreamServers    []string
	maxClients         = flag.Uint("maxclients", 1000, "Maximum number of simultaneous clients")
	maxRTT             = flag.Float64("maxrtt", 0.25, "Maximum mean RTT for upstream queries before marking a server as dead")
	debug              = flag.Bool("debug", false, "Debug mode")
	resolverRing       chan QueuedRequest
	globalTimeout      = 1 * time.Second
	udpClient          dns.Client
	tcpClient          dns.Client
)

func main() {
	flag.Parse()

	upstreamServers = strings.Split(*upstreamServersStr, ",") // parseUpstreamServers(*upstreamServersStr)
	resolverRing = make(chan QueuedRequest, *maxClients)
	udpClient = dns.Client{Net: "udp", DialTimeout: globalTimeout, ReadTimeout: globalTimeout, WriteTimeout: globalTimeout, SingleInflight: true}
	tcpClient = dns.Client{Net: "tcp", DialTimeout: globalTimeout, ReadTimeout: globalTimeout, WriteTimeout: globalTimeout, SingleInflight: true}

	for i := uint(0); i < *maxClients; i++ {
		go func() {
			resolverThread()
		}()
	}

	dns.HandleFunc(".", route)
	defer dns.HandleRemove(".")

	// UDP Server
	udpServer := &dns.Server{Addr: *address, Net: "udp"}
	defer udpServer.Shutdown()
	udpAddr, err := net.ResolveUDPAddr(udpServer.Net, udpServer.Addr)
	if err != nil {
		log.Fatal(err)
	}
	udpPacketConn, err := net.ListenUDP(udpServer.Net, udpAddr)
	if err != nil {
		log.Fatal(err)
	}
	udpServer.PacketConn = udpPacketConn
	udpPacketConn.SetReadBuffer(MaxUDPBufferSize)
	udpPacketConn.SetWriteBuffer(MaxUDPBufferSize)

	// TCP Server
	tcpServer := &dns.Server{Addr: *address, Net: "tcp"}
	defer tcpServer.Shutdown()
	tcpAddr, err := net.ResolveTCPAddr(tcpServer.Net, tcpServer.Addr)
	if err != nil {
		log.Fatal(err)
	}
	tcpListener, err := net.ListenTCP(tcpServer.Net, tcpAddr)
	if err != nil {
		log.Fatal(err)
	}
	tcpServer.Listener = tcpListener

	// Start Servers
	go func() {
		log.Fatal(udpServer.ActivateAndServe())
	}()
	go func() {
		log.Fatal(tcpServer.ActivateAndServe())
	}()
	fmt.Println("Ready")

	select {}
}

func getMaxPayloadSize(req *dns.Msg) uint16 {
	opt := req.IsEdns0()
	if opt == nil {
		return dns.MinMsgSize
	}
	maxPayloadSize := opt.UDPSize()
	if maxPayloadSize < dns.MinMsgSize {
		maxPayloadSize = dns.MinMsgSize
	}
	return maxPayloadSize
}

func pickUpstream(req *dns.Msg) (*string, error) {
	res := upstreamServers[0]
	return &res, nil
}

func syncResolve(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	var resolved *dns.Msg
	var rtt time.Duration
	var err error

	for _, addr := range upstreamServers {
		if *debug {
			log.Printf("Querying %v for %v\n", addr, req.Question[0].Name)
		}

		resolved, rtt, err = udpClient.Exchange(req, addr)
		if err != nil || (resolved != nil && resolved.Truncated) {
			resolved, rtt, err = tcpClient.Exchange(req, addr)
		}
		if (dns.RcodeToString[resolved.Rcode] != "NOERROR") {
			continue
		}
		if err == nil {
			break
		}
	}

	if err != nil {
		return nil, 0, err
	}

	return resolved, rtt, nil
}

func resolverThread() {
	for {
		queuedRequest := <-resolverRing
		if time.Since(queuedRequest.ts).Seconds() > *maxRTT {
			response := QueuedResponse{resolved: nil, rtt: 0, err: errors.New("Request too old")}
			queuedRequest.responseChan <- response
			close(queuedRequest.responseChan)
			continue
		}
		resolved, rtt, err := syncResolve(queuedRequest.req)
		response := QueuedResponse{resolved: resolved, rtt: rtt, err: err}
		queuedRequest.responseChan <- response
		close(queuedRequest.responseChan)
	}
}

func resolveViaResolverThreads(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	responseChan := make(chan QueuedResponse)
	queuedRequest := QueuedRequest{ts: time.Now(), req: req, responseChan: responseChan}
	for queued := false; queued == false; {
		select {
		case resolverRing <- queuedRequest:
			queued = true
		default:
			old := <-resolverRing
			evictedResponse := QueuedResponse{resolved: nil, rtt: 0, err: errors.New("Evicted")}
			old.responseChan <- evictedResponse
		}
	}
	response := <-responseChan
	if response.err != nil {
		return nil, response.rtt, response.err
	}
	return response.resolved, response.rtt, nil
}

func resolve(req *dns.Msg) (*dns.Msg, error) {
	extra2 := []dns.RR{}
	for _, extra := range req.Extra {
		if extra.Header().Rrtype != dns.TypeOPT {
			extra2 = append(extra2, extra)
		}
	}

	dnssec := false
	for _, extra := range req.Extra {
		if extra.Header().Rrtype == dns.TypeOPT {
			dnssec = extra.(*dns.OPT).Do()
		}
	}

	req.Extra = extra2
	req.SetEdns0(dns.DefaultMsgSize, dnssec)
	resolved, _, err := resolveViaResolverThreads(req)
	if err != nil {
		return nil, err
	}
	resolved.Compress = true
	return resolved, nil
}

func sendTruncated(w dns.ResponseWriter, msgHdr dns.MsgHdr) {
	emptyResp := new(dns.Msg)
	emptyResp.MsgHdr = msgHdr
	emptyResp.Response = true
	if _, isTCP := w.RemoteAddr().(*net.TCPAddr); isTCP {
		dns.HandleFailed(w, emptyResp)
		return
	}
	emptyResp.Truncated = true
	w.WriteMsg(emptyResp)
}

func route(w dns.ResponseWriter, req *dns.Msg) {
	maxPayloadSize := getMaxPayloadSize(req)

	resp, err := resolve(req)
	if err != nil {
		w.Close()
		return
	}

	packed, _ := resp.Pack()
	packedLen := len(packed)
	if uint16(packedLen) > maxPayloadSize {
		sendTruncated(w, resp.MsgHdr)
	} else {
		w.WriteMsg(resp)
	}
}
