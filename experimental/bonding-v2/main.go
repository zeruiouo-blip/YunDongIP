package main

import (
	crand "crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

const (
	ftOpen  byte = 1
	ftData  byte = 2
	ftAck   byte = 3
	ftClose byte = 4

	headerSize     = 17
	chunkSize      = 32 * 1024
	maxPending     = 256 // 8 MiB phase-1 window; reduce cross-lane head-of-line depth
	laneQueueDepth = 1024
	defaultRTO     = 500 * time.Millisecond

	// Phase-1 aggregation deliberately relies on the reliability of each
	// WebSocket/TCP lane.  Speculative retransmission is disabled until the
	// base 1-lane -> 2-lane aggregation gate is proven.  The previous timer
	// started when a frame was queued rather than when it reached the wire,
	// so a healthy queued frame could be duplicated repeatedly and inflate
	// per-lane in-flight bytes.
	enableSpeculativeRetry = false
)

type frame struct {
	typ byte
	sid uint64
	seq uint64
	p   []byte
}

func encodeFrame(f frame) []byte {
	b := make([]byte, headerSize+len(f.p))
	b[0] = f.typ
	binary.BigEndian.PutUint64(b[1:9], f.sid)
	binary.BigEndian.PutUint64(b[9:17], f.seq)
	copy(b[17:], f.p)
	return b
}

func decodeFrame(b []byte) (frame, error) {
	if len(b) < headerSize {
		return frame{}, fmt.Errorf("short frame")
	}
	return frame{
		typ: b[0],
		sid: binary.BigEndian.Uint64(b[1:9]),
		seq: binary.BigEndian.Uint64(b[9:17]),
		p:   append([]byte(nil), b[17:]...),
	}, nil
}

type txItem struct {
	data []byte
}

type lane struct {
	id   int
	name string
	c    *websocket.Conn
	q    chan txItem

	ok         atomic.Bool
	inflight   atomic.Int64
	txBytes    atomic.Uint64
	rxBytes    atomic.Uint64
	ackedBytes atomic.Uint64
	rateBps    atomic.Uint64
}

func (l *lane) enqueue(b []byte) bool {
	if !l.ok.Load() {
		return false
	}
	l.q <- txItem{data: b}
	return true
}

func (l *lane) writer() {
	for it := range l.q {
		if !l.ok.Load() {
			return
		}
		if err := l.c.WriteMessage(websocket.BinaryMessage, it.data); err != nil {
			l.ok.Store(false)
			_ = l.c.Close()
			log.Printf("LANE DOWN %s write=%v", l.name, err)
			return
		}
		l.txBytes.Add(uint64(len(it.data)))
	}
}

type pendingPacket struct {
	seq      uint64
	payload  []byte
	lastSent time.Time
	lastLane int
	attempts map[int]int
}

type sender struct {
	h   *hub
	sid uint64

	mu      sync.Mutex
	cond    *sync.Cond
	nextSeq uint64
	pending map[uint64]*pendingPacket
	closed  bool
}

func newSender(h *hub, sid uint64) *sender {
	s := &sender{h: h, sid: sid, pending: make(map[uint64]*pendingPacket)}
	s.cond = sync.NewCond(&s.mu)
	if enableSpeculativeRetry {
		go s.retransmitLoop()
	}
	return s
}

func (s *sender) sendData(p []byte) error {
	s.mu.Lock()
	for len(s.pending) >= maxPending {
		s.cond.Wait()
	}
	seq := s.nextSeq
	s.nextSeq++
	pkt := &pendingPacket{
		seq:      seq,
		payload:  append([]byte(nil), p...),
		lastLane: -1,
		attempts: make(map[int]int),
	}
	s.pending[seq] = pkt
	s.mu.Unlock()

	return s.transmit(pkt, -1)
}

func (s *sender) transmit(pkt *pendingPacket, exclude int) error {
	l := s.h.chooseLane(exclude)
	if l == nil {
		return fmt.Errorf("no active lane")
	}

	s.mu.Lock()
	// ACK may have removed this packet while a retransmission was being selected.
	if cur := s.pending[pkt.seq]; cur != pkt {
		s.mu.Unlock()
		return nil
	}
	pkt.lastSent = time.Now()
	pkt.lastLane = l.id
	pkt.attempts[l.id]++
	s.mu.Unlock()

	payload := encodeFrame(frame{typ: ftData, sid: s.sid, seq: pkt.seq, p: pkt.payload})
	l.inflight.Add(int64(len(pkt.payload)))
	if !l.enqueue(payload) {
		l.inflight.Add(-int64(len(pkt.payload)))
		return fmt.Errorf("lane unavailable")
	}
	return nil
}

func (s *sender) ack(seq uint64) {
	s.mu.Lock()
	pkt := s.pending[seq]
	if pkt == nil {
		s.mu.Unlock()
		return
	}
	delete(s.pending, seq)
	attempts := pkt.attempts
	n := int64(len(pkt.payload))
	s.cond.Broadcast()
	s.mu.Unlock()

	for laneID, count := range attempts {
		if l := s.h.laneByID(laneID); l != nil {
			l.inflight.Add(-n * int64(count))
			l.ackedBytes.Add(uint64(n) * uint64(count))
		}
	}
}

func (s *sender) retransmitLoop() {
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for range t.C {
		s.mu.Lock()
		if s.closed && len(s.pending) == 0 {
			s.mu.Unlock()
			return
		}
		now := time.Now()
		var resend []*pendingPacket
		for _, pkt := range s.pending {
			if !pkt.lastSent.IsZero() && now.Sub(pkt.lastSent) >= defaultRTO {
				resend = append(resend, pkt)
				// Prevent repeated selection by the next tick while this retry is queued.
				pkt.lastSent = now
			}
		}
		s.mu.Unlock()

		for _, pkt := range resend {
			// Prefer another lane. If there is only one active lane, chooseLane falls back to it.
			_ = s.transmit(pkt, pkt.lastLane)
		}
	}
}

func (s *sender) finish() uint64 {
	s.mu.Lock()
	s.closed = true
	final := s.nextSeq
	s.mu.Unlock()
	return final
}

type receiver struct {
	mu sync.Mutex

	next   uint64
	buf    map[uint64][]byte
	w      io.Writer
	finSet bool
	fin    uint64
	onFin  func()
}

func newReceiver(w io.Writer, onFin func()) *receiver {
	return &receiver{buf: make(map[uint64][]byte), w: w, onFin: onFin}
}

func (r *receiver) put(seq uint64, p []byte) error {
	r.mu.Lock()
	if seq < r.next {
		r.mu.Unlock()
		return nil
	}
	if _, exists := r.buf[seq]; !exists {
		r.buf[seq] = append([]byte(nil), p...)
	}
	for {
		v, ok := r.buf[r.next]
		if !ok {
			break
		}
		if _, err := r.w.Write(v); err != nil {
			r.mu.Unlock()
			return err
		}
		delete(r.buf, r.next)
		r.next++
	}
	done := r.finSet && r.next >= r.fin && r.onFin != nil
	var fn func()
	if done {
		fn = r.onFin
		r.onFin = nil
	}
	r.mu.Unlock()
	if fn != nil {
		fn()
	}
	return nil
}

func (r *receiver) finish(final uint64) {
	r.mu.Lock()
	r.finSet = true
	r.fin = final
	done := r.next >= r.fin && r.onFin != nil
	var fn func()
	if done {
		fn = r.onFin
		r.onFin = nil
	}
	r.mu.Unlock()
	if fn != nil {
		fn()
	}
}

func newStreamID() (uint64, error) {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return 0, err
	}
	sid := binary.BigEndian.Uint64(b[:])
	if sid == 0 {
		sid = 1
	}
	return sid, nil
}

func closeWrite(c net.Conn) {
	if x, ok := c.(interface{ CloseWrite() error }); ok {
		_ = x.CloseWrite()
	} else {
		_ = c.Close()
	}
}

type stream struct {
	conn net.Conn
	send *sender
	recv *receiver
}

type hub struct {
	mu sync.RWMutex

	lanes   []*lane
	streams map[uint64]*stream
	target  string
	nextID  int
}

func newHub(target string) *hub {
	h := &hub{streams: make(map[uint64]*stream), target: target}
	go h.statsLoop()
	go h.rateLoop()
	return h
}

func (h *hub) addLane(name string, c *websocket.Conn) *lane {
	h.mu.Lock()
	id := h.nextID
	h.nextID++
	l := &lane{id: id, name: name, c: c, q: make(chan txItem, laneQueueDepth)}
	l.ok.Store(true)
	h.lanes = append(h.lanes, l)
	h.mu.Unlock()
	go l.writer()
	return l
}

func (h *hub) laneByID(id int) *lane {
	h.mu.RLock()
	defer h.mu.RUnlock()
	for _, l := range h.lanes {
		if l.id == id {
			return l
		}
	}
	return nil
}

func (h *hub) activeCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	n := 0
	for _, l := range h.lanes {
		if l.ok.Load() {
			n++
		}
	}
	return n
}

func (h *hub) chooseLane(exclude int) *lane {
	h.mu.RLock()
	defer h.mu.RUnlock()

	var best *lane
	var bestScore int64
	for _, l := range h.lanes {
		if !l.ok.Load() || l.id == exclude {
			continue
		}
		inflight := l.inflight.Load()
		if inflight < 0 {
			inflight = 0
		}
		rate := l.rateBps.Load()
		if rate == 0 {
			rate = 8 * 1024 * 1024 // neutral startup estimate: 8 MiB/s
		}
		// Estimated queue drain time. Faster lanes are allowed to carry a
		// proportionally larger in-flight window instead of forcing every
		// lane to the same byte backlog.
		score := inflight * 1000000000 / int64(rate)
		if best == nil || score < bestScore {
			best = l
			bestScore = score
		}
	}
	if best != nil {
		return best
	}

	// One-lane fallback, or all other lanes are down.
	for _, l := range h.lanes {
		if l.ok.Load() {
			return l
		}
	}
	return nil
}

func (h *hub) sendControl(f frame) error {
	l := h.chooseLane(-1)
	if l == nil {
		return fmt.Errorf("no active lanes")
	}
	if !l.enqueue(encodeFrame(f)) {
		return fmt.Errorf("control lane unavailable")
	}
	return nil
}

func (h *hub) sendAckOn(l *lane, sid, seq uint64) {
	if l == nil || !l.ok.Load() {
		l = h.chooseLane(-1)
	}
	if l == nil {
		return
	}
	_ = l.enqueue(encodeFrame(frame{typ: ftAck, sid: sid, seq: seq}))
}

func (h *hub) addStream(sid uint64, c net.Conn) *stream {
	st := &stream{conn: c}
	st.send = newSender(h, sid)
	st.recv = newReceiver(c, func() { closeWrite(c) })
	h.mu.Lock()
	h.streams[sid] = st
	h.mu.Unlock()
	return st
}

func (h *hub) getStream(sid uint64) *stream {
	h.mu.RLock()
	st := h.streams[sid]
	h.mu.RUnlock()
	return st
}

func (h *hub) ensureServerStream(sid uint64) *stream {
	if st := h.getStream(sid); st != nil {
		return st
	}
	log.Printf("STREAM OPEN sid=%d dialing target=%s", sid, h.target)

	c, err := net.DialTimeout("tcp", h.target, 8*time.Second)
	if err != nil {
		log.Printf("STREAM %d target dial failed: %v", sid, err)
		_ = h.sendControl(frame{typ: ftClose, sid: sid, seq: 0})
		return nil
	}
	candidate := &stream{conn: c}
	candidate.send = newSender(h, sid)
	candidate.recv = newReceiver(c, func() { closeWrite(c) })

	h.mu.Lock()
	if old := h.streams[sid]; old != nil {
		h.mu.Unlock()
		_ = c.Close()
		return old
	}
	h.streams[sid] = candidate
	h.mu.Unlock()
	log.Printf("STREAM READY sid=%d target=%s", sid, h.target)

	go h.pumpConnToTunnel(sid, candidate)
	return candidate
}

func (h *hub) handleFrame(src *lane, f frame) {
	switch f.typ {
	case ftOpen:
		if h.target != "" {
			h.ensureServerStream(f.sid)
		}
	case ftData:
		st := h.getStream(f.sid)
		if st == nil && h.target != "" {
			st = h.ensureServerStream(f.sid)
		}
		if st == nil {
			return
		}
		// ACK as soon as this endpoint owns a copy; delivery can still wait for order.
		h.sendAckOn(src, f.sid, f.seq)
		if err := st.recv.put(f.seq, f.p); err != nil {
			log.Printf("STREAM %d receiver write failed: %v", f.sid, err)
		}
	case ftAck:
		if st := h.getStream(f.sid); st != nil {
			st.send.ack(f.seq)
		}
	case ftClose:
		if st := h.getStream(f.sid); st != nil {
			st.recv.finish(f.seq)
		}
	}
}

func (h *hub) readLane(l *lane) {
	defer func() {
		l.ok.Store(false)
		_ = l.c.Close()
		log.Printf("LANE DOWN %s read", l.name)
	}()
	for {
		_, b, err := l.c.ReadMessage()
		if err != nil {
			return
		}
		l.rxBytes.Add(uint64(len(b)))
		f, err := decodeFrame(b)
		if err != nil {
			continue
		}
		h.handleFrame(l, f)
	}
}

func (h *hub) pumpConnToTunnel(sid uint64, st *stream) {
	b := make([]byte, chunkSize)
	first := true
	for {
		n, err := st.conn.Read(b)
		if n > 0 {
			if first {
				log.Printf("STREAM FIRST-READ sid=%d bytes=%d", sid, n)
				first = false
			}
			if e := st.send.sendData(b[:n]); e != nil {
				log.Printf("STREAM %d send failed: %v", sid, e)
				break
			}
		}
		if err != nil {
			final := st.send.finish()
			_ = h.sendControl(frame{typ: ftClose, sid: sid, seq: final})
			return
		}
	}
}

func (h *hub) rateLoop() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
	prev := make(map[int]uint64)
	for range t.C {
		h.mu.RLock()
		lanes := append([]*lane(nil), h.lanes...)
		h.mu.RUnlock()
		for _, l := range lanes {
			now := l.ackedBytes.Load()
			delta := now - prev[l.id]
			prev[l.id] = now
			if delta == 0 {
				continue
			}
			sample := delta * 2 // bytes per second over a 500ms sample
			old := l.rateBps.Load()
			if old == 0 {
				l.rateBps.Store(sample)
			} else {
				l.rateBps.Store((old*3 + sample) / 4)
			}
		}
	}
}

func (h *hub) statsLoop() {
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	prevTX := make(map[int]uint64)
	prevRX := make(map[int]uint64)
	for range t.C {
		h.mu.RLock()
		lanes := append([]*lane(nil), h.lanes...)
		h.mu.RUnlock()
		if len(lanes) == 0 {
			continue
		}
		parts := make([]string, 0, len(lanes))
		for _, l := range lanes {
			tx := l.txBytes.Load()
			rx := l.rxBytes.Load()
			dtx := tx - prevTX[l.id]
			drx := rx - prevRX[l.id]
			prevTX[l.id] = tx
			prevRX[l.id] = rx
			parts = append(parts, fmt.Sprintf(
				"%s ok=%t tx=%.2fMB/s rx=%.2fMB/s flight=%.1fKB rate=%.2fMB/s",
				l.name,
				l.ok.Load(),
				float64(dtx)/(2*1024*1024),
				float64(drx)/(2*1024*1024),
				float64(l.inflight.Load())/1024,
				float64(l.rateBps.Load())/(1024*1024),
			))
		}
		log.Printf("STATS active=%d | %s", h.activeCount(), strings.Join(parts, " | "))
	}
}

func runClient(listen, domain, path, token string, port int, ips []string) error {
	h := newHub("")

	for _, raw := range ips {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			continue
		}
		u := url.URL{
			Scheme:   "wss",
			Host:     net.JoinHostPort(ip, fmt.Sprint(port)),
			Path:     path,
			RawQuery: "token=" + url.QueryEscape(token),
		}
		d := websocket.Dialer{
			TLSClientConfig: &tls.Config{
				ServerName: domain,
				MinVersion: tls.VersionTLS12,
			},
			HandshakeTimeout: 8 * time.Second,
			ReadBufferSize:   64 * 1024,
			WriteBufferSize:  64 * 1024,
		}
		hd := http.Header{}
		hd.Set("Host", domain)
		c, _, err := d.Dial(u.String(), hd)
		if err != nil {
			log.Printf("LANE %s FAIL %v", ip, err)
			continue
		}
		l := h.addLane(ip, c)
		log.Printf("LANE %s UP id=%d", ip, l.id)
		go h.readLane(l)
	}

	if h.activeCount() == 0 {
		return fmt.Errorf("zero CF lanes")
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Printf("CLIENT READY %s lanes=%d", listen, h.activeCount())

	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			sid, err := newStreamID()
			if err != nil {
				log.Printf("LOCAL ACCEPT id generation failed from=%s err=%v", c.RemoteAddr(), err)
				_ = c.Close()
				return
			}
			log.Printf("LOCAL ACCEPT sid=%d from=%s", sid, c.RemoteAddr())
			st := h.addStream(sid, c)
			if err := h.sendControl(frame{typ: ftOpen, sid: sid}); err != nil {
				log.Printf("STREAM OPEN send failed sid=%d err=%v", sid, err)
			}
			h.pumpConnToTunnel(sid, st)
			_ = c.Close()
		}(c)
	}
}

func runServer(listen, path, token, target, cert, key string) error {
	h := newHub(target)
	up := websocket.Upgrader{
		CheckOrigin:     func(*http.Request) bool { return true },
		ReadBufferSize:  64 * 1024,
		WriteBufferSize: 64 * 1024,
	}

	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != token {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		l := h.addLane(r.RemoteAddr, c)
		log.Printf("LANE IN %s id=%d active=%d", r.RemoteAddr, l.id, h.activeCount())
		go h.readLane(l)
	})

	srv := &http.Server{Addr: listen, Handler: mux}
	log.Printf("SERVER READY %s -> %s", listen, target)
	return srv.ListenAndServeTLS(cert, key)
}

func runBench(listen string, bytes int64) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		n := bytes
		if q := r.URL.Query().Get("bytes"); q != "" {
			var x int64
			if _, err := fmt.Sscan(q, &x); err == nil && x > 0 {
				n = x
			}
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(n))
		w.Header().Set("Connection", "close")
		buf := make([]byte, 64*1024)
		for n > 0 {
			m := int64(len(buf))
			if n < m {
				m = n
			}
			if _, err := w.Write(buf[:m]); err != nil {
				return
			}
			n -= m
		}
	})
	log.Printf("BENCH READY http://%s/ bytes=%d", listen, bytes)
	return http.ListenAndServe(listen, mux)
}

func main() {
	mode := flag.String("mode", "client", "client|server|bench")
	listen := flag.String("listen", "127.0.0.1:10001", "listen address")
	domain := flag.String("domain", "", "Cloudflare hostname")
	ips := flag.String("ips", "", "comma-separated Cloudflare IPs")
	port := flag.Int("port", 8443, "Cloudflare port")
	path := flag.String("path", "/ydi-bond-v2", "WebSocket path")
	token := flag.String("token", "change-me", "shared token")
	target := flag.String("target", "127.0.0.1:18080", "server TCP target")
	cert := flag.String("cert", "", "TLS fullchain")
	key := flag.String("key", "", "TLS private key")
	benchBytes := flag.Int64("bench-bytes", 1<<30, "bench response bytes")
	flag.Parse()

	var err error
	switch *mode {
	case "client":
		if *domain == "" || *ips == "" {
			log.Fatal("client requires -domain and -ips")
		}
		err = runClient(*listen, *domain, *path, *token, *port, strings.Split(*ips, ","))
	case "server":
		if *cert == "" || *key == "" {
			log.Fatal("server requires -cert and -key")
		}
		err = runServer(*listen, *path, *token, *target, *cert, *key)
	case "bench":
		err = runBench(*listen, *benchBytes)
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		log.Fatal(err)
	}
}
