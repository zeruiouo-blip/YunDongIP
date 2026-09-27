package main

import (
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
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
	open   byte = 1
	data   byte = 2
	closem byte = 3

	chunkSize = 256 * 1024
	txQueue   = 512
)

type frame struct {
	t    byte
	s, q uint64
	p    []byte
}

func enc(f frame) []byte {
	b := make([]byte, 17+len(f.p))
	b[0] = f.t
	binary.BigEndian.PutUint64(b[1:9], f.s)
	binary.BigEndian.PutUint64(b[9:17], f.q)
	copy(b[17:], f.p)
	return b
}

func dec(b []byte) (frame, error) {
	if len(b) < 17 {
		return frame{}, fmt.Errorf("short frame")
	}
	return frame{
		t: b[0],
		s: binary.BigEndian.Uint64(b[1:9]),
		q: binary.BigEndian.Uint64(b[9:17]),
		p: append([]byte(nil), b[17:]...),
	}, nil
}

type lane struct {
	c    *websocket.Conn
	ok   atomic.Bool
	sent atomic.Uint64
}

func (l *lane) write(f frame) error {
	_ = l.c.SetWriteDeadline(time.Now().Add(8 * time.Second))
	b := enc(f)
	if err := l.c.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return err
	}
	l.sent.Add(uint64(len(b)))
	return nil
}

type reorder struct {
	mu     sync.Mutex
	n      uint64
	m      map[uint64][]byte
	w      io.Writer
	finSet bool
	fin    uint64
	onFin  func()
}

func (o *reorder) finishLocked() func() {
	if o.finSet && o.n >= o.fin && o.onFin != nil {
		f := o.onFin
		o.onFin = nil
		return f
	}
	return nil
}

func (o *reorder) put(q uint64, p []byte) error {
	o.mu.Lock()
	if q < o.n {
		o.mu.Unlock()
		return nil
	}
	o.m[q] = p
	for {
		v, ok := o.m[o.n]
		if !ok {
			break
		}
		if _, err := o.w.Write(v); err != nil {
			o.mu.Unlock()
			return err
		}
		delete(o.m, o.n)
		o.n++
	}
	f := o.finishLocked()
	o.mu.Unlock()
	if f != nil {
		f()
	}
	return nil
}

func (o *reorder) finish(q uint64) {
	o.mu.Lock()
	o.finSet = true
	o.fin = q
	f := o.finishLocked()
	o.mu.Unlock()
	if f != nil {
		f()
	}
}

func closeWrite(c net.Conn) {
	if x, ok := c.(interface{ CloseWrite() error }); ok {
		_ = x.CloseWrite()
	} else {
		_ = c.Close()
	}
}

type cs struct {
	c net.Conn
	r *reorder
}

type ss struct {
	c net.Conn
	r *reorder
	q atomic.Uint64
}

type hub struct {
	mu     sync.RWMutex
	lanes  []*lane
	tx     chan frame
	c      map[uint64]*cs
	s      map[uint64]*ss
	target string
}

func nh(target string) *hub {
	return &hub{
		tx:     make(chan frame, txQueue),
		c:      map[uint64]*cs{},
		s:      map[uint64]*ss{},
		target: target,
	}
}

func (h *hub) active() int {
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

func (h *hub) add(l *lane) {
	l.ok.Store(true)
	h.mu.Lock()
	h.lanes = append(h.lanes, l)
	h.mu.Unlock()
	go h.laneWriter(l)
}

func (h *hub) laneWriter(l *lane) {
	for f := range h.tx {
		if !l.ok.Load() {
			if h.active() > 0 {
				h.tx <- f
			}
			return
		}
		if err := l.write(f); err != nil {
			l.ok.Store(false)
			log.Printf("lane writer down: %v", err)
			if h.active() > 0 {
				h.tx <- f
			}
			return
		}
	}
}

func (h *hub) send(f frame) error {
	if h.active() == 0 {
		return fmt.Errorf("no active lanes")
	}
	h.tx <- f
	return nil
}

func runClient(listen, domain, path, token string, port int, ips []string) error {
	h := nh("")
	for _, ip := range ips {
		ip = strings.TrimSpace(ip)
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
			ReadBufferSize:   chunkSize,
			WriteBufferSize:  chunkSize,
		}
		hd := http.Header{}
		hd.Set("Host", domain)
		c, _, err := d.Dial(u.String(), hd)
		if err != nil {
			log.Printf("lane %s FAIL %v", ip, err)
			continue
		}
		l := &lane{c: c}
		h.add(l)
		log.Printf("lane %s UP", ip)
		go readClient(h, l)
	}
	if h.active() == 0 {
		return fmt.Errorf("zero CF lanes")
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	log.Printf("LOCAL READY %s lanes=%d", listen, h.active())

	for {
		c, err := ln.Accept()
		if err != nil {
			return err
		}
		go func(c net.Conn) {
			sid := rand.Uint64()
			st := &cs{c: c}
			st.r = &reorder{
				m:     map[uint64][]byte{},
				w:     c,
				onFin: func() { closeWrite(c) },
			}
			h.mu.Lock()
			h.c[sid] = st
			h.mu.Unlock()

			_ = h.send(frame{t: open, s: sid})
			var q uint64
			b := make([]byte, chunkSize)
			for {
				n, err := c.Read(b)
				if n > 0 {
					_ = h.send(frame{
						t: data,
						s: sid,
						q: q,
						p: append([]byte(nil), b[:n]...),
					})
					q++
				}
				if err != nil {
					break
				}
			}
			_ = h.send(frame{t: closem, s: sid, q: q})

			h.mu.Lock()
			delete(h.c, sid)
			h.mu.Unlock()
			_ = c.Close()
		}(c)
	}
}

func readClient(h *hub, l *lane) {
	defer l.ok.Store(false)
	for {
		_, b, err := l.c.ReadMessage()
		if err != nil {
			return
		}
		f, err := dec(b)
		if err != nil {
			continue
		}
		h.mu.RLock()
		st := h.c[f.s]
		h.mu.RUnlock()
		if st == nil {
			continue
		}
		switch f.t {
		case data:
			_ = st.r.put(f.q, f.p)
		case closem:
			st.r.finish(f.q)
		}
	}
}

func runServer(listen, path, token, target, cert, key string) error {
	h := nh(target)
	up := websocket.Upgrader{
		CheckOrigin:      func(*http.Request) bool { return true },
		ReadBufferSize:   chunkSize,
		WriteBufferSize:  chunkSize,
	}
	http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != token {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		l := &lane{c: c}
		h.add(l)
		log.Printf("lane IN %s active=%d", r.RemoteAddr, h.active())
		go readServer(h, l)
	})

	log.Printf("SERVER READY %s -> %s", listen, target)
	return http.ListenAndServeTLS(listen, cert, key, nil)
}

func readServer(h *hub, l *lane) {
	defer l.ok.Store(false)
	for {
		_, b, err := l.c.ReadMessage()
		if err != nil {
			return
		}
		f, err := dec(b)
		if err != nil {
			continue
		}
		switch f.t {
		case open:
			_ = ensureStream(h, f.s)
		case data:
			st := ensureStream(h, f.s)
			if st != nil {
				_ = st.r.put(f.q, f.p)
			}
		case closem:
			h.mu.RLock()
			st := h.s[f.s]
			h.mu.RUnlock()
			if st != nil {
				st.r.finish(f.q)
			}
		}
	}
}

func ensureStream(h *hub, sid uint64) *ss {
	h.mu.RLock()
	st := h.s[sid]
	h.mu.RUnlock()
	if st != nil {
		return st
	}

	c, err := net.DialTimeout("tcp", h.target, 8*time.Second)
	if err != nil {
		_ = h.send(frame{t: closem, s: sid})
		return nil
	}
	st = &ss{c: c}
	st.r = &reorder{
		m:     map[uint64][]byte{},
		w:     c,
		onFin: func() { closeWrite(c) },
	}

	h.mu.Lock()
	if old := h.s[sid]; old != nil {
		h.mu.Unlock()
		_ = c.Close()
		return old
	}
	h.s[sid] = st
	h.mu.Unlock()

	go pumpServerBack(h, sid, st)
	return st
}

func pumpServerBack(h *hub, sid uint64, st *ss) {
	b := make([]byte, chunkSize)
	for {
		n, err := st.c.Read(b)
		if n > 0 {
			q := st.q.Add(1) - 1
			_ = h.send(frame{
				t: data,
				s: sid,
				q: q,
				p: append([]byte(nil), b[:n]...),
			})
		}
		if err != nil {
			break
		}
	}
	_ = h.send(frame{t: closem, s: sid, q: st.q.Load()})

	h.mu.Lock()
	if h.s[sid] == st {
		delete(h.s, sid)
	}
	h.mu.Unlock()
	_ = st.c.Close()
}

func main() {
	mode := flag.String("mode", "client", "client|server")
	listen := flag.String("listen", "127.0.0.1:10000", "listen")
	domain := flag.String("domain", "", "CF hostname")
	ips := flag.String("ips", "", "CF IP1,IP2,...")
	port := flag.Int("port", 8443, "CF port")
	path := flag.String("path", "/ydi-mp", "WS path")
	token := flag.String("token", "change-me", "shared token")
	target := flag.String("target", "127.0.0.1:10086", "server target")
	cert := flag.String("cert", "", "TLS cert")
	key := flag.String("key", "", "TLS key")
	flag.Parse()

	var err error
	if *mode == "server" {
		if *cert == "" || *key == "" {
			log.Fatal("server requires -cert and -key")
		}
		err = runServer(*listen, *path, *token, *target, *cert, *key)
	} else {
		if *domain == "" || *ips == "" {
			log.Fatal("client requires -domain and -ips")
		}
		err = runClient(*listen, *domain, *path, *token, *port, strings.Split(*ips, ","))
	}
	if err != nil {
		log.Fatal(err)
	}
}
