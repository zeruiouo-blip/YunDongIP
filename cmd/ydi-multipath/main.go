package main

import(
"crypto/tls";"encoding/binary";"flag";"fmt";"io";"log";"math/rand";"net";"net/http";"net/url";"strings";"sync";"sync/atomic";"time"
"github.com/gorilla/websocket"
)
const(open byte=1; data byte=2; closem byte=3)
type frame struct{t byte;s,q uint64;p []byte}
func enc(f frame)[]byte{b:=make([]byte,17+len(f.p));b[0]=f.t;binary.BigEndian.PutUint64(b[1:9],f.s);binary.BigEndian.PutUint64(b[9:17],f.q);copy(b[17:],f.p);return b}
func dec(b []byte)(frame,error){if len(b)<17{return frame{},fmt.Errorf("short frame")};return frame{b[0],binary.BigEndian.Uint64(b[1:9]),binary.BigEndian.Uint64(b[9:17]),append([]byte(nil),b[17:]...)},nil}
type lane struct{c *websocket.Conn;mu sync.Mutex;ok atomic.Bool}
func(l *lane)send(f frame)error{l.mu.Lock();defer l.mu.Unlock();return l.c.WriteMessage(websocket.BinaryMessage,enc(f))}
type reorder struct{mu sync.Mutex;n uint64;m map[uint64][]byte;w io.Writer;finSet bool;fin uint64;onFin func()}
func(o *reorder)finishLocked()func(){if o.finSet&&o.n>=o.fin&&o.onFin!=nil{f:=o.onFin;o.onFin=nil;return f};return nil}
func(o *reorder)put(q uint64,p []byte)error{o.mu.Lock();if q<o.n{o.mu.Unlock();return nil};o.m[q]=p;for{v,k:=o.m[o.n];if !k{break};if _,e:=o.w.Write(v);e!=nil{o.mu.Unlock();return e};delete(o.m,o.n);o.n++};f:=o.finishLocked();o.mu.Unlock();if f!=nil{f()};return nil}
func(o *reorder)finish(q uint64){o.mu.Lock();o.finSet=true;o.fin=q;f:=o.finishLocked();o.mu.Unlock();if f!=nil{f()}}
func closeWrite(c net.Conn){if x,ok:=c.(interface{CloseWrite()error});ok{_ = x.CloseWrite()}else{_ = c.Close()}}
type cs struct{c net.Conn;r *reorder}
type ss struct{c net.Conn;r *reorder;q atomic.Uint64}
type hub struct{mu sync.RWMutex;l []*lane;rr atomic.Uint64;c map[uint64]*cs;s map[uint64]*ss;target string}
func nh(t string)*hub{return &hub{c:map[uint64]*cs{},s:map[uint64]*ss{},target:t}}
func(h *hub)add(l *lane){l.ok.Store(true);h.mu.Lock();h.l=append(h.l,l);h.mu.Unlock()}
func(h *hub)send(f frame)error{h.mu.RLock();ls:=append([]*lane(nil),h.l...);h.mu.RUnlock();if len(ls)==0{return fmt.Errorf("no lanes")};x:=int(h.rr.Add(1)%uint64(len(ls)));for i:=0;i<len(ls);i++{l:=ls[(x+i)%len(ls)];if l.ok.Load(){if e:=l.send(f);e==nil{return nil};l.ok.Store(false)}};return fmt.Errorf("all lanes failed")}

func runClient(listen,domain,path,token string,port int,ips []string)error{
h:=nh("")
for _,ip:=range ips{ip=strings.TrimSpace(ip);if ip==""{continue};u:=url.URL{Scheme:"wss",Host:net.JoinHostPort(ip,fmt.Sprint(port)),Path:path,RawQuery:"token="+url.QueryEscape(token)};d:=websocket.Dialer{TLSClientConfig:&tls.Config{ServerName:domain,MinVersion:tls.VersionTLS12},HandshakeTimeout:8*time.Second};hd:=http.Header{};hd.Set("Host",domain);c,_,e:=d.Dial(u.String(),hd);if e!=nil{log.Printf("lane %s FAIL %v",ip,e);continue};l:=&lane{c:c};h.add(l);log.Printf("lane %s UP",ip);go readClient(h,l)}
h.mu.RLock();n:=len(h.l);h.mu.RUnlock();if n==0{return fmt.Errorf("zero CF lanes")}
ln,e:=net.Listen("tcp",listen);if e!=nil{return e};log.Printf("LOCAL READY %s lanes=%d",listen,n)
for{c,e:=ln.Accept();if e!=nil{return e};go func(c net.Conn){sid:=rand.Uint64();st:=&cs{c:c};st.r=&reorder{m:map[uint64][]byte{},w:c,onFin:func(){closeWrite(c)}};h.mu.Lock();h.c[sid]=st;h.mu.Unlock();_ = h.send(frame{t:open,s:sid});var q uint64;b:=make([]byte,32768);for{n,e:=c.Read(b);if n>0{_ = h.send(frame{t:data,s:sid,q:q,p:append([]byte(nil),b[:n]...)});q++};if e!=nil{break}};_ = h.send(frame{t:closem,s:sid,q:q});h.mu.Lock();delete(h.c,sid);h.mu.Unlock();c.Close()}(c)}
}
func readClient(h *hub,l *lane){defer l.ok.Store(false);for{_,b,e:=l.c.ReadMessage();if e!=nil{return};f,e:=dec(b);if e!=nil{continue};h.mu.RLock();st:=h.c[f.s];h.mu.RUnlock();if st==nil{continue};if f.t==data{_ = st.r.put(f.q,f.p)}else if f.t==closem{st.r.finish(f.q)}}}

func runServer(listen,path,token,target,cert,key string)error{
h:=nh(target);up:=websocket.Upgrader{CheckOrigin:func(*http.Request)bool{return true},ReadBufferSize:65536,WriteBufferSize:65536}
http.HandleFunc(path,func(w http.ResponseWriter,r *http.Request){if r.URL.Query().Get("token")!=token{http.Error(w,"forbidden",403);return};c,e:=up.Upgrade(w,r,nil);if e!=nil{return};l:=&lane{c:c};h.add(l);log.Printf("lane IN %s",r.RemoteAddr);go readServer(h,l)})
log.Printf("SERVER READY %s -> %s",listen,target);return http.ListenAndServeTLS(listen,cert,key,nil)
}
func readServer(h *hub,l *lane){defer l.ok.Store(false);for{_,b,e:=l.c.ReadMessage();if e!=nil{return};f,e:=dec(b);if e!=nil{continue};switch f.t{case open:_=ensureStream(h,f.s);case data:st:=ensureStream(h,f.s);if st!=nil{_ = st.r.put(f.q,f.p)};case closem:h.mu.RLock();st:=h.s[f.s];h.mu.RUnlock();if st!=nil{st.r.finish(f.q)}}}}
func ensureStream(h *hub,sid uint64)*ss{h.mu.RLock();st:=h.s[sid];h.mu.RUnlock();if st!=nil{return st};c,e:=net.DialTimeout("tcp",h.target,8*time.Second);if e!=nil{_ = h.send(frame{t:closem,s:sid});return nil};st=&ss{c:c};st.r=&reorder{m:map[uint64][]byte{},w:c,onFin:func(){closeWrite(c)}};h.mu.Lock();if old:=h.s[sid];old!=nil{h.mu.Unlock();c.Close();return old};h.s[sid]=st;h.mu.Unlock();go pumpServerBack(h,sid,st);return st}
func pumpServerBack(h *hub,sid uint64,st *ss){b:=make([]byte,32768);for{n,e:=st.c.Read(b);if n>0{q:=st.q.Add(1)-1;_ = h.send(frame{t:data,s:sid,q:q,p:append([]byte(nil),b[:n]...)})};if e!=nil{break}};_ = h.send(frame{t:closem,s:sid,q:st.q.Load()});h.mu.Lock();if h.s[sid]==st{delete(h.s,sid)};h.mu.Unlock();st.c.Close()}

func main(){mode:=flag.String("mode","client","client|server");listen:=flag.String("listen","127.0.0.1:10000","listen");domain:=flag.String("domain","","CF hostname");ips:=flag.String("ips","","CF IP1,IP2,...");port:=flag.Int("port",8443,"CF port");path:=flag.String("path","/ydi-mp","WS path");token:=flag.String("token","change-me","shared token");target:=flag.String("target","127.0.0.1:10086","server target");cert:=flag.String("cert","","TLS cert");key:=flag.String("key","","TLS key");flag.Parse();var e error;if *mode=="server"{if *cert==""||*key==""{log.Fatal("server requires -cert and -key")};e=runServer(*listen,*path,*token,*target,*cert,*key)}else{if *domain==""||*ips==""{log.Fatal("client requires -domain and -ips")};e=runClient(*listen,*domain,*path,*token,*port,strings.Split(*ips,","))};if e!=nil{log.Fatal(e)}}
