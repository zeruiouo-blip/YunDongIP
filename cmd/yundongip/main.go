// Copyright (c) 2026 zeruiouo-blip
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"hash/fnv"
	"io"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed index.html
var staticFiles embed.FS

const (
	projectName        = "YunDongIP"
	projectVersion     = "0.1.1"
	projectSource      = "https://github.com/zeruiouo-blip/YunDongIP"
	projectBuildMarker = "YDI-PROVENANCE-0.1.1-9C4E7A12"
)

var (
	buildVersion = projectVersion
	buildCommit  = "source"
)

type IPVersion string

const (
	IPv4 IPVersion = "IPv4"
	IPv6 IPVersion = "IPv6"
)

type DataCenterInfo struct {
	DataCenter  string  `json:"DataCenter"`
	Region      string  `json:"Region"`
	City        string  `json:"City"`
	IPCount     int     `json:"IPCount"`
	MinLatency  int     `json:"MinLatency"`
	AvgLatency  int     `json:"AvgLatency"`
	MinLossRate float64 `json:"MinLossRate"`
}

type ScanResult struct {
	IP            string        `json:"IP"`
	Port          int           `json:"Port"`
	DataCenter    string        `json:"DataCenter"`
	Country       string        `json:"Country"`
	Region        string        `json:"Region"`
	City          string        `json:"City"`
	Method        string        `json:"Method"`
	LatencyStr    string        `json:"LatencyStr"`
	TCPDuration   time.Duration `json:"TCPDuration"`
	MinLatency    time.Duration `json:"MinLatency"`
	MaxLatency    time.Duration `json:"MaxLatency"`
	AvgLatency    time.Duration `json:"AvgLatency"`
	LossRate      float64       `json:"LossRate"`
	ProbeCount    int           `json:"ProbeCount"`
	SuccessCount  int           `json:"SuccessCount"`
	LocalAdaptive bool          `json:"LocalAdaptive"`
}

type TestResult struct {
	IP         string
	Port       int
	DataCenter string
	Country    string
	Region     string
	City       string
	Method     string
	MinLatency time.Duration
	MaxLatency time.Duration
	AvgLatency time.Duration
	LossRate   float64
	Speed      string
}

type location struct {
	Iata   string  `json:"iata"`
	Lat    float64 `json:"lat"`
	Lon    float64 `json:"lon"`
	Cca2   string  `json:"cca2"`
	Region string  `json:"region"`
	City   string  `json:"city"`
}

type NodeProfile struct {
	IP           string    `json:"ip"`
	Version      IPVersion `json:"version"`
	SpeedMB      float64   `json:"speed_mb"`
	LatencyMS    int       `json:"latency_ms"`
	Colo         string    `json:"colo"`
	ISP          string    `json:"isp"`
	BackbonePath string    `json:"backbone_path"`
	CurrentRole  string    `json:"current_role"`
	BoundDomain  string    `json:"bound_domain"`
	IsLocked     bool      `json:"is_locked"`
	BornTime     time.Time `json:"born_time"`
}

type CandidateIP struct {
	IP             string       `json:"ip"`
	Port           int          `json:"port"`
	Version        IPVersion    `json:"version"`
	Colo           string       `json:"colo"`
	Country        string       `json:"country"`
	Region         string       `json:"region"`
	City           string       `json:"city"`
	Method         string       `json:"method"`
	Delay          int          `json:"delay"`
	Speed          float64      `json:"speed"`
	HistorySpeed   float64      `json:"history_speed"` // 保留历史优秀战力
	ChallengeCount int          `json:"challenge_count"`
	ZeroStreak     int          `json:"zero_streak"` // 连续 0 MB/s 计数 (满2次处决)
	LastCheck      time.Time    `json:"last_check"`
	Status         string       `json:"status"`
	Profile        *NodeProfile `json:"profile,omitempty"`
}

type ColdIP struct {
	IP           string    `json:"ip"`
	Port         int       `json:"port"`
	Version      IPVersion `json:"version"`
	Colo         string    `json:"colo"`
	LastSpeed    float64   `json:"last_speed"`
	LastDelay    int       `json:"last_delay"`
	FailCount    int       `json:"fail_count"`
	ColdTime     time.Time `json:"cold_time"`
	ColdUntil    time.Time `json:"cold_until"`
	RemainingSec int64     `json:"remaining_sec"`
	Status       string    `json:"status"`
}

type RetiredIP struct {
	IP          string       `json:"ip"`
	Port        int          `json:"port"`
	Version     IPVersion    `json:"version"`
	Colo        string       `json:"colo"`
	LastSpeed   float64      `json:"last_speed"`
	LastDelay   int          `json:"last_delay"`
	RetiredTime time.Time    `json:"retired_time"`
	OrigDomain  string       `json:"orig_domain"`
	PeriodTag   string       `json:"period_tag"`
	Status      string       `json:"status"`
	Profile     *NodeProfile `json:"profile,omitempty"`
}

type SubdomainConfig struct {
	Subdomain string `json:"subdomain"`
	Type      string `json:"type"`
	Mode      string `json:"mode"`
}

type PipelineConfig struct {
	Enabled       bool              `json:"enabled"`
	MinSpeedMB    float64           `json:"min_speed_mb"`
	Ports         string            `json:"ports"`
	AllowedColos  string            `json:"allowed_colos"`
	ApiToken      string            `json:"api_token"`
	ZoneID        string            `json:"zone_id"`
	RootDomain    string            `json:"root_domain"`
	PeakStartHour int               `json:"peak_start_hour"`
	PeakEndHour   int               `json:"peak_end_hour"`
	Subdomains    []SubdomainConfig `json:"subdomains"`
	R2Mode        string            `json:"r2_mode"`
	R2ManualColos []string          `json:"r2_manual_colos"`
	R2PerRegion   int               `json:"r2_per_region"`
}

type SubdomainStatus struct {
	Subdomain    string       `json:"subdomain"`
	FullDomain   string       `json:"full_domain"`
	Type         string       `json:"type"`
	Mode         string       `json:"mode"`
	Rank         int          `json:"rank"`
	CurrentIP    string       `json:"current_ip"`
	CurrentSpeed float64      `json:"current_speed"`
	Status       string       `json:"status"`
	LastUpTime   time.Time    `json:"last_up_time"`
	Profile      *NodeProfile `json:"profile,omitempty"`
}

// R4 100 物理格子环形缓冲
type RingBuffer100 struct {
	Slots   [100]*CandidateIP
	Pointer int
	mu      sync.RWMutex
}

func (rb *RingBuffer100) PatrolStep() *CandidateIP {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	start := rb.Pointer
	for {
		item := rb.Slots[rb.Pointer]
		rb.Pointer = (rb.Pointer + 1) % 100
		if item != nil {
			return item
		}
		if rb.Pointer == start {
			return nil
		}
	}
}

func (rb *RingBuffer100) Insert(item *CandidateIP) *CandidateIP {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	for i := 0; i < 100; i++ {
		if rb.Slots[i] == nil {
			rb.Slots[i] = item
			return nil
		}
	}
	lowestIdx := -1
	minSpeed := math.MaxFloat64
	for i := 0; i < 100; i++ {
		if rb.Slots[i] != nil && (rb.Slots[i].Profile == nil || !rb.Slots[i].Profile.IsLocked) {
			if rb.Slots[i].Speed < minSpeed {
				minSpeed = rb.Slots[i].Speed
				lowestIdx = i
			}
		}
	}
	if lowestIdx != -1 {
		evicted := rb.Slots[lowestIdx]
		rb.Slots[lowestIdx] = item
		return evicted
	}
	return item
}

func (rb *RingBuffer100) Remove(ip string) {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	for i := 0; i < 100; i++ {
		if rb.Slots[i] != nil && rb.Slots[i].IP == ip {
			rb.Slots[i] = nil
			return
		}
	}
}

func (rb *RingBuffer100) ToList() []*CandidateIP {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	var list []*CandidateIP
	for i := 0; i < 100; i++ {
		if rb.Slots[i] != nil {
			list = append(list, rb.Slots[i])
		}
	}
	return list
}

func (rb *RingBuffer100) Count() int {
	rb.mu.RLock()
	defer rb.mu.RUnlock()
	c := 0
	for i := 0; i < 100; i++ {
		if rb.Slots[i] != nil {
			c++
		}
	}
	return c
}

func (rb *RingBuffer100) ClearAndExtract() []*CandidateIP {
	rb.mu.Lock()
	defer rb.mu.Unlock()
	var list []*CandidateIP
	for i := 0; i < 100; i++ {
		if rb.Slots[i] != nil {
			list = append(list, rb.Slots[i])
			rb.Slots[i] = nil
		}
	}
	rb.Pointer = 0
	return list
}

var (
	scanResults []ScanResult
	scanMutex   sync.Mutex
	locationMap map[string]location

	wsMutex       sync.Mutex
	taskMutex     sync.Mutex
	isTaskRunning bool
	taskCancel    context.CancelFunc

	listenPort   int
	listenHost   string
	openBrowser  bool
	speedTestURL string

	pipeCfg        PipelineConfig
	pipeLock       sync.Mutex
	pool2          = make(map[string]*CandidateIP) // 兼容旧接口：不再作为独立R2候选池使用
	r2Eligible     = make(map[string]struct{})     // 扫描/精测榜中的直接R2候选集合
	r2RegionCursor int
	r2ZeroStreak   = make(map[string]int)
	r2HistorySpeed = make(map[string]float64)
	r2RetryAfter   = make(map[string]time.Time)
	pool3V4        = make([]*CandidateIP, 0)
	pool3V6        = make([]*CandidateIP, 0)
	pool4V4Ring    = RingBuffer100{}
	pool4V6Ring    = RingBuffer100{}
	coldPool       = make(map[string]*ColdIP)

	retiredDaytime = make(map[string]*RetiredIP)
	retiredPeak    = make(map[string]*RetiredIP)
	sealedDaytime  = make(map[string]*CandidateIP)
	sealedPeak     = make(map[string]*CandidateIP)

	lastRecordedPeriod = "daytime"

	domainStatus = make(map[string]*SubdomainStatus)
	profileStore = make(map[string]*NodeProfile)
	pipeStop     chan struct{}
	logs         []string
	logLock      sync.Mutex
	activeWSConn *wsConn

	localDetectedCity   = "本地公网出口"
	localDetectedRegion = ""
	localDetectedISP    = "自动探测中"
	localGeoReady       bool

	lowSpeedBlacklist = make(map[string]time.Time)
	blacklistLock     sync.RWMutex

	scanRotationLock  sync.Mutex
	scanRotationEpoch uint64

	r3BenchmarkV4     float64
	r3BenchmarkTimeV4 time.Time
	r3BenchmarkV6     float64
	r3BenchmarkTimeV6 time.Time

	// 全局测速单车道：所有下载测速共用一个通道，保证任一时刻只有一个真实下载测速在进行。
	speedBus = make(chan struct{}, 1)
)

var defaultIPv4CIDRs = []string{
	"104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "162.158.0.0/15",
	"198.41.128.0/17", "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
	"103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20",
	"188.114.96.0/20", "197.234.240.0/22", "131.0.72.0/22",
}

var defaultIPv6CIDRs = []string{
	"2606:4700::/32", "2606:4700:30::/48", "2400:cb00::/32", "2803:f800::/32",
	"2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29", "2c0f:f248::/32",
}

func removeCandidateFromSlice(slice *[]*CandidateIP, ip string) {
	newSlice := make([]*CandidateIP, 0, len(*slice))
	for _, item := range *slice {
		if item != nil && item.IP != ip {
			newSlice = append(newSlice, item)
		}
	}
	*slice = newSlice
}

func isBlacklisted(ip string) bool {
	blacklistLock.RLock()
	defer blacklistLock.RUnlock()
	_, ok := lowSpeedBlacklist[ip]
	return ok
}

func addToBlacklist(ip string) {
	blacklistLock.Lock()
	lowSpeedBlacklist[ip] = time.Now()
	blacklistLock.Unlock()
	saveCacheFiles()
}

func getCurrentPeriodTag() string {
	hr := time.Now().Hour()
	s := pipeCfg.PeakStartHour
	e := pipeCfg.PeakEndHour
	if s == 0 && e == 0 {
		s = 19
		e = 24
	}
	if hr >= s && hr < e {
		return "peak"
	}
	return "daytime"
}

func detectLocalOutboundGeo() {
	client := &http.Client{Timeout: 4 * time.Second}

	type geoResult struct {
		City   string
		Region string
		ISP    string
	}
	var result geoResult

	// 首选 HTTPS 公网出口定位，避免旧版固定地区和明文接口造成误判。
	req, _ := http.NewRequest("GET", "https://ipwho.is/", nil)
	req.Header.Set("User-Agent", projectName+"/"+projectVersion)
	if resp, err := client.Do(req); err == nil {
		var res struct {
			Success bool   `json:"success"`
			City    string `json:"city"`
			Region  string `json:"region"`
			Connection struct {
				ISP string `json:"isp"`
			} `json:"connection"`
		}
		if resp.Body != nil {
			_ = json.NewDecoder(resp.Body).Decode(&res)
			resp.Body.Close()
		}
		if res.Success && (strings.TrimSpace(res.City) != "" || strings.TrimSpace(res.Region) != "") {
			result.City = strings.TrimSpace(res.City)
			result.Region = strings.TrimSpace(res.Region)
			result.ISP = strings.TrimSpace(res.Connection.ISP)
		}
	}

	// 主接口不可用时使用第二个 HTTPS 来源兜底。
	if result.City == "" && result.Region == "" {
		req2, _ := http.NewRequest("GET", "https://ipapi.co/json/", nil)
		req2.Header.Set("User-Agent", projectName+"/"+projectVersion)
		if resp, err := client.Do(req2); err == nil {
			var res struct {
				City   string `json:"city"`
				Region string `json:"region"`
				Org    string `json:"org"`
			}
			if resp.Body != nil {
				_ = json.NewDecoder(resp.Body).Decode(&res)
				resp.Body.Close()
			}
			result.City = strings.TrimSpace(res.City)
			result.Region = strings.TrimSpace(res.Region)
			result.ISP = strings.TrimSpace(res.Org)
		}
	}

	label := "本地公网出口"
	if result.Region != "" && result.City != "" && !strings.EqualFold(result.Region, result.City) {
		label = result.Region + " · " + result.City
	} else if result.City != "" {
		label = result.City
	} else if result.Region != "" {
		label = result.Region
	}
	isp := result.ISP
	if isp == "" {
		isp = "未知运营商"
	}

	pipeLock.Lock()
	localDetectedCity = label
	localDetectedRegion = result.Region
	localDetectedISP = isp
	localGeoReady = result.City != "" || result.Region != ""
	refreshProfileRoutesLocked()
	saveCacheFiles()
	pipeLock.Unlock()

	if localGeoReady {
		addLog("📍 [公网出口识别] 已自动识别地区：%s；运营商：%s。数字身份证首跳已同步刷新。", localDetectedCity, localDetectedISP)
	} else {
		addLog("⚠️ [公网出口识别] 暂未取得地区信息，数字身份证将显示“本地公网出口”，不会使用固定城市。")
	}
}

func refreshProfileRoutesLocked() {
	for _, p := range profileStore {
		if p == nil {
			continue
		}
		isp, path := buildDetailedRoutePath(p.IP, p.Colo, p.LatencyMS, p.Version == IPv6)
		p.ISP = isp
		p.BackbonePath = path
	}
	for _, stat := range domainStatus {
		if stat == nil || stat.CurrentIP == "" {
			continue
		}
		if p := profileStore[stat.CurrentIP]; p != nil {
			stat.Profile = p
		}
	}
}

func addLog(format string, a ...interface{}) {
	msg := fmt.Sprintf("[%s] ", time.Now().Format("15:04:05")) + fmt.Sprintf(format, a...)
	logLock.Lock()
	logs = append(logs, msg)
	if len(logs) > 120 {
		logs = logs[1:]
	}
	logLock.Unlock()

	wsMutex.Lock()
	if activeWSConn != nil {
		_ = activeWSConn.WriteJSON(map[string]interface{}{
			"type": "log",
			"data": msg,
		})
	}
	wsMutex.Unlock()
}

func isIPv6(ip string) bool {
	return strings.Contains(ip, ":")
}

func checkLocalIPv6Support() bool {
	conn, err := net.DialTimeout("tcp", "[2606:4700:4700::1111]:53", 1500*time.Millisecond)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}

func isColoMatched(nodeColo, allowedFilter string) bool {
	clean := strings.TrimSpace(allowedFilter)
	if clean == "" || strings.Contains(clean, "留空") || strings.Contains(clean, "自动") {
		return true
	}
	colos := strings.Split(clean, ",")
	for _, c := range colos {
		c = strings.TrimSpace(strings.ToUpper(c))
		if c != "" && strings.EqualFold(c, strings.TrimSpace(strings.ToUpper(nodeColo))) {
			return true
		}
	}
	return false
}

func buildDetailedRoutePath(ip, colo string, latency int, isV6 bool) (string, string) {
	localLabel := strings.TrimSpace(localDetectedCity)
	if localLabel == "" {
		localLabel = "本地公网出口"
	}
	isp := strings.TrimSpace(localDetectedISP)
	if isp == "" || isp == "自动探测中" {
		isp = "未知运营商"
	}
	proto := "IPv4"
	if isV6 {
		proto = "IPv6"
	}

	hops := []string{
		fmt.Sprintf("%s (%s)", localLabel, isp),
		fmt.Sprintf("本地运营商公网出口 (%s)", proto),
	}
	if latency > 0 {
		hops = append(hops, fmt.Sprintf("公网转接路径 · 端到端约 %d ms", latency))
	} else {
		hops = append(hops, "公网转接路径")
	}

	cleanColo := strings.TrimSpace(strings.ToUpper(colo))
	if cleanColo == "" || cleanColo == "TRACE中" {
		cleanColo = "CF"
	}
	switch cleanColo {
	case "HKG":
		hops = append(hops, "Cloudflare 香港 Anycast 边缘 (HKG)")
	case "SJC":
		hops = append(hops, "Cloudflare 圣何塞 Anycast 边缘 (SJC)")
	case "LAX":
		hops = append(hops, "Cloudflare 洛杉矶 Anycast 边缘 (LAX)")
	case "NRT":
		hops = append(hops, "Cloudflare 东京 Anycast 边缘 (NRT)")
	case "KIX":
		hops = append(hops, "Cloudflare 大阪 Anycast 边缘 (KIX)")
	case "FRA":
		hops = append(hops, "Cloudflare 法兰克福 Anycast 边缘 (FRA)")
	case "CF":
		hops = append(hops, "Cloudflare Anycast 边缘")
	default:
		hops = append(hops, fmt.Sprintf("Cloudflare %s Anycast 边缘", cleanColo))
	}

	return isp, strings.Join(hops, " ➔ ")
}

func buildNodeProfile(ip string, ver IPVersion, speedMbps float64, delay int, port int, coloHint string) *NodeProfile {
	colo := strings.TrimSpace(strings.ToUpper(coloHint))
	if colo == "" || colo == "TRACE中" {
		colo = "CF"
	}

	isp, fullPath := buildDetailedRoutePath(ip, colo, delay, ver == IPv6)

	return &NodeProfile{
		IP:           ip,
		Version:      ver,
		SpeedMB:      speedMbps / 8.0,
		LatencyMS:    delay,
		Colo:         colo,
		ISP:          isp,
		BackbonePath: fullPath,
		CurrentRole:  "candidate",
		BornTime:     time.Now(),
	}
}

func syncDomainStatusMapLocked() {
	activeKeys := make(map[string]bool)
	rankV4 := 0
	rankV6 := 0

	for _, s := range pipeCfg.Subdomains {
		key := fmt.Sprintf("%s_%s", s.Subdomain, s.Type)
		activeKeys[key] = true

		full := s.Subdomain
		if pipeCfg.RootDomain != "" {
			full = fmt.Sprintf("%s.%s", s.Subdomain, pipeCfg.RootDomain)
		}

		stat, exists := domainStatus[key]
		if !exists {
			stat = &SubdomainStatus{
				Subdomain:  s.Subdomain,
				FullDomain: full,
				Type:       s.Type,
				Mode:       s.Mode,
				Status:     "就绪待命",
			}
			domainStatus[key] = stat
		} else {
			stat.Mode = s.Mode
			stat.FullDomain = full
		}

		if s.Mode == "manual" {
			stat.Rank = 0
		} else if s.Type == "A" {
			rankV4++
			stat.Rank = rankV4
		} else {
			rankV6++
			stat.Rank = rankV6
		}
	}

	for k := range domainStatus {
		if !activeKeys[k] {
			delete(domainStatus, k)
		}
	}
}

func openLocalBrowser(url string) {
	var cmd string
	var args []string
	switch runtime.GOOS {
	case "windows":
		cmd, args = "rundll32", []string{"url.dll,FileProtocolHandler", url}
	case "darwin":
		cmd, args = "open", []string{url}
	default:
		cmd, args = "xdg-open", []string{url}
	}
	_ = exec.Command(cmd, args...).Start()
}

func handleAbout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-YunDongIP-Project", projectName)
	w.Header().Set("X-YunDongIP-Version", buildVersion)
	w.Header().Set("X-YunDongIP-Build", buildCommit)
	w.Header().Set("X-YunDongIP-Marker", projectBuildMarker)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"project":      projectName,
		"version":      buildVersion,
		"build_commit": buildCommit,
		"source":       projectSource,
		"marker":       projectBuildMarker,
	})
}

func main() {
	flag.IntVar(&listenPort, "port", 13335, "服务监听端口")
	flag.StringVar(&listenHost, "host", "127.0.0.1", "服务监听地址；局域网访问可指定 0.0.0.0")
	flag.BoolVar(&openBrowser, "open-browser", true, "启动后自动打开本机浏览器")
	flag.StringVar(&speedTestURL, "url", "speed.cloudflare.com/__down?bytes=25000000", "测速下载地址")
	flag.Parse()

	initLocations()
	loadCleanCacheFiles()
	loadPipelineConfig()
	loadScanRotationState()
	go detectLocalOutboundGeo()
	go func() {
		localGeoRefreshTicker := time.NewTicker(15 * time.Minute)
		defer localGeoRefreshTicker.Stop()
		for range localGeoRefreshTicker.C {
			detectLocalOutboundGeo()
		}
	}()

	pipeLock.Lock()
	pipeCfg.Enabled = false
	lastRecordedPeriod = getCurrentPeriodTag()
	pipeLock.Unlock()

	http.HandleFunc("/api/about", handleAbout)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-YunDongIP-Project", projectName)
		w.Header().Set("X-YunDongIP-Version", buildVersion)
		w.Header().Set("X-YunDongIP-Build", buildCommit)
		w.Header().Set("X-YunDongIP-Marker", projectBuildMarker)
		data, err := staticFiles.ReadFile("index.html")
		if err != nil {
			http.Error(w, "无法加载页面", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(data)
	})
	http.HandleFunc("/ws", handleWebSocket)

	http.HandleFunc("/api/pipeline/get", handlePipeGet)
	http.HandleFunc("/api/pipeline/save", handlePipeSave)
	http.HandleFunc("/api/pipeline/sync_now", handlePipeSyncNow)
	http.HandleFunc("/api/pipeline/benchmark/reset", handleResetR3Benchmark)
	http.HandleFunc("/api/pipeline/r2/config", handleR2ConfigSave)
	http.HandleFunc("/api/pipeline/clear_all", handleClearAll)
	http.HandleFunc("/api/pipeline/subdomain/add", handleAddSubdomain)
	http.HandleFunc("/api/pipeline/subdomain/delete", handleDeleteSubdomain)
	http.HandleFunc("/api/pipeline/subdomain/set_mode", handleSetSubdomainMode)
	http.HandleFunc("/api/pipeline/subdomain/pin", handlePinIPToSubdomain)

	http.HandleFunc("/api/pipeline/node/lock", handleToggleNodeLock)
	http.HandleFunc("/api/pipeline/node/demote", handleDemoteNodeToR3)
	http.HandleFunc("/api/pipeline/node/delete", handlePhysicalDeleteNode)

	http.HandleFunc("/api/pipeline/cold/unfreeze", handleUnfreezeColdIP)
	http.HandleFunc("/api/pipeline/cold/delete", handleDeleteColdIP)

	http.HandleFunc("/api/pipeline/retired/clear_all", handleClearRetiredPool)
	http.HandleFunc("/api/pipeline/retired/delete", handleDeleteRetired)
	http.HandleFunc("/api/pipeline/retired/to_pool3", handleRetiredToPool3)

	http.HandleFunc("/api/pipeline/blacklist/clear", handleClearBlacklist)
	http.HandleFunc("/api/cf/zones", handleFetchZones)

	addr := fmt.Sprintf("%s:%d", listenHost, listenPort)
	url := fmt.Sprintf("http://%s:%d", listenHost, listenPort)
	if listenHost == "0.0.0.0" || listenHost == "::" || listenHost == "" {
		url = fmt.Sprintf("http://127.0.0.1:%d", listenPort)
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("启动失败: %v\n", err)
		return
	}
	fmt.Printf("%s %s | build=%s | source=%s | marker=%s | 服务启动于 %s\n", projectName, buildVersion, buildCommit, projectSource, projectBuildMarker, url)
	if openBrowser {
		openLocalBrowser(url)
	}
	if err := http.Serve(listener, nil); err != nil {
		fmt.Printf("服务停止: %v\n", err)
	}
}

func handleClearBlacklist(w http.ResponseWriter, r *http.Request) {
	blacklistLock.Lock()
	count := len(lowSpeedBlacklist)
	lowSpeedBlacklist = make(map[string]time.Time)
	blacklistLock.Unlock()
	_ = os.Remove("blacklist_cache.json")
	addLog("⚠️ [人工特赦] 已清空全部 %d 个熔断黑名单节点！", count)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "cleared_count": count})
}

// wsConn is the project's self-contained WebSocket server connection.
// It implements only the server-side features YunDongIP needs: text frames,
// control frames, masking/unmasking, fragmentation, and the opening handshake.
// No external WebSocket package is required.
type wsConn struct {
	conn      net.Conn
	writeMu   sync.Mutex
	closeOnce sync.Once
}

func upgradeWebSocket(w http.ResponseWriter, r *http.Request) (*wsConn, error) {
	if r.Method != http.MethodGet {
		return nil, fmt.Errorf("WebSocket upgrade requires GET")
	}
	if !headerTokenContains(r.Header.Get("Connection"), "upgrade") || !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return nil, fmt.Errorf("missing WebSocket Upgrade headers")
	}
	if r.Header.Get("Sec-WebSocket-Version") != "13" {
		return nil, fmt.Errorf("unsupported WebSocket version")
	}
	key := strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key"))
	if key == "" {
		return nil, fmt.Errorf("missing Sec-WebSocket-Key")
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		return nil, fmt.Errorf("HTTP server does not support connection hijacking")
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return nil, err
	}
	if rw != nil {
		// The browser will not send WebSocket frames until it receives this handshake,
		// so no buffered frame bytes should exist here. Flush the response and leave
		// the hijacked connection as the single source of subsequent I/O.
		defer func() { _ = rw.Flush() }()
	}

	accept := websocketAcceptKey(key)
	response := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n" +
		"\r\n"
	if _, err := io.WriteString(conn, response); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if rw != nil {
		_ = rw.Flush()
	}
	return &wsConn{conn: conn}, nil
}

func headerTokenContains(value, wanted string) bool {
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), wanted) {
			return true
		}
	}
	return false
}

func websocketAcceptKey(key string) string {
	h := sha1.New()
	_, _ = io.WriteString(h, key+"258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

func (c *wsConn) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	var err error
	c.closeOnce.Do(func() {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		// Best effort close frame. A TCP close still follows immediately.
		_ = c.writeFrameLocked(0x88, []byte{0x03, 0xE8})
		err = c.conn.Close()
	})
	return err
}

func (c *wsConn) ReadMessage() ([]byte, error) {
	if c == nil || c.conn == nil {
		return nil, io.EOF
	}
	var message []byte
	inProgress := false
	for {
		fin, opcode, payload, err := c.readFrame()
		if err != nil {
			return nil, err
		}
		switch opcode {
		case 0x8: // close
			c.writeMu.Lock()
			_ = c.writeFrameLocked(0x88, payload)
			c.writeMu.Unlock()
			return nil, io.EOF
		case 0x9: // ping
			c.writeMu.Lock()
			err := c.writeFrameLocked(0x8A, payload)
			c.writeMu.Unlock()
			if err != nil {
				return nil, err
			}
			continue
		case 0xA: // pong
			continue
		case 0x0: // continuation
			if !inProgress {
				return nil, fmt.Errorf("unexpected WebSocket continuation frame")
			}
			message = append(message, payload...)
			if fin {
				return message, nil
			}
		case 0x1: // text
			if inProgress {
				return nil, fmt.Errorf("new WebSocket text frame before previous message completed")
			}
			message = append(message[:0], payload...)
			if fin {
				return message, nil
			}
			inProgress = true
		case 0x2: // binary is not used by the browser protocol
			return nil, fmt.Errorf("binary WebSocket messages are not supported")
		default:
			return nil, fmt.Errorf("unsupported WebSocket opcode 0x%x", opcode)
		}
	}
}

func (c *wsConn) WriteJSON(v interface{}) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return c.WriteMessage(b)
}

func (c *wsConn) WriteMessage(payload []byte) error {
	if c == nil || c.conn == nil {
		return io.ErrClosedPipe
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.writeFrameLocked(0x81, payload)
}

func (c *wsConn) writeFrameLocked(first byte, payload []byte) error {
	header := make([]byte, 0, 10)
	header = append(header, first)
	switch {
	case len(payload) <= 125:
		header = append(header, byte(len(payload)))
	case len(payload) <= 65535:
		header = append(header, 126, byte(len(payload)>>8), byte(len(payload)))
	default:
		header = append(header, 127)
		var ext [8]byte
		binary.BigEndian.PutUint64(ext[:], uint64(len(payload)))
		header = append(header, ext[:]...)
	}
	if _, err := c.conn.Write(header); err != nil {
		return err
	}
	for len(payload) > 0 {
		n, err := c.conn.Write(payload)
		if err != nil {
			return err
		}
		payload = payload[n:]
	}
	return nil
}

func (c *wsConn) readFrame() (bool, byte, []byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(c.conn, hdr[:]); err != nil {
		return false, 0, nil, err
	}
	fin := hdr[0]&0x80 != 0
	rsv := hdr[0] & 0x70
	opcode := hdr[0] & 0x0F
	if rsv != 0 {
		return false, 0, nil, fmt.Errorf("unsupported WebSocket extensions")
	}
	masked := hdr[1]&0x80 != 0
	if !masked {
		return false, 0, nil, fmt.Errorf("client WebSocket frame is not masked")
	}
	length := uint64(hdr[1] & 0x7F)
	if length == 126 {
		var ext [2]byte
		if _, err := io.ReadFull(c.conn, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = uint64(binary.BigEndian.Uint16(ext[:]))
	} else if length == 127 {
		var ext [8]byte
		if _, err := io.ReadFull(c.conn, ext[:]); err != nil {
			return false, 0, nil, err
		}
		length = binary.BigEndian.Uint64(ext[:])
		if length&(uint64(1)<<63) != 0 {
			return false, 0, nil, fmt.Errorf("invalid WebSocket payload length")
		}
	}
	if opcode >= 0x8 {
		if !fin || length > 125 {
			return false, 0, nil, fmt.Errorf("invalid WebSocket control frame")
		}
	}
	if length > uint64(int(^uint(0)>>1)) {
		return false, 0, nil, fmt.Errorf("WebSocket payload too large")
	}
	var mask [4]byte
	if _, err := io.ReadFull(c.conn, mask[:]); err != nil {
		return false, 0, nil, err
	}
	payload := make([]byte, int(length))
	if _, err := io.ReadFull(c.conn, payload); err != nil {
		return false, 0, nil, err
	}
	for i := range payload {
		payload[i] ^= mask[i%4]
	}
	return fin, opcode, payload, nil
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	ws, err := upgradeWebSocket(w, r)
	if err != nil {
		addLog("❌ [WebSocket升级失败] %s -> %v", r.RemoteAddr, err)
		return
	}

	// 全程序只保留一个用于推送日志/结果的活动前端连接。新页面连接进来时，主动关闭旧连接。
	wsMutex.Lock()
	oldWS := activeWSConn
	activeWSConn = ws
	wsMutex.Unlock()
	if oldWS != nil && oldWS != ws {
		_ = oldWS.Close()
	}

	defer func() {
		_ = ws.Close()
		wsMutex.Lock()
		if activeWSConn == ws {
			activeWSConn = nil
		}
		wsMutex.Unlock()
	}()

	for {
		msg, err := ws.ReadMessage()
		if err != nil {
			break
		}
		var request struct {
			Type string          `json:"type"`
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(msg, &request); err != nil {
			continue
		}

		switch request.Type {
		case "start_task":
			var params struct {
				EnableV4     bool   `json:"enableV4"`
				EnableV6     bool   `json:"enableV6"`
				EnableTCP    bool   `json:"enableTCP"`
				EnableHTTP   bool   `json:"enableHTTP"`
				Threads      int    `json:"threads"`
				PortsStr     string `json:"portsStr"`
				Delay        int    `json:"delay"`
				AllowedColos string `json:"allowedColos"`
				SubnetMode   string `json:"subnetMode"`
			}
			if err := json.Unmarshal(request.Data, &params); err != nil {
				sendWSMessage(ws, "error", "扫描参数解析失败")
				continue
			}
			if params.Threads <= 0 {
				params.Threads = 200
			}
			if params.Threads > 1000 {
				params.Threads = 1000
			}
			go runEnhancedTask(ws, params.EnableV4, params.EnableV6, params.EnableTCP, params.EnableHTTP, params.Threads, params.PortsStr, params.Delay, params.AllowedColos, params.SubnetMode)

		case "stop_task":
			taskMutex.Lock()
			cancel := taskCancel
			taskMutex.Unlock()
			if cancel != nil {
				cancel()
				sendWSMessage(ws, "log", "⏹️ 已请求终止扫描，正在等待当前 TCP 探测安全退出...")
			} else {
				sendWSMessage(ws, "log", "当前没有正在运行的扫描任务")
			}

		case "start_test":
			taskMutex.Lock()
			scanning := isTaskRunning
			taskMutex.Unlock()
			if scanning {
				sendWSMessage(ws, "error", "扫描进行中：详细精测暂时暂停，扫描结束后自动恢复。")
				continue
			}
			var params struct {
				DC    string `json:"dc"`
				Port  int    `json:"port"`
				Delay int    `json:"delay"`
			}
			json.Unmarshal(request.Data, &params)
			go runDetailedTest(ws, params.DC, params.Port, params.Delay)

		case "start_speed_test":
			taskMutex.Lock()
			scanning := isTaskRunning
			taskMutex.Unlock()
			if scanning {
				sendWSMessage(ws, "error", "扫描进行中：手动测速暂时暂停，扫描结束后自动恢复。")
				continue
			}
			var params struct {
				IP   string `json:"ip"`
				Port int    `json:"port"`
			}
			json.Unmarshal(request.Data, &params)
			go runSpeedTest(ws, params.IP, params.Port)
		}
	}
}

func sendPartialSummary(ws *wsConn) {
	scanMutex.Lock()
	defer scanMutex.Unlock()
	if len(scanResults) == 0 {
		return
	}

	dcMap := make(map[string]*DataCenterInfo)
	avgSums := make(map[string]int64)
	for _, res := range scanResults {
		if _, ok := dcMap[res.DataCenter]; !ok {
			dcMap[res.DataCenter] = &DataCenterInfo{
				DataCenter:  res.DataCenter,
				Region:      res.Region,
				City:        res.City,
				IPCount:     0,
				MinLatency:  999999,
				AvgLatency:  999999,
				MinLossRate: 1,
			}
		}
		info := dcMap[res.DataCenter]
		info.IPCount++
		avgMs := int(res.AvgLatency / time.Millisecond)
		minMs := int(res.MinLatency / time.Millisecond)
		if avgMs < info.MinLatency {
			info.MinLatency = avgMs
		}
		if minMs < info.AvgLatency {
			// Keep the historical field meaning simple for the UI: the best observed
			// single-handshake latency inside this colo group.
			info.AvgLatency = minMs
		}
		if res.LossRate < info.MinLossRate {
			info.MinLossRate = res.LossRate
		}
		avgSums[res.DataCenter] += int64(avgMs)
	}
	var dcList []DataCenterInfo
	for colo, info := range dcMap {
		if info.IPCount > 0 {
			info.AvgLatency = int(avgSums[colo] / int64(info.IPCount))
		}
		dcList = append(dcList, *info)
	}
	sort.Slice(dcList, func(i, j int) bool {
		if dcList[i].MinLossRate != dcList[j].MinLossRate {
			return dcList[i].MinLossRate < dcList[j].MinLossRate
		}
		if dcList[i].AvgLatency != dcList[j].AvgLatency {
			return dcList[i].AvgLatency < dcList[j].AvgLatency
		}
		return dcList[i].DataCenter < dcList[j].DataCenter
	})
	sendWSMessage(ws, "scan_complete_wait_dc", dcList)
}

func sendWSMessage(ws *wsConn, msgType string, data interface{}) {
	wsMutex.Lock()
	defer wsMutex.Unlock()
	if ws != nil {
		_ = ws.WriteJSON(map[string]interface{}{
			"type": msgType,
			"data": data,
		})
	}
}

func handlePipeGet(w http.ResponseWriter, r *http.Request) {
	r2View := buildR2View(r2BatchSize * r2NormalBatchRuns)
	pipeLock.Lock()
	defer pipeLock.Unlock()

	syncDomainStatusMapLocked()

	sortCandidates(pool3V4)
	sortCandidates(pool3V6)

	r4V4List := pool4V4Ring.ToList()
	r4V6List := pool4V6Ring.ToList()
	sortCandidates(r4V4List)
	sortCandidates(r4V6List)

	now := time.Now()
	coldList := make([]*ColdIP, 0, len(coldPool))
	for _, c := range coldPool {
		rem := int64(c.ColdUntil.Sub(now).Seconds())
		if rem < 0 {
			rem = 0
		}
		c.RemainingSec = rem
		coldList = append(coldList, c)
	}
	sort.Slice(coldList, func(i, j int) bool {
		return coldList[i].RemainingSec < coldList[j].RemainingSec
	})

	retDayList := make([]*RetiredIP, 0, len(retiredDaytime))
	for _, v := range retiredDaytime {
		retDayList = append(retDayList, v)
	}
	sort.Slice(retDayList, func(i, j int) bool {
		return retDayList[i].RetiredTime.After(retDayList[j].RetiredTime)
	})

	retPeakList := make([]*RetiredIP, 0, len(retiredPeak))
	for _, v := range retiredPeak {
		retPeakList = append(retPeakList, v)
	}
	sort.Slice(retPeakList, func(i, j int) bool {
		return retPeakList[i].RetiredTime.After(retPeakList[j].RetiredTime)
	})

	sealDayList := make([]*CandidateIP, 0, len(sealedDaytime))
	for _, v := range sealedDaytime {
		sealDayList = append(sealDayList, v)
	}
	sortCandidates(sealDayList)

	sealPeakList := make([]*CandidateIP, 0, len(sealedPeak))
	for _, v := range sealedPeak {
		sealPeakList = append(sealPeakList, v)
	}
	sortCandidates(sealPeakList)

	statList := make([]*SubdomainStatus, 0, len(domainStatus))
	for _, v := range domainStatus {
		if v.CurrentIP != "" {
			if _, has := profileStore[v.CurrentIP]; !has {
				ver := IPv4
				if v.Type == "AAAA" || isIPv6(v.CurrentIP) {
					ver = IPv6
				}
				profileStore[v.CurrentIP] = buildNodeProfile(v.CurrentIP, ver, v.CurrentSpeed, 50, 443, "")
			}
			v.Profile = profileStore[v.CurrentIP]
		}
		statList = append(statList, v)
	}
	sort.Slice(statList, func(i, j int) bool {
		if statList[i].Type != statList[j].Type {
			return statList[i].Type < statList[j].Type
		}
		return statList[i].Rank < statList[j].Rank
	})

	logLock.Lock()
	logSnapshot := make([]string, len(logs))
	copy(logSnapshot, logs)
	logLock.Unlock()

	blacklistLock.RLock()
	bCount := len(lowSpeedBlacklist)
	blacklistLock.RUnlock()

	p2V4 := countR2EligibleLocked(IPv4)
	p2V6 := countR2EligibleLocked(IPv6)

	curPeriod := getCurrentPeriodTag()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"config":          pipeCfg,
		"domain_status":   statList,
		"pool2":           r2View, // 兼容旧前端字段名；实际内容来自精测榜直接候选，不是独立R2池。
		"pool2_count":     p2V4 + p2V6,
		"pool2_v4_count":  p2V4,
		"pool2_v6_count":  p2V6,
		"r2_mode":         pipeCfg.R2Mode,
		"r2_manual_colos": pipeCfg.R2ManualColos,
		"r2_per_region":   r2PerRegionBatch,
		"pool3_v4":        pool3V4,
		"pool3_v6":        pool3V6,
		"pool4_v4":        r4V4List,
		"pool4_v6":        r4V6List,
		"cold_pool":       coldList,
		"retired_daytime": retDayList,
		"retired_peak":    retPeakList,
		"sealed_daytime":  sealDayList,
		"sealed_peak":     sealPeakList,
		"current_period":  curPeriod,
		"profiles":        profileStore,
		"logs":            logSnapshot,
		"local_city":      localDetectedCity,
		"local_region":    localDetectedRegion,
		"local_isp":       localDetectedISP,
		"local_geo_ready": localGeoReady,
		"blacklist_count": bCount,
	})
}

func handleToggleNodeLock(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	pipeLock.Lock()
	defer pipeLock.Unlock()

	p, exists := profileStore[ip]
	if !exists {
		http.Error(w, "未找到该节点数字画像", 404)
		return
	}
	p.IsLocked = !p.IsLocked
	statusText := "已授予免死金牌 🛡️"
	if !p.IsLocked {
		statusText = "已取消免死金牌"
	}
	addLog("节点 %s %s", ip, statusText)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "locked": p.IsLocked})
}

func handleDemoteNodeToR3(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	pipeLock.Lock()
	defer pipeLock.Unlock()

	pool4V4Ring.Remove(ip)
	pool4V6Ring.Remove(ip)
	delete(retiredDaytime, ip)
	delete(retiredPeak, ip)

	ver := IPv4
	if isIPv6(ip) {
		ver = IPv6
		pool3V6 = append(pool3V6, &CandidateIP{IP: ip, Port: 443, Version: ver, Speed: 16.0, Delay: 60, ChallengeCount: 0, LastCheck: time.Now(), Status: "↩️ 回流3轮打磨"})
	} else {
		pool3V4 = append(pool3V4, &CandidateIP{IP: ip, Port: 443, Version: ver, Speed: 16.0, Delay: 60, ChallengeCount: 0, LastCheck: time.Now(), Status: "↩️ 回流3轮打磨"})
	}

	saveCacheFiles()
	addLog("↩️ 节点 %s 已送回第 3 轮战备水库重新打磨！", ip)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handlePhysicalDeleteNode(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	pipeLock.Lock()
	defer pipeLock.Unlock()

	delete(pool2, ip)
	delete(r2Eligible, ip)
	delete(r2ZeroStreak, ip)
	delete(r2HistorySpeed, ip)
	delete(r2RetryAfter, ip)
	removeCandidateFromSlice(&pool3V4, ip)
	removeCandidateFromSlice(&pool3V6, ip)
	pool4V4Ring.Remove(ip)
	pool4V6Ring.Remove(ip)
	delete(coldPool, ip)
	delete(retiredDaytime, ip)
	delete(retiredPeak, ip)
	delete(sealedDaytime, ip)
	delete(sealedPeak, ip)
	delete(profileStore, ip)
	addToBlacklist(ip)

	saveCacheFiles()
	addLog("🗑️ [物理删除] 节点 %s 及其身份证已彻底销毁并拉入永久黑名单！", ip)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handleUnfreezeColdIP(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	pipeLock.Lock()
	defer pipeLock.Unlock()

	c, ok := coldPool[ip]
	if !ok {
		http.Error(w, "不在冷宫中", 404)
		return
	}
	delete(coldPool, ip)

	cand := &CandidateIP{
		IP:             c.IP,
		Port:           c.Port,
		Version:        c.Version,
		Colo:           c.Colo,
		Delay:          c.LastDelay,
		Speed:          c.LastSpeed,
		ChallengeCount: 0,
		Status:         "⏳ 冷宫特赦·重返3轮备战",
		LastCheck:      time.Now(),
	}

	if c.Version == IPv6 || isIPv6(c.IP) {
		pool3V6 = append(pool3V6, cand)
	} else {
		pool3V4 = append(pool3V4, cand)
	}

	saveCacheFiles()
	addLog("⚡ [冷宫特赦] 节点 %s 挑战次数归零，直接重返 R3 战备水库！", ip)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handleDeleteColdIP(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	pipeLock.Lock()
	delete(coldPool, ip)
	delete(profileStore, ip)
	addToBlacklist(ip)
	saveCacheFiles()
	addLog("🗑️ [冷宫处决] 节点 %s 已抹除！", ip)
	pipeLock.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handleClearRetiredPool(w http.ResponseWriter, r *http.Request) {
	pipeLock.Lock()
	defer pipeLock.Unlock()

	for k := range retiredDaytime {
		delete(profileStore, k)
	}
	for k := range retiredPeak {
		delete(profileStore, k)
	}
	retiredDaytime = make(map[string]*RetiredIP)
	retiredPeak = make(map[string]*RetiredIP)
	saveCacheFiles()
	addLog("💥 [退役阁清空] 已清空昼夜两大历史退役功勋阁！")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handleClearAll(w http.ResponseWriter, r *http.Request) {
	pipeLock.Lock()
	defer pipeLock.Unlock()

	pool2 = make(map[string]*CandidateIP)
	r2Eligible = make(map[string]struct{})
	r2RegionCursor = 0
	r2ZeroStreak = make(map[string]int)
	r2HistorySpeed = make(map[string]float64)
	r2RetryAfter = make(map[string]time.Time)
	pool3V4 = make([]*CandidateIP, 0)
	pool3V6 = make([]*CandidateIP, 0)
	pool4V4Ring = RingBuffer100{}
	pool4V6Ring = RingBuffer100{}
	coldPool = make(map[string]*ColdIP)

	keepIPs := make(map[string]bool)
	for _, stat := range domainStatus {
		if stat.CurrentIP != "" {
			keepIPs[stat.CurrentIP] = true
		}
	}
	for ip := range retiredDaytime {
		keepIPs[ip] = true
	}
	for ip := range retiredPeak {
		keepIPs[ip] = true
	}
	for ip := range sealedDaytime {
		keepIPs[ip] = true
	}
	for ip := range sealedPeak {
		keepIPs[ip] = true
	}

	for ip := range profileStore {
		if !keepIPs[ip] {
			delete(profileStore, ip)
		}
	}

	saveCacheFiles()
	addLog("🧹 [一键全清] 已清空海选与水库！(在位真皇、退役阁与休眠封存舱绝对保护)")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handleAddSubdomain(w http.ResponseWriter, r *http.Request) {
	sub := strings.TrimSpace(r.URL.Query().Get("sub"))
	rawType := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("type")))
	mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))

	recType := "A"
	if rawType == "AAAA" || strings.Contains(rawType, "V6") {
		recType = "AAAA"
	}

	if sub == "" {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"success": false, "message": "子域名前缀不能为空！"})
		return
	}
	if mode != "manual" {
		mode = "auto"
	}

	pipeLock.Lock()

	for _, s := range pipeCfg.Subdomains {
		if strings.EqualFold(s.Subdomain, sub) && s.Type == recType {
			pipeLock.Unlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": fmt.Sprintf("子域名 [%s] 已经存在！", sub),
			})
			return
		}
	}

	pipeCfg.Subdomains = append(pipeCfg.Subdomains, SubdomainConfig{
		Subdomain: sub,
		Type:      recType,
		Mode:      mode,
	})
	autoSync := pipeCfg.Enabled && mode == "auto"
	savePipelineConfig()
	syncDomainStatusMapLocked()
	saveCacheFiles()
	addLog("已成功添加新子域名: %s (%s, 模式: %s)", sub, recType, mode)

	pipeLock.Unlock()
	if autoSync {
		go debounceSyncDNS()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("子域名 [%s] 开辟成功！", sub),
	})
}

func handleDeleteSubdomain(w http.ResponseWriter, r *http.Request) {
	sub := strings.TrimSpace(r.URL.Query().Get("sub"))
	rawType := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("type")))
	recType := "A"
	if rawType == "AAAA" || strings.Contains(rawType, "V6") {
		recType = "AAAA"
	}

	pipeLock.Lock()
	var newList []SubdomainConfig
	for _, s := range pipeCfg.Subdomains {
		if !(strings.EqualFold(s.Subdomain, sub) && (rawType == "" || s.Type == recType)) {
			newList = append(newList, s)
		}
	}
	pipeCfg.Subdomains = newList
	savePipelineConfig()
	syncDomainStatusMapLocked()
	saveCacheFiles()
	addLog("已移除子域名赛道: %s", sub)
	pipeLock.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handleSetSubdomainMode(w http.ResponseWriter, r *http.Request) {
	sub := strings.TrimSpace(r.URL.Query().Get("sub"))
	rawType := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("type")))
	mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))

	recType := "A"
	if rawType == "AAAA" || strings.Contains(rawType, "V6") {
		recType = "AAAA"
	}

	pipeLock.Lock()
	for i := range pipeCfg.Subdomains {
		if strings.EqualFold(pipeCfg.Subdomains[i].Subdomain, sub) && pipeCfg.Subdomains[i].Type == recType {
			pipeCfg.Subdomains[i].Mode = mode
			break
		}
	}
	key := fmt.Sprintf("%s_%s", sub, recType)
	stat, ok := domainStatus[key]

	if mode == "auto" && ok && stat.CurrentIP != "" {
		curTag := getCurrentPeriodTag()
		retItem := &RetiredIP{
			IP:          stat.CurrentIP,
			Port:        443,
			Version:     IPVersion(recType),
			Colo:        "CF",
			LastSpeed:   stat.CurrentSpeed,
			LastDelay:   50,
			RetiredTime: time.Now(),
			OrigDomain:  sub,
			PeriodTag:   curTag,
			Status:      fmt.Sprintf("%s 恢复自动退役", sub),
			Profile:     profileStore[stat.CurrentIP],
		}
		if curTag == "peak" {
			retiredPeak[stat.CurrentIP] = retItem
		} else {
			retiredDaytime[stat.CurrentIP] = retItem
		}
		stat.CurrentIP = ""
		stat.CurrentSpeed = 0
		stat.LastUpTime = time.Time{}
		stat.Profile = nil
	}

	autoSync := pipeCfg.Enabled && mode == "auto"
	savePipelineConfig()
	syncDomainStatusMapLocked()
	saveCacheFiles()
	addLog("子域名 %s 模式切换为: %s", sub, mode)
	pipeLock.Unlock()
	if autoSync {
		go debounceSyncDNS()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handlePinIPToSubdomain(w http.ResponseWriter, r *http.Request) {
	sub := strings.TrimSpace(r.URL.Query().Get("sub"))
	rawType := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("type")))
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))

	recType := "A"
	if rawType == "AAAA" || strings.Contains(rawType, "V6") || isIPv6(ip) {
		recType = "AAAA"
	}

	pipeLock.Lock()
	defer pipeLock.Unlock()

	fullDomain := fmt.Sprintf("%s.%s", sub, pipeCfg.RootDomain)

	conflictType := "AAAA"
	if recType == "AAAA" {
		conflictType = "A"
	}
	_ = cleanConflictingRecord(pipeCfg.ApiToken, pipeCfg.ZoneID, fullDomain, conflictType)

	err := updateCloudflareDNS(pipeCfg.ApiToken, pipeCfg.ZoneID, fullDomain, recType, ip)
	if err != nil {
		addLog("❌ 手动指定上位失败: %v", err)
		http.Error(w, err.Error(), 500)
		return
	}

	key := fmt.Sprintf("%s_%s", sub, recType)
	stat, ok := domainStatus[key]
	if !ok {
		stat = &SubdomainStatus{
			Subdomain:  sub,
			FullDomain: fullDomain,
			Type:       recType,
			Mode:       "manual",
			Status:     "就绪",
		}
		domainStatus[key] = stat
	}

	if stat.CurrentIP != "" && stat.CurrentIP != ip {
		curTag := getCurrentPeriodTag()
		retItem := &RetiredIP{
			IP:          stat.CurrentIP,
			Port:        443,
			Version:     IPVersion(recType),
			Colo:        "CF",
			LastSpeed:   stat.CurrentSpeed,
			LastDelay:   50,
			RetiredTime: time.Now(),
			OrigDomain:  sub,
			PeriodTag:   curTag,
			Status:      fmt.Sprintf("%s 手动换下", sub),
			Profile:     profileStore[stat.CurrentIP],
		}
		if curTag == "peak" {
			retiredPeak[stat.CurrentIP] = retItem
		} else {
			retiredDaytime[stat.CurrentIP] = retItem
		}
		addLog("📦 前任节点 (%s) 沉淀入【%s退役阁】", stat.CurrentIP, map[string]string{"peak": "晚高峰", "daytime": "白天"}[curTag])
	}

	for i := range pipeCfg.Subdomains {
		if strings.EqualFold(pipeCfg.Subdomains[i].Subdomain, sub) && pipeCfg.Subdomains[i].Type == recType {
			pipeCfg.Subdomains[i].Mode = "manual"
			break
		}
	}

	stat.CurrentIP = ip
	stat.CurrentSpeed = 32.0
	stat.Mode = "manual"
	stat.LastUpTime = time.Now()
	syncDomainStatusMapLocked()

	if _, has := profileStore[ip]; !has {
		ver := IPv4
		if isIPv6(ip) {
			ver = IPv6
		}
		profileStore[ip] = buildNodeProfile(ip, ver, 32.0, 50, 443, "")
	}
	prof := profileStore[ip]
	prof.CurrentRole = "emperor"
	prof.BoundDomain = fullDomain
	stat.Profile = prof

	pool4V4Ring.Remove(ip)
	pool4V6Ring.Remove(ip)
	delete(r2Eligible, ip)
	delete(r2ZeroStreak, ip)
	delete(r2HistorySpeed, ip)
	delete(r2RetryAfter, ip)
	delete(retiredDaytime, ip)
	delete(retiredPeak, ip)

	savePipelineConfig()
	saveCacheFiles()
	addLog("👑 [手动指定登基] %s -> %s (已锁定专线)", fullDomain, ip)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handleRetiredToPool3(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	pipeLock.Lock()
	defer pipeLock.Unlock()

	ret, exists := retiredDaytime[ip]
	if !exists {
		ret, exists = retiredPeak[ip]
	}
	if !exists {
		http.Error(w, "未找到该退役节点", 404)
		return
	}

	delete(retiredDaytime, ip)
	delete(retiredPeak, ip)

	ver := IPv4
	if isIPv6(ret.IP) {
		ver = IPv6
	}

	cand := &CandidateIP{
		IP:             ret.IP,
		Port:           ret.Port,
		Version:        ver,
		Colo:           ret.Colo,
		Delay:          ret.LastDelay,
		Speed:          ret.LastSpeed,
		HistorySpeed:   ret.LastSpeed,
		ChallengeCount: 0,
		Status:         fmt.Sprintf("🔥 擂台复活 (%.2f MB/s)", ret.LastSpeed/8.0),
		LastCheck:      time.Now(),
	}

	if ver == IPv6 {
		pool3V6 = append(pool3V6, cand)
	} else {
		pool3V4 = append(pool3V4, cand)
	}

	saveCacheFiles()
	addLog("🔥 备用退役老将 %s 已送回第 3 轮军机水库！", ip)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handleDeleteRetired(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	pipeLock.Lock()
	delete(retiredDaytime, ip)
	delete(retiredPeak, ip)
	delete(profileStore, ip)
	addToBlacklist(ip)
	saveCacheFiles()
	addLog("彻底删除退役节点档案: %s", ip)
	pipeLock.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handlePipeSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var req PipelineConfig
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}

	pipeLock.Lock()
	if req.MinSpeedMB <= 0 {
		req.MinSpeedMB = 1.0
	}
	if req.PeakStartHour == 0 && req.PeakEndHour == 0 {
		req.PeakStartHour = 19
		req.PeakEndHour = 24
	}
	if req.R2Mode == "" {
		req.R2Mode = pipeCfg.R2Mode
	}
	if req.R2Mode != "manual" {
		req.R2Mode = "auto"
	}
	if req.R2ManualColos == nil {
		req.R2ManualColos = append([]string(nil), pipeCfg.R2ManualColos...)
	}
	req.R2PerRegion = r2PerRegionBatch
	req.Subdomains = pipeCfg.Subdomains
	pipeCfg = req
	savePipelineConfig()
	syncDomainStatusMapLocked()
	saveCacheFiles()

	if pipeStop != nil {
		close(pipeStop)
		pipeStop = nil
	}
	if pipeCfg.Enabled {
		pipeStop = make(chan struct{})
		go runSymmetricClockEngine(pipeStop)
		addLog("🚀 全自动自适应争霸夺位引擎已启动！")
	} else {
		addLog("⏸️ 全自动争霸引擎已挂起暂停")
	}
	pipeLock.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

func handleR2ConfigSave(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}
	var req struct {
		Mode        string   `json:"mode"`
		ManualColos []string `json:"manual_colos"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	mode := strings.ToLower(strings.TrimSpace(req.Mode))
	if mode != "manual" {
		mode = "auto"
	}
	seen := make(map[string]struct{})
	colos := make([]string, 0, len(req.ManualColos))
	for _, c := range req.ManualColos {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}
		colos = append(colos, c)
	}
	pipeLock.Lock()
	pipeCfg.R2Mode = mode
	pipeCfg.R2ManualColos = colos
	pipeCfg.R2PerRegion = r2PerRegionBatch
	savePipelineConfig()
	pipeLock.Unlock()
	if mode == "manual" && len(colos) == 0 {
		addLog("🧭 [R2地区接入] 手动模式未勾选地区，自动回落为全地区自动轮转。")
	} else if mode == "manual" {
		addLog("🧭 [R2地区接入] 已切换手动地区：%s；每地区固定%d个/轮。", strings.Join(colos, ","), r2PerRegionBatch)
	} else {
		addLog("🧭 [R2地区接入] 已切回自动：精测榜全部地区参与，每地区固定%d个/轮。", r2PerRegionBatch)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"mode":         mode,
		"manual_colos": colos,
		"per_region":   r2PerRegionBatch,
	})
}

func handlePipeSyncNow(w http.ResponseWriter, r *http.Request) {
	addLog("收到手动【即刻登基】指令：触发全级穿透推举登基...")
	go debounceSyncDNS()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{"success": true})
}

// handleResetR3Benchmark 手动清空当前 IPv4/IPv6 的 R3.5 上位门槛。
// 下一个 R3.5 周期会按现有白天/高峰规则重新建立基准，不改变候选池、R4、域名绑定等其它状态。
func handleResetR3Benchmark(w http.ResponseWriter, r *http.Request) {
	target := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("type")))
	if target != "A" && target != "AAAA" && target != "ALL" && target != "" {
		target = "ALL"
	}

	pipeLock.Lock()
	switch target {
	case "A":
		r3BenchmarkV4 = 0
		r3BenchmarkTimeV4 = time.Time{}
	case "AAAA":
		r3BenchmarkV6 = 0
		r3BenchmarkTimeV6 = time.Time{}
	default:
		r3BenchmarkV4 = 0
		r3BenchmarkTimeV4 = time.Time{}
		r3BenchmarkV6 = 0
		r3BenchmarkTimeV6 = time.Time{}
	}
	pipeLock.Unlock()

	label := "IPv4 / IPv6"
	if target == "A" {
		label = "IPv4"
	} else if target == "AAAA" {
		label = "IPv6"
	}
	addLog("🔄 [手动刷新门槛] %s 赛道 R3.5 上位基准已清空，下一轮将重新建立门槛。", label)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"type":    target,
		"message": fmt.Sprintf("%s 上位门槛已清空，下一轮对应赛道的 R3.5 将重新建立基准。", label),
	})
}

func handleFetchZones(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		http.Error(w, "missing token", 400)
		return
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "https://api.cloudflare.com/client/v4/zones?status=active&per_page=50", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var res struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
		Result []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"result"`
	}
	_ = json.Unmarshal(body, &res)

	if !res.Success {
		errMsg := "Token 权限不足"
		if len(res.Errors) > 0 {
			errMsg = res.Errors[0].Message
		}
		addLog("拉取根域名失败: %s", errMsg)
	} else {
		addLog("成功拉取到 %d 个根域名", len(res.Result))
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res.Result)
}

func handlePeriodTransitionCheck() {
	pipeLock.Lock()
	defer pipeLock.Unlock()

	currentPeriod := getCurrentPeriodTag()
	if currentPeriod == lastRecordedPeriod {
		return
	}

	addLog("🌅 [时空流转] 监测到时段切换: %s ➔ %s！启动时空封存休眠舱轮换...", lastRecordedPeriod, currentPeriod)

	if currentPeriod == "peak" {
		v4List := pool4V4Ring.ClearAndExtract()
		for _, v := range v4List {
			v.Status = "❄️ 白天封存休眠中"
			sealedDaytime[v.IP] = v
		}
		v6List := pool4V6Ring.ClearAndExtract()
		for _, v := range v6List {
			v.Status = "❄️ 白天封存休眠中"
			sealedDaytime[v.IP] = v
		}
		addLog("❄️ [时空封存] 已将白天 R4 优质待命节点 (%d 个 IPv4, %d 个 IPv6) 封存保护！", len(v4List), len(v6List))

		for ip, v := range sealedPeak {
			delete(sealedPeak, ip)
			v.Status = "⚡ 高峰解冻参战"
			v.ChallengeCount = 0
			if v.Version == IPv6 || isIPv6(v.IP) {
				pool3V6 = append(pool3V6, v)
			} else {
				pool3V4 = append(pool3V4, v)
			}
		}

		r3BenchmarkV4 = 0
		r3BenchmarkV6 = 0
	} else {
		v4List := pool4V4Ring.ClearAndExtract()
		for _, v := range v4List {
			v.Status = "⚡ 高峰封存休眠中"
			sealedPeak[v.IP] = v
		}
		v6List := pool4V6Ring.ClearAndExtract()
		for _, v := range v6List {
			v.Status = "⚡ 高峰封存休眠中"
			sealedPeak[v.IP] = v
		}
		addLog("⚡ [时空封存] 已将晚高峰 R4 节点 (%d 个 IPv4, %d 个 IPv6) 封存保护！", len(v4List), len(v6List))

		for ip, v := range sealedDaytime {
			delete(sealedDaytime, ip)
			v.Status = "☀️ 白天解冻入R3"
			v.ChallengeCount = 0
			if v.Version == IPv6 || isIPv6(v.IP) {
				pool3V6 = append(pool3V6, v)
			} else {
				pool3V4 = append(pool3V4, v)
			}
		}
		addLog("☀️ [时空苏醒] 已将白天封存节点全部苏醒放回 R3 战备水库！")
	}

	lastRecordedPeriod = currentPeriod
	saveCacheFiles()
}

const (
	r2LowWater         = 50
	r2HighWater        = 100
	r2BatchSize        = 5
	r2NormalBatchRuns  = 10
	r2PerRegionBatch   = 2
	scanProbeCount     = 4
	scanLossCutoff     = 0.60
	scanDialTimeout    = 1 * time.Second
	scanBatchSize      = 50
	scanTraceBatchSize = 50
	scanTraceWorkers   = 64
	scanTraceTimeout   = 800 * time.Millisecond
)

func acquireSpeedBus(owner string) {
	speedBus <- struct{}{}
	addLog("🚦 [测速总线] %s 获得独享总线，其它测速轮次暂停。", owner)
}

func releaseSpeedBus(owner string) {
	<-speedBus
	addLog("🟢 [测速总线] %s 已完成并交还总线。", owner)
}

func countR2EligibleLocked(ver IPVersion) int {
	count := 0
	for ip := range r2Eligible {
		candidateVer := IPv4
		if isIPv6(ip) {
			candidateVer = IPv6
		}
		if candidateVer == ver {
			count++
		}
	}
	return count
}

func scanResultLess(a, b ScanResult) bool {
	if a.LossRate != b.LossRate {
		return a.LossRate < b.LossRate
	}
	if a.MinLatency != b.MinLatency {
		return a.MinLatency < b.MinLatency
	}
	if a.AvgLatency != b.AvgLatency {
		return a.AvgLatency < b.AvgLatency
	}
	if a.MaxLatency != b.MaxLatency {
		return a.MaxLatency < b.MaxLatency
	}
	return a.IP < b.IP
}

func r2ManualColoSetLocked() map[string]struct{} {
	set := make(map[string]struct{}, len(pipeCfg.R2ManualColos))
	for _, colo := range pipeCfg.R2ManualColos {
		colo = strings.ToUpper(strings.TrimSpace(colo))
		if colo != "" {
			set[colo] = struct{}{}
		}
	}
	return set
}

func r2ColoAllowedLocked(colo string, manualSet map[string]struct{}) bool {
	if pipeCfg.R2Mode != "manual" || len(manualSet) == 0 {
		return true
	}
	_, ok := manualSet[strings.ToUpper(strings.TrimSpace(colo))]
	return ok
}

func snapshotScanResults() []ScanResult {
	scanMutex.Lock()
	defer scanMutex.Unlock()
	out := make([]ScanResult, len(scanResults))
	copy(out, scanResults)
	return out
}

func advanceScanRotationEpoch() {
	scanRotationLock.Lock()
	scanRotationEpoch++
	epoch := scanRotationEpoch
	scanRotationLock.Unlock()
	_ = saveToFile("scan_rotation.json", fmt.Sprintf(`{"epoch":%d}`, epoch))
}

func currentScanRotationEpoch() uint64 {
	scanRotationLock.Lock()
	defer scanRotationLock.Unlock()
	return scanRotationEpoch
}

func loadScanRotationState() {
	b, err := os.ReadFile("scan_rotation.json")
	if err != nil {
		return
	}
	var st struct {
		Epoch uint64 `json:"epoch"`
	}
	if json.Unmarshal(b, &st) == nil {
		scanRotationLock.Lock()
		scanRotationEpoch = st.Epoch
		scanRotationLock.Unlock()
	}
}

func rotationParts(mode string) (parts int, ok bool) {
	switch mode {
	case "rotate2":
		return 2, true
	case "rotate3":
		return 3, true
	case "rotate4":
		return 4, true
	case "rotate5":
		return 5, true
	default:
		return 0, false
	}
}

func deterministicIPv4Samples(baseIP string, total int) []string {
	if total <= 0 {
		return nil
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte("cfdata-v5|" + baseIP))
	r := rand.New(rand.NewSource(int64(h.Sum64() & uint64(math.MaxInt64))))
	octets := strings.Split(baseIP, ".")
	if len(octets) != 4 {
		return nil
	}
	seen := make(map[string]struct{}, total)
	out := make([]string, 0, total)
	for len(out) < total {
		cSeg := r.Intn(250) + 1
		dHost := r.Intn(254) + 1
		ip := fmt.Sprintf("%s.%s.%d.%d", octets[0], octets[1], cSeg, dHost)
		if _, exists := seen[ip]; exists {
			continue
		}
		seen[ip] = struct{}{}
		out = append(out, ip)
	}
	return out
}

func buildR2Schedule(ver *IPVersion, limit int, advanceCursor bool) []*CandidateIP {
	if limit <= 0 {
		return nil
	}
	// R2 只消费扫描阶段已经完成 CF Trace 分类的候选，不负责地区识别。
	results := snapshotScanResults()
	if len(results) == 0 {
		return nil
	}

	pipeLock.Lock()
	defer pipeLock.Unlock()

	manualSet := r2ManualColoSetLocked()
	groups := make(map[string][]ScanResult)
	seenIP := make(map[string]struct{})
	now := time.Now()

	for _, res := range results {
		if _, seen := seenIP[res.IP]; seen {
			continue
		}
		candidateVer := IPv4
		if isIPv6(res.IP) {
			candidateVer = IPv6
		}
		if ver != nil && candidateVer != *ver {
			continue
		}
		if _, ok := r2Eligible[res.IP]; !ok {
			continue
		}
		if res.LossRate >= scanLossCutoff || isBlacklisted(res.IP) {
			continue
		}
		if strings.TrimSpace(res.DataCenter) == "" {
			// 未完成 CF Trace 分类的节点不得进入 R2。
			continue
		}
		if !r2ColoAllowedLocked(res.DataCenter, manualSet) {
			continue
		}
		if !isColoMatched(res.DataCenter, pipeCfg.AllowedColos) {
			continue
		}
		if due, ok := r2RetryAfter[res.IP]; ok && now.Before(due) {
			continue
		}
		if isIPAlreadyInPipeline(res.IP) {
			delete(r2Eligible, res.IP)
			continue
		}

		seenIP[res.IP] = struct{}{}
		groups[res.DataCenter] = append(groups[res.DataCenter], res)
	}

	regions := make([]string, 0, len(groups))
	for region := range groups {
		regions = append(regions, region)
		list := groups[region]
		sort.Slice(list, func(i, j int) bool { return scanResultLess(list[i], list[j]) })
		groups[region] = list
	}
	sort.Strings(regions)
	if len(regions) == 0 {
		return nil
	}

	start := r2RegionCursor % len(regions)
	selected := make([]*CandidateIP, 0, limit)
	perRegion := r2PerRegionBatch
	if perRegion <= 0 {
		perRegion = 2
	}

	for depth := 0; len(selected) < limit; depth++ {
		addedThisRound := 0
		for offset := 0; offset < len(regions) && len(selected) < limit; offset++ {
			region := regions[(start+offset)%len(regions)]
			list := groups[region]
			from := depth * perRegion
			if from >= len(list) {
				continue
			}
			to := from + perRegion
			if to > len(list) {
				to = len(list)
			}
			for _, res := range list[from:to] {
				candidateVer := IPv4
				if isIPv6(res.IP) {
					candidateVer = IPv6
				}
				history := r2HistorySpeed[res.IP]
				if history <= 0 {
					history = 8.0
				}
				selected = append(selected, &CandidateIP{
					IP: res.IP, Port: res.Port, Version: candidateVer, Colo: res.DataCenter,
					Country: res.Country, Region: res.Region, City: res.City, Method: res.Method,
					Delay: int(res.AvgLatency.Milliseconds()), HistorySpeed: history,
					ZeroStreak: r2ZeroStreak[res.IP], LastCheck: time.Now(),
					Status: fmt.Sprintf("⏳ R2直接接入 · %s · 丢包 %.0f%% · 平均 %dms", res.DataCenter, res.LossRate*100, int(res.AvgLatency/time.Millisecond)),
				})
				addedThisRound++
				if len(selected) >= limit {
					break
				}
			}
		}
		if addedThisRound == 0 {
			break
		}
	}

	if advanceCursor {
		covered := 0
		seenRegions := make(map[string]struct{})
		for _, c := range selected {
			if c == nil || c.Colo == "" {
				continue
			}
			if _, ok := seenRegions[c.Colo]; ok {
				continue
			}
			seenRegions[c.Colo] = struct{}{}
			covered++
		}
		if covered <= 0 {
			covered = 1
		}
		if covered < len(regions) {
			r2RegionCursor = (start + covered) % len(regions)
		} else {
			r2RegionCursor = (start + 1) % len(regions)
		}
	}

	return selected
}

func buildR2View(limit int) []*CandidateIP {
	return buildR2Schedule(nil, limit, false)
}

func executeR2Candidate(cand *CandidateIP) {
	if cand == nil || strings.TrimSpace(cand.Colo) == "" {
		addLog("⚠️ [R2拒绝未分类候选] 节点 %s 未完成扫描阶段 CF Trace 分类，跳过 R2 测速。", func() string {
			if cand == nil {
				return "<nil>"
			}
			return cand.IP
		}())
		return
	}
	// R2 只负责精测、熔断和晋升，不负责 CF Trace / 地区识别。
	pipeLock.Lock()
	delete(r2Eligible, cand.IP)
	minSpeedMB := pipeCfg.MinSpeedMB
	if minSpeedMB <= 0 {
		minSpeedMB = 1.0
	}
	r4CountV4, r4CountV6 := pool4V4Ring.Count(), pool4V6Ring.Count()
	allowedColos := pipeCfg.AllowedColos
	oldHistory := r2HistorySpeed[cand.IP]
	if oldHistory <= 0 {
		oldHistory = cand.HistorySpeed
		if oldHistory <= 0 {
			oldHistory = 8.0
		}
	}
	zeroStreak := r2ZeroStreak[cand.IP]
	pipeLock.Unlock()

	spd, reason := httpSpeedTestDirect(cand.IP, cand.Port, 5*time.Second)

	pipeLock.Lock()
	cand.LastCheck = time.Now()
	r2RetryAfter[cand.IP] = cand.LastCheck.Add(30 * time.Second)
	if spd <= 0 {
		if reason != "" {
			addLog("⚠️ [R2测速失败] 节点 %s：%s（本次按0速计入熔断计数）", cand.IP, reason)
		}
		zeroStreak++
		r2ZeroStreak[cand.IP] = zeroStreak
		r2HistorySpeed[cand.IP] = oldHistory
		cand.ZeroStreak = zeroStreak
		if zeroStreak < 2 {
			cand.Speed = 0
			cand.HistorySpeed = oldHistory
			cand.Status = fmt.Sprintf("⚠️ 首次0速免死 (%d/2)，保留历史战力", zeroStreak)
			r2Eligible[cand.IP] = struct{}{}
			pipeLock.Unlock()
			return
		}
		delete(r2ZeroStreak, cand.IP)
		delete(r2HistorySpeed, cand.IP)
		delete(r2RetryAfter, cand.IP)
		addToBlacklist(cand.IP)
		addLog("☠️ [连续0速死刑] R2 节点 %s 连续 2 次为0，直接熔断拉黑！", cand.IP)
		pipeLock.Unlock()
		return
	}

	cand.Speed, cand.HistorySpeed, cand.ZeroStreak = spd, spd, 0
	delete(r2ZeroStreak, cand.IP)
	delete(r2HistorySpeed, cand.IP)
	delete(r2RetryAfter, cand.IP)
	if spd < minSpeedMB*8.0 {
		addToBlacklist(cand.IP)
		addLog("🗑️ [R2低速淘汰] 节点 %s 实测 %.2f MB/s，低于基础门槛 %.2f MB/s。", cand.IP, spd/8.0, minSpeedMB)
		pipeLock.Unlock()
		return
	}
	if allowedColos != "" && cand.Colo != "" && !isColoMatched(cand.Colo, allowedColos) {
		cand.Status = "⛔ 机房过滤淘汰"
		pipeLock.Unlock()
		return
	}
	cand.Status = fmt.Sprintf("✅ 达标 (%.2f MB/s)", spd/8.0)
	if cand.Version == IPv6 || isIPv6(cand.IP) {
		cand.Version = IPv6
		if r4CountV6 < 5 {
			prof := buildNodeProfile(cand.IP, IPv6, cand.Speed, cand.Delay, cand.Port, cand.Colo)
			cand.Profile = prof
			profileStore[cand.IP] = prof
			pool4V6Ring.Insert(cand)
			addLog("⚡ [R2直通保送] IPv6 待命紧缺，节点 %s (%.2f MB/s) 直通 R4！", cand.IP, spd/8.0)
		} else {
			pool3V6 = append(pool3V6, cand)
			addLog("🚀 [R2晋升] IPv6 节点 %s 实测 %.2f MB/s 灌入 R3 水库！", cand.IP, spd/8.0)
		}
	} else {
		cand.Version = IPv4
		if r4CountV4 < 5 {
			prof := buildNodeProfile(cand.IP, IPv4, cand.Speed, cand.Delay, cand.Port, cand.Colo)
			cand.Profile = prof
			profileStore[cand.IP] = prof
			pool4V4Ring.Insert(cand)
			addLog("⚡ [R2直通保送] IPv4 待命紧缺，节点 %s (%.2f MB/s) 直通 R4！", cand.IP, spd/8.0)
		} else {
			pool3V4 = append(pool3V4, cand)
			addLog("🚀 [R2晋升] IPv4 节点 %s 实测 %.2f MB/s 灌入 R3 水库！", cand.IP, spd/8.0)
		}
	}
	pipeLock.Unlock()
}

func chooseR2RefillTargetLocked() (IPVersion, bool) {
	countV4, countV6 := len(pool3V4), len(pool3V6)
	if countV4 >= r2LowWater && countV6 >= r2LowWater {
		return IPv4, false
	}
	if countV4 < r2LowWater && countV6 >= r2LowWater {
		return IPv4, true
	}
	if countV6 < r2LowWater && countV4 >= r2LowWater {
		return IPv6, true
	}
	if countV4 <= countV6 {
		return IPv4, true
	}
	return IPv6, true
}

func executeR2IngestionCycle() {
	acquireSpeedBus("R2海选/补水轮")
	defer releaseSpeedBus("R2海选/补水轮")

	pipeLock.Lock()
	_, refill := chooseR2RefillTargetLocked()
	pipeLock.Unlock()

	if refill {
		addLog("💧 [R2直接补水] R3低于%d席，按精测榜地区队列轮转；每地区固定%d个候选，目标补到%d席。", r2LowWater, r2PerRegionBatch, r2HighWater)
		for {
			pipeLock.Lock()
			target, needRefill := chooseR2RefillTargetLocked()
			count := len(pool3V4)
			if target == IPv6 {
				count = len(pool3V6)
			}
			pipeLock.Unlock()
			if !needRefill || count >= r2HighWater {
				break
			}

			need := r2HighWater - count
			if need > r2BatchSize*r2NormalBatchRuns {
				need = r2BatchSize * r2NormalBatchRuns
			}
			batch := buildR2Schedule(&target, need, true)
			if len(batch) == 0 {
				addLog("⚠️ [R2地区补水中止] %s轨道暂无符合所选地区/丢包条件的候选，交还总线。", target)
				break
			}
			for _, cand := range batch {
				if cand == nil {
					continue
				}
				pipeLock.Lock()
				delete(r2Eligible, cand.IP)
				pipeLock.Unlock()
				executeR2Candidate(cand)
			}
		}
		return
	}

	addLog("🌊 [R2正常阶段] 双轨R3均≥%d席：从精测榜直接组装%d个候选，按地区每轮%d个，按丢包→最低延迟排序；再分%d组×%d个依次独享5秒。", r2LowWater, r2BatchSize*r2NormalBatchRuns, r2PerRegionBatch, r2NormalBatchRuns, r2BatchSize)
	phase := buildR2Schedule(nil, r2BatchSize*r2NormalBatchRuns, true)
	if len(phase) == 0 {
		addLog("⚠️ [R2正常阶段] 精测榜当前没有可接入候选，本轮提前结束。")
		return
	}
	for round := 0; round < r2NormalBatchRuns && round*r2BatchSize < len(phase); round++ {
		end := (round + 1) * r2BatchSize
		if end > len(phase) {
			end = len(phase)
		}
		batch := phase[round*r2BatchSize : end]
		addLog("🧪 [R2地区批次] 第%d/%d组，%d个IP依次独享5秒测速。", round+1, r2NormalBatchRuns, len(batch))
		for _, cand := range batch {
			if cand == nil {
				continue
			}
			pipeLock.Lock()
			delete(r2Eligible, cand.IP)
			pipeLock.Unlock()
			executeR2Candidate(cand)
		}
	}
}

func isIPAlreadyInPipeline(ip string) bool {
	for _, c := range pool3V4 {
		if c.IP == ip {
			return true
		}
	}
	for _, c := range pool3V6 {
		if c.IP == ip {
			return true
		}
	}
	for _, c := range pool4V4Ring.ToList() {
		if c.IP == ip {
			return true
		}
	}
	for _, c := range pool4V6Ring.ToList() {
		if c.IP == ip {
			return true
		}
	}
	if _, ok := coldPool[ip]; ok {
		return true
	}
	if _, ok := retiredDaytime[ip]; ok {
		return true
	}
	if _, ok := retiredPeak[ip]; ok {
		return true
	}
	if _, ok := sealedDaytime[ip]; ok {
		return true
	}
	if _, ok := sealedPeak[ip]; ok {
		return true
	}
	for _, st := range domainStatus {
		if st.CurrentIP == ip {
			return true
		}
	}
	return false
}

func runSymmetricClockEngine(stop <-chan struct{}) {
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				taskMutex.Lock()
				scanning := isTaskRunning
				taskMutex.Unlock()
				if !scanning {
					checkAndReviveColdIPs()
					handlePeriodTransitionCheck()
				}
			case <-stop:
				return
			}
		}
	}()

	for {
		select {
		case <-stop:
			return
		default:
		}

		taskMutex.Lock()
		scanning := isTaskRunning
		taskMutex.Unlock()

		pipeLock.Lock()
		enabled := pipeCfg.Enabled
		pipeLock.Unlock()

		if scanning || !enabled {
			time.Sleep(1 * time.Second)
			continue
		}

		executeR4PatrolCycle()
		executeR2IngestionCycle()
		executeR4PatrolCycle()
		executeR3DuelCycle()
		debounceSyncDNS()

		time.Sleep(5 * time.Second)
	}
}

// 4. R4 0~99 物理卡槽顺序巡检：1分钟测1个格子，低于 R3 前 20 名淘汰回 R3 并清空负罪标签
func executeR4PatrolCycle() {
	acquireSpeedBus("R4巡检轮")
	defer releaseSpeedBus("R4巡检轮")
	minSpeedMB := pipeCfg.MinSpeedMB
	if minSpeedMB <= 0 {
		minSpeedMB = 1.0
	}

	if cand := pool4V4Ring.PatrolStep(); cand != nil {
		spd, speedErr := httpSpeedTestDirect(cand.IP, cand.Port, 5*time.Second)

		pipeLock.Lock()
		cand.LastCheck = time.Now()

		if spd > 0 {
			cand.Speed = spd
			cand.HistorySpeed = spd
			cand.ZeroStreak = 0
			if cand.Profile != nil {
				cand.Profile.SpeedMB = spd / 8.0
			}

			threshold := getR3NthSpeedLocked(IPv4, 20)
			if spd < threshold && pool4V4Ring.Count() > 20 {
				cand.ChallengeCount = 0 // 清空负罪标签
				cand.Status = "↩️ 逊于R3新秀·回流重战"
				pool4V4Ring.Remove(cand.IP)
				pool3V4 = append(pool3V4, cand)
				addLog("↩️ [R4末位轮替] 节点 %s 实测 %.2f MB/s 低于 R3 前 20 门槛，退回 R3 重战！", cand.IP, spd/8.0)
			}
		} else {
			if speedErr != "" {
				addLog("⚠️ [R4测速失败] 节点 %s：%s（本次按0速处理，但与真实0速区分）", cand.IP, speedErr)
			}
			cand.ZeroStreak++
			if cand.ZeroStreak >= 2 {
				pool4V4Ring.Remove(cand.IP)
				addToBlacklist(cand.IP)
				addLog("☠️ [连续0速死刑] R4 节点 %s 连续 2 次实测为 0，当场处决拉入黑名单！", cand.IP)
			} else {
				addLog("⚠️ [R4零速警告] 节点 %s 测出 0 MB/s，保留历史成绩 (%.2f MB/s) 给予免死...", cand.IP, cand.HistorySpeed/8.0)
			}
		}
		pipeLock.Unlock()
	}

	if cand := pool4V6Ring.PatrolStep(); cand != nil {
		spd, speedErr := httpSpeedTestDirect(cand.IP, cand.Port, 5*time.Second)

		pipeLock.Lock()
		cand.LastCheck = time.Now()

		if spd > 0 {
			cand.Speed = spd
			cand.HistorySpeed = spd
			cand.ZeroStreak = 0
			if cand.Profile != nil {
				cand.Profile.SpeedMB = spd / 8.0
			}

			threshold := getR3NthSpeedLocked(IPv6, 20)
			if spd < threshold && pool4V6Ring.Count() > 20 {
				cand.ChallengeCount = 0
				cand.Status = "↩️ 逊于R3新秀·回流重战"
				pool4V6Ring.Remove(cand.IP)
				pool3V6 = append(pool3V6, cand)
				addLog("↩️ [R4末位轮替] IPv6 节点 %s 实测 %.2f MB/s 低于 R3 前 20 门槛，退回 R3 重战！", cand.IP, spd/8.0)
			}
		} else {
			if speedErr != "" {
				addLog("⚠️ [R4测速失败] 节点 %s：%s（本次按0速处理，但与真实0速区分）", cand.IP, speedErr)
			}
			cand.ZeroStreak++
			if cand.ZeroStreak >= 2 {
				pool4V6Ring.Remove(cand.IP)
				addToBlacklist(cand.IP)
				addLog("☠️ [连续0速死刑] IPv6 节点 %s 连续 2 次实测为 0，当场处决拉黑！", cand.IP)
			} else {
				addLog("⚠️ [R4零速警告] IPv6 节点 %s 测出 0 MB/s，保留历史成绩 (%.2f MB/s) 给予免死...", cand.IP, cand.HistorySpeed/8.0)
			}
		}
		pipeLock.Unlock()
	}
	saveCacheFiles()
}

// 1. R2 动态水管：低于 50 个大水管狂灌，满 100 个转为常规

func executeR3DuelCycle() {
	acquireSpeedBus("R3.5擂台PK")
	defer releaseSpeedBus("R3.5擂台PK")
	runDuelForTrack(IPv4, &pool3V4, &pool4V4Ring)
	runDuelForTrack(IPv6, &pool3V6, &pool4V6Ring)
	saveCacheFiles()
}

// 3. R3 宽容期放宽至 2 小时；5. 连续两次 0 MB/s 处决
func runDuelForTrack(ver IPVersion, pool *[]*CandidateIP, ring *RingBuffer100) {
	pipeLock.Lock()

	minSpeedMB := pipeCfg.MinSpeedMB
	if minSpeedMB <= 0 {
		minSpeedMB = 1.0
	}
	baseSpeed := minSpeedMB * 8.0

	var pBenchmark *float64
	var pBenchmarkTime *time.Time
	if ver == IPv4 {
		pBenchmark = &r3BenchmarkV4
		pBenchmarkTime = &r3BenchmarkTimeV4
	} else {
		pBenchmark = &r3BenchmarkV6
		pBenchmarkTime = &r3BenchmarkTimeV6
	}

	now := time.Now()
	if pBenchmarkTime.IsZero() || now.Sub(*pBenchmarkTime) > 30*time.Minute {
		*pBenchmark = baseSpeed
		*pBenchmarkTime = now
		addLog("🔄 [R3重置] %s 赛道 30 分钟周期已满，R3.5 PK 门槛归零重置！", ver)
	}

	currentAdmissionLimit := (*pBenchmark) * 0.70
	if currentAdmissionLimit < baseSpeed {
		currentAdmissionLimit = baseSpeed
	}

	// 50 名开外且超过 2 小时未参赛才移入黑名单
	sortCandidates(*pool)
	var activePool []*CandidateIP
	for idx, cand := range *pool {
		if cand == nil {
			continue
		}
		if idx >= 50 && now.Sub(cand.LastCheck) > 2*time.Hour {
			addToBlacklist(cand.IP)
			addLog("🧹 [R3宽容期满] 节点 %s 超过 2 小时排在 50 名外未出战，移入熔断黑名单！", cand.IP)
			continue
		}
		activePool = append(activePool, cand)
	}
	*pool = activePool

	if len(*pool) == 0 {
		pipeLock.Unlock()
		return
	}

	var contestants []*CandidateIP
	var remainingPool []*CandidateIP

	for _, cand := range *pool {
		effectiveSpeed := cand.Speed
		if cand.HistorySpeed > effectiveSpeed {
			effectiveSpeed = cand.HistorySpeed
		}
		if len(contestants) < 10 && effectiveSpeed >= currentAdmissionLimit {
			contestants = append(contestants, cand)
		} else {
			remainingPool = append(remainingPool, cand)
		}
	}

	if len(contestants) < 3 && len(remainingPool) > 0 {
		fillCount := 3 - len(contestants)
		if fillCount > len(remainingPool) {
			fillCount = len(remainingPool)
		}
		contestants = append(contestants, remainingPool[:fillCount]...)
		remainingPool = remainingPool[fillCount:]
	}

	*pool = remainingPool
	pipeLock.Unlock()

	if len(contestants) == 0 {
		return
	}

	addLog("⚔️ [R3.5 PK] %s 赛道开辟擂台 (共 %d 节点激战，门槛: >= %.2f MB/s)...", ver, len(contestants), currentAdmissionLimit/8.0)

	for _, cand := range contestants {
		spd, speedErr := httpSpeedTestDirect(cand.IP, cand.Port, 5*time.Second)
		cand.LastCheck = time.Now()
		if spd > 0 {
			cand.Speed = spd
			cand.HistorySpeed = spd
			cand.ZeroStreak = 0
		} else {
			if speedErr != "" {
				addLog("⚠️ [R3.5测速失败] 节点 %s：%s（本次按0速处理）", cand.IP, speedErr)
			}
			cand.ZeroStreak++
		}
	}

	sortCandidates(contestants)

	pipeLock.Lock()
	defer pipeLock.Unlock()

	topCount := len(contestants)
	if topCount > 3 {
		topCount = 3
	}
	if topCount > 0 {
		var sumTop float64
		for i := 0; i < topCount; i++ {
			sumTop += contestants[i].Speed
		}
		avgTop := sumTop / float64(topCount)
		*pBenchmark = avgTop
	}

	for idx, cand := range contestants {
		if cand.ZeroStreak >= 2 {
			addToBlacklist(cand.IP)
			addLog("☠️ [连续0速死刑] 节点 %s 连续 2 次复测断流为 0，直接拉入黑名单！", cand.IP)
			continue
		}

		if idx < 3 && cand.Speed >= baseSpeed {
			cand.ChallengeCount = 0
			cand.Status = fmt.Sprintf("👑 晋升皇储 (%.2f MB/s)", cand.Speed/8.0)
			prof := buildNodeProfile(cand.IP, ver, cand.Speed, cand.Delay, cand.Port, cand.Colo)
			cand.Profile = prof
			profileStore[cand.IP] = prof

			evicted := ring.Insert(cand)
			addLog("👑 [R3.5出线] 节点 %s 实测 %.2f MB/s 荣登 R4 皇位待命仓！", cand.IP, cand.Speed/8.0)

			if evicted != nil {
				delete(profileStore, evicted.IP)
				evicted.ChallengeCount = 0
				evicted.Status = "↩️ 待命溢出·回流第3轮"
				*pool = append(*pool, evicted)
			}
			continue
		}

		cand.ChallengeCount++
		if cand.ChallengeCount >= 5 {
			coldUntil := time.Now().Add(30 * time.Minute)
			coldPool[cand.IP] = &ColdIP{
				IP:           cand.IP,
				Port:         cand.Port,
				Version:      ver,
				Colo:         cand.Colo,
				LastSpeed:    cand.Speed,
				LastDelay:    cand.Delay,
				FailCount:    cand.ChallengeCount,
				ColdTime:     time.Now(),
				ColdUntil:    coldUntil,
				RemainingSec: 1800,
				Status:       "❄️ 连续5次未晋级·冷宫面壁半小时",
			}
			addLog("❄️ [发配冷宫] 节点 %s 攻擂 5 次未进前三，进入冷宫反省 30 分钟！", cand.IP)
		} else {
			cand.Status = fmt.Sprintf("水库打磨 (%.2f MB/s), 挑战 %d/5", cand.Speed/8.0, cand.ChallengeCount)
			*pool = append(*pool, cand)
		}
	}
}

func checkAndReviveColdIPs() {
	pipeLock.Lock()
	defer pipeLock.Unlock()

	now := time.Now()
	for ip, c := range coldPool {
		if now.After(c.ColdUntil) {
			delete(coldPool, ip)
			cand := &CandidateIP{
				IP:             c.IP,
				Port:           c.Port,
				Version:        c.Version,
				Colo:           c.Colo,
				Delay:          c.LastDelay,
				Speed:          c.LastSpeed,
				HistorySpeed:   c.LastSpeed,
				ChallengeCount: 0,
				Status:         "⏳ 冷宫半小时满·重返3轮备战",
				LastCheck:      now,
			}
			if c.Version == IPv6 || isIPv6(c.IP) {
				pool3V6 = append(pool3V6, cand)
			} else {
				pool3V4 = append(pool3V4, cand)
			}
			addLog("⚡ [冷宫解封] 节点 %s 面壁 30 分钟期满，负罪清零，重返 R3 战备水库！", c.IP)
		}
	}
}

func debounceSyncDNS() {
	pipeLock.Lock()
	defer pipeLock.Unlock()

	if pipeCfg.ApiToken == "" || pipeCfg.RootDomain == "" || pipeCfg.ZoneID == "" {
		return
	}

	curPeriod := getCurrentPeriodTag()

	assignedIPs := make(map[string]bool)
	for _, stat := range domainStatus {
		if stat.CurrentIP != "" {
			assignedIPs[stat.CurrentIP] = true
		}
	}

	v4Candidates := pool4V4Ring.ToList()
	v6Candidates := pool4V6Ring.ToList()
	sortCandidates(v4Candidates)
	sortCandidates(v6Candidates)

	autoRankV4 := 0
	autoRankV6 := 0

	for _, cfg := range pipeCfg.Subdomains {
		key := fmt.Sprintf("%s_%s", cfg.Subdomain, cfg.Type)
		stat, ok := domainStatus[key]
		if !ok || stat.Mode == "manual" {
			continue
		}

		if stat.Type == "A" {
			autoRankV4++
			stat.Rank = autoRankV4

			inCooldown := false
			if !stat.LastUpTime.IsZero() && time.Since(stat.LastUpTime) < 2*time.Minute {
				inCooldown = true
			}

			var bestV4 *CandidateIP
			for _, cand := range v4Candidates {
				if !assignedIPs[cand.IP] {
					bestV4 = cand
					break
				}
			}

			if bestV4 == nil && len(pool3V4) > 0 {
				sortCandidates(pool3V4)
				for _, cand := range pool3V4 {
					if cand.Speed >= 8.0 && !assignedIPs[cand.IP] {
						bestV4 = cand
						pool4V4Ring.Insert(cand)
						removeCandidateFromSlice(&pool3V4, cand.IP)
						addLog("⚡ [穿透登基] R4 空缺，从 R3 水库调遣优质节点 %s 破格登基！", cand.IP)
						break
					}
				}
			}

			shouldAscend := false
			if bestV4 != nil {
				if stat.CurrentIP == "" {
					shouldAscend = true
				} else if !inCooldown && bestV4.IP != stat.CurrentIP {
					if curPeriod == "peak" {
						shouldAscend = true
					} else {
						if bestV4.Speed > stat.CurrentSpeed {
							shouldAscend = true
						}
					}
				}
			}

			if shouldAscend && bestV4 != nil {
				if stat.CurrentIP != "" {
					retItem := &RetiredIP{
						IP:          stat.CurrentIP,
						Port:        bestV4.Port,
						Version:     IPv4,
						Colo:        bestV4.Colo,
						LastSpeed:   stat.CurrentSpeed,
						LastDelay:   bestV4.Delay,
						RetiredTime: time.Now(),
						OrigDomain:  stat.Subdomain,
						PeriodTag:   curPeriod,
						Status:      fmt.Sprintf("%s 满2分钟禅让退役", stat.Subdomain),
						Profile:     profileStore[stat.CurrentIP],
					}
					if curPeriod == "peak" {
						retiredPeak[stat.CurrentIP] = retItem
					} else {
						retiredDaytime[stat.CurrentIP] = retItem
					}
					addLog("📦 [老将退位] 节点 %s 坐满 2 分钟，退入【%s退役阁】！", stat.CurrentIP, map[string]string{"peak": "晚高峰", "daytime": "白天"}[curPeriod])
				}

				_ = cleanConflictingRecord(pipeCfg.ApiToken, pipeCfg.ZoneID, stat.FullDomain, "AAAA")

				err := updateCloudflareDNS(pipeCfg.ApiToken, pipeCfg.ZoneID, stat.FullDomain, "A", bestV4.IP)
				if err == nil {
					stat.CurrentIP = bestV4.IP
					stat.CurrentSpeed = bestV4.Speed
					stat.LastUpTime = time.Now()
					if prof, has := profileStore[bestV4.IP]; has {
						prof.CurrentRole = "emperor"
						prof.BoundDomain = stat.FullDomain
						stat.Profile = prof
					}
					assignedIPs[bestV4.IP] = true
					pool4V4Ring.Remove(bestV4.IP)
					addLog("👑 [IPv4真皇登基] %s 成功上位: %s (%.2f MB/s)，重置 2 分钟防抖守擂！", stat.FullDomain, bestV4.IP, bestV4.Speed/8.0)
				}
			}
		} else if stat.Type == "AAAA" {
			autoRankV6++
			stat.Rank = autoRankV6

			inCooldown := false
			if !stat.LastUpTime.IsZero() && time.Since(stat.LastUpTime) < 2*time.Minute {
				inCooldown = true
			}

			var bestV6 *CandidateIP
			for _, cand := range v6Candidates {
				if !assignedIPs[cand.IP] {
					bestV6 = cand
					break
				}
			}

			if bestV6 == nil && len(pool3V6) > 0 {
				sortCandidates(pool3V6)
				for _, cand := range pool3V6 {
					if cand.Speed >= 8.0 && !assignedIPs[cand.IP] {
						bestV6 = cand
						pool4V6Ring.Insert(cand)
						removeCandidateFromSlice(&pool3V6, cand.IP)
						addLog("⚡ [穿透登基] R4 空缺，从 R3 水库调遣优质节点 %s 破格登基！", cand.IP)
						break
					}
				}
			}

			shouldAscend := false
			if bestV6 != nil {
				if stat.CurrentIP == "" {
					shouldAscend = true
				} else if !inCooldown && bestV6.IP != stat.CurrentIP {
					if curPeriod == "peak" {
						shouldAscend = true
					} else {
						if bestV6.Speed > stat.CurrentSpeed {
							shouldAscend = true
						}
					}
				}
			}

			if shouldAscend && bestV6 != nil {
				if stat.CurrentIP != "" {
					retItem := &RetiredIP{
						IP:          stat.CurrentIP,
						Port:        bestV6.Port,
						Version:     IPv6,
						Colo:        bestV6.Colo,
						LastSpeed:   stat.CurrentSpeed,
						LastDelay:   bestV6.Delay,
						RetiredTime: time.Now(),
						OrigDomain:  stat.Subdomain,
						PeriodTag:   curPeriod,
						Status:      fmt.Sprintf("%s 满2分钟禅让退役", stat.Subdomain),
						Profile:     profileStore[stat.CurrentIP],
					}
					if curPeriod == "peak" {
						retiredPeak[stat.CurrentIP] = retItem
					} else {
						retiredDaytime[stat.CurrentIP] = retItem
					}
					addLog("📦 [老将退位] IPv6 节点 %s 坐满 2 分钟，退入【%s退役阁】！", stat.CurrentIP, map[string]string{"peak": "晚高峰", "daytime": "白天"}[curPeriod])
				}

				_ = cleanConflictingRecord(pipeCfg.ApiToken, pipeCfg.ZoneID, stat.FullDomain, "A")

				err := updateCloudflareDNS(pipeCfg.ApiToken, pipeCfg.ZoneID, stat.FullDomain, "AAAA", bestV6.IP)
				if err == nil {
					stat.CurrentIP = bestV6.IP
					stat.CurrentSpeed = bestV6.Speed
					stat.LastUpTime = time.Now()
					if prof, has := profileStore[bestV6.IP]; has {
						prof.CurrentRole = "emperor"
						prof.BoundDomain = stat.FullDomain
						stat.Profile = prof
					}
					assignedIPs[bestV6.IP] = true
					pool4V6Ring.Remove(bestV6.IP)
					addLog("👑 [IPv6真皇登基] %s 成功上位: %s (%.2f MB/s)，重置 2 分钟防抖守擂！", stat.FullDomain, bestV6.IP, bestV6.Speed/8.0)
				}
			}
		}
	}
	saveCacheFiles()
}

func getR3NthSpeedLocked(ver IPVersion, n int) float64 {
	var pool []*CandidateIP
	if ver == IPv4 {
		pool = pool3V4
	} else {
		pool = pool3V6
	}
	if len(pool) < n {
		return 8.0
	}
	return pool[n-1].Speed
}

func cleanConflictingRecord(token, zoneID, fullDomain, conflictType string) error {
	client := &http.Client{Timeout: 8 * time.Second}
	reqUrl := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s&type=%s", zoneID, fullDomain, conflictType)
	req, err := http.NewRequest("GET", reqUrl, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var listResp struct {
		Success bool `json:"success"`
		Result  []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Content string `json:"content"`
		} `json:"result"`
	}
	_ = json.Unmarshal(body, &listResp)

	if listResp.Success && len(listResp.Result) > 0 {
		for _, rec := range listResp.Result {
			if strings.EqualFold(rec.Name, fullDomain) {
				delUrl := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, rec.ID)
				dReq, _ := http.NewRequest("DELETE", delUrl, nil)
				dReq.Header.Set("Authorization", "Bearer "+token)
				dResp, dErr := client.Do(dReq)
				if dErr == nil {
					dResp.Body.Close()
					addLog("🧹 [历史纠偏] 成功清理子域 %s 下残留的旧 %s 冲突记录: %s", fullDomain, conflictType, rec.Content)
				}
			}
		}
	}
	return nil
}

func classifySpeedTestError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "请求超时"
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "连接/读取超时"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "connection refused"):
		return "TCP连接被拒绝"
	case strings.Contains(msg, "connection reset") || strings.Contains(msg, "reset by peer"):
		return "连接被对端重置"
	case strings.Contains(msg, "network is unreachable") || strings.Contains(msg, "no route to host"):
		return "网络不可达"
	case strings.Contains(msg, "tls") || strings.Contains(msg, "handshake") || strings.Contains(msg, "certificate"):
		return "TLS握手失败"
	case strings.Contains(msg, "eof"):
		return "对端提前关闭连接"
	default:
		return "连接失败: " + err.Error()
	}
}

func readTraceResponse(r io.Reader) (string, error) {
	var body bytes.Buffer
	buf := make([]byte, 2048)
	for {
		n, err := r.Read(buf)
		if n > 0 {
			body.Write(buf[:n])
			text := body.String()
			// 不重新扫描、不重新建连；只在同一次 TCP/TLS 连接里继续读取，直到拿到 trace 的 colo/loc。
			if strings.Contains(text, "colo=") {
				return text, nil
			}
		}
		if err != nil {
			return body.String(), err
		}
	}
}

func httpSpeedTestDirect(ip string, port int, sampleDuration time.Duration) (float64, string) {

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	dialer := &net.Dialer{Timeout: 3500 * time.Millisecond}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName:         "speed.cloudflare.com",
			InsecureSkipVerify: true,
		},
		DisableKeepAlives: true,
		DialContext: func(c context.Context, network, addr string) (net.Conn, error) {
			target := net.JoinHostPort(ip, strconv.Itoa(port))
			return dialer.DialContext(c, network, target)
		},
	}
	client := &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	scheme := "https"
	if port == 80 || port == 8080 || port == 8880 || port == 2052 || port == 2082 || port == 2086 || port == 2095 {
		scheme = "http"
	}

	testURL := fmt.Sprintf("%s://speed.cloudflare.com/__down?bytes=1000000000", scheme)
	req, err := http.NewRequestWithContext(ctx, "GET", testURL, nil)
	if err != nil {
		return 0, "构造请求失败: " + err.Error()
	}

	req.Host = "speed.cloudflare.com"
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36")
	req.Header.Set("Referer", "https://speed.cloudflare.com/")
	req.Header.Set("Origin", "https://speed.cloudflare.com")
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")

	resp, err := client.Do(req)
	if err != nil {
		return 0, classifySpeedTestError(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 206 {
		return 0, fmt.Sprintf("HTTP状态码 %d", resp.StatusCode)
	}

	buf := make([]byte, 64*1024)
	var totalBytes int64
	var readStart time.Time
	var sampleDeadline time.Time
	hasStartedTiming := false

	for {
		n, rErr := resp.Body.Read(buf)
		if n > 0 {
			if !hasStartedTiming {
				readStart = time.Now()
				sampleDeadline = readStart.Add(sampleDuration)
				hasStartedTiming = true
			}
			totalBytes += int64(n)
		}
		if hasStartedTiming && time.Now().After(sampleDeadline) {
			break
		}
		if rErr != nil {
			if rErr == io.EOF {
				break
			}
			return 0, "读取测速数据失败: " + rErr.Error()
		}
	}

	if !hasStartedTiming || totalBytes == 0 {
		return 0, "连接成功但未收到测速数据"
	}

	duration := time.Since(readStart).Seconds()
	if duration <= 0 {
		return 0, "测速计时异常"
	}
	return (float64(totalBytes) * 8.0) / (duration * 1000.0 * 1000.0), ""
}

func updateCloudflareDNS(token, zoneID, domain, recType, ip string) error {
	client := &http.Client{Timeout: 12 * time.Second}
	reqUrl := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records?name=%s&type=%s", zoneID, domain, recType)
	req, err := http.NewRequest("GET", reqUrl, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("请求超时: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	var listResp struct {
		Success bool `json:"success"`
		Errors  []struct {
			Message string `json:"message"`
		} `json:"errors"`
		Result []struct {
			ID      string `json:"id"`
			Content string `json:"content"`
		} `json:"result"`
	}
	_ = json.Unmarshal(body, &listResp)

	if !listResp.Success {
		msg := "权限验证失败"
		if len(listResp.Errors) > 0 {
			msg = listResp.Errors[0].Message
		}
		return fmt.Errorf(msg)
	}

	payload := map[string]interface{}{
		"type":    recType,
		"name":    domain,
		"content": ip,
		"ttl":     60,
		"proxied": false,
	}
	pData, _ := json.Marshal(payload)

	if len(listResp.Result) > 0 {
		if listResp.Result[0].Content == ip {
			return nil
		}
		recordID := listResp.Result[0].ID
		updateUrl := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, recordID)
		uReq, _ := http.NewRequest("PUT", updateUrl, bytes.NewBuffer(pData))
		uReq.Header.Set("Authorization", "Bearer "+token)
		uReq.Header.Set("Content-Type", "application/json")
		uResp, err := client.Do(uReq)
		if err != nil {
			return err
		}
		defer uResp.Body.Close()
		return nil
	} else {
		createUrl := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
		cReq, _ := http.NewRequest("POST", createUrl, bytes.NewBuffer(pData))
		cReq.Header.Set("Authorization", "Bearer "+token)
		cReq.Header.Set("Content-Type", "application/json")
		cResp, err := client.Do(cReq)
		if err != nil {
			return err
		}
		defer cResp.Body.Close()
		return nil
	}
}

func sortCandidates(list []*CandidateIP) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].Speed != list[j].Speed {
			return list[i].Speed > list[j].Speed
		}
		return list[i].Delay < list[j].Delay
	})
}

func savePipelineConfig() {
	d, _ := json.Marshal(pipeCfg)
	_ = os.WriteFile("pipeline_config.json", d, 0644)
}

func loadPipelineConfig() {
	d, err := os.ReadFile("pipeline_config.json")
	if err == nil {
		_ = json.Unmarshal(d, &pipeCfg)
	}

	pipeCfg.Enabled = false
	pipeCfg.Ports = "443"
	pipeCfg.AllowedColos = ""
	if pipeCfg.MinSpeedMB <= 0 {
		pipeCfg.MinSpeedMB = 1.0
	}
	if pipeCfg.PeakStartHour == 0 && pipeCfg.PeakEndHour == 0 {
		pipeCfg.PeakStartHour = 19
		pipeCfg.PeakEndHour = 24
	}
	if pipeCfg.R2Mode != "manual" {
		pipeCfg.R2Mode = "auto"
	}
	if pipeCfg.R2PerRegion <= 0 {
		pipeCfg.R2PerRegion = 2
	}
	savePipelineConfig()

	pipeLock.Lock()
	syncDomainStatusMapLocked()
	pipeLock.Unlock()
}

func saveCacheFiles() {
	dRetDay, _ := json.Marshal(retiredDaytime)
	_ = os.WriteFile("retired_daytime.json", dRetDay, 0644)
	dRetPeak, _ := json.Marshal(retiredPeak)
	_ = os.WriteFile("retired_peak.json", dRetPeak, 0644)

	dSealDay, _ := json.Marshal(sealedDaytime)
	_ = os.WriteFile("sealed_daytime.json", dSealDay, 0644)
	dSealPeak, _ := json.Marshal(sealedPeak)
	_ = os.WriteFile("sealed_peak.json", dSealPeak, 0644)

	dDom, _ := json.Marshal(domainStatus)
	_ = os.WriteFile("domains_cache.json", dDom, 0644)
	dProf, _ := json.Marshal(profileStore)
	_ = os.WriteFile("profiles_cache.json", dProf, 0644)

	blacklistLock.RLock()
	dBlack, _ := json.Marshal(lowSpeedBlacklist)
	blacklistLock.RUnlock()
	_ = os.WriteFile("blacklist_cache.json", dBlack, 0644)
}

func loadCleanCacheFiles() {
	os.Remove("pool3_v4_cache.json")
	os.Remove("pool3_v6_cache.json")
	os.Remove("pool4_v4_cache.json")
	os.Remove("pool4_v6_cache.json")
	os.Remove("cold_cache.json")

	pool2 = make(map[string]*CandidateIP)
	r2Eligible = make(map[string]struct{})
	r2RegionCursor = 0
	r2ZeroStreak = make(map[string]int)
	r2HistorySpeed = make(map[string]float64)
	r2RetryAfter = make(map[string]time.Time)
	pool3V4 = make([]*CandidateIP, 0)
	pool3V6 = make([]*CandidateIP, 0)
	pool4V4Ring = RingBuffer100{}
	pool4V6Ring = RingBuffer100{}
	coldPool = make(map[string]*ColdIP)

	if d, err := os.ReadFile("retired_daytime.json"); err == nil {
		_ = json.Unmarshal(d, &retiredDaytime)
	}
	if d, err := os.ReadFile("retired_peak.json"); err == nil {
		_ = json.Unmarshal(d, &retiredPeak)
	}
	if d, err := os.ReadFile("sealed_daytime.json"); err == nil {
		_ = json.Unmarshal(d, &sealedDaytime)
	}
	if d, err := os.ReadFile("sealed_peak.json"); err == nil {
		_ = json.Unmarshal(d, &sealedPeak)
	}

	if d, err := os.ReadFile("domains_cache.json"); err == nil {
		_ = json.Unmarshal(d, &domainStatus)
	}
	if d, err := os.ReadFile("profiles_cache.json"); err == nil {
		_ = json.Unmarshal(d, &profileStore)
	}
	if d, err := os.ReadFile("blacklist_cache.json"); err == nil {
		blacklistLock.Lock()
		_ = json.Unmarshal(d, &lowSpeedBlacklist)
		blacklistLock.Unlock()
	}
}

func parsePorts(portsStr string) []int {
	var ports []int
	parts := strings.Split(portsStr, ",")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if val, err := strconv.Atoi(p); err == nil && val > 0 && val <= 65535 {
			ports = append(ports, val)
		}
	}
	if len(ports) == 0 {
		ports = []int{443}
	}
	return ports
}

func runEnhancedTask(ws *wsConn, v4, v6, useTCP, useHTTP bool, threads int, portsStr string, maxDelay int, colosFilter string, subnetMode string) {
	startScanSession(ws, v4, v6, useTCP, useHTTP, threads, portsStr, maxDelay, colosFilter, subnetMode)
}

// 扫描前段重新实现：行为严格对齐最终 v5，职责拆分为采样、TCP 粗筛、实时批次、Trace 分类与收尾。
func startScanSession(ws *wsConn, v4, v6, useTCP, useHTTP bool, threads int, portsStr string, maxDelay int, colosFilter string, subnetMode string) {
	taskMutex.Lock()
	if isTaskRunning {
		taskMutex.Unlock()
		sendWSMessage(ws, "error", "已有任务正在运行中，请等待完成或点击终止")
		return
	}
	isTaskRunning = true
	ctx, cancel := context.WithCancel(context.Background())
	taskCancel = cancel
	taskMutex.Unlock()

	completedNormally := false
	defer func() {
		if completedNormally {
			advanceScanRotationEpoch()
		}
		taskMutex.Lock()
		isTaskRunning = false
		taskCancel = nil
		taskMutex.Unlock()
		sendWSMessage(ws, "task_complete", map[string]interface{}{
			"completed":    completedNormally,
			"rotate_epoch": currentScanRotationEpoch(),
		})
	}()

	sendWSMessage(ws, "log", "🚀 扫描启动：高速海选车道，默认并发 200；每个 IP 仅做 4 次 TCP 握手。")
	if !v4 && !v6 {
		v4, v6 = true, true
	}
	if !useTCP && !useHTTP {
		useTCP = true
	}
	_ = useTCP
	_ = useHTTP
	_ = maxDelay

	if v6 {
		if !checkLocalIPv6Support() {
			sendWSMessage(ws, "log", "⚠️ [网络诊断] 本机未检测到公网 IPv6 路由！若全超时请检查路由器 IPv6 开关。")
		} else {
			sendWSMessage(ws, "log", "✅ [网络诊断] 本机 IPv6 双栈通畅！已启动 IPv6 Anycast 节点并发扫描。")
		}
	}

	if threads <= 0 {
		threads = 200
	}
	if threads > 1000 {
		threads = 1000
	}
	ports := parsePorts(portsStr)

	pipeLock.Lock()
	pipeCfg.Ports = portsStr
	pipeCfg.AllowedColos = colosFilter
	savePipelineConfig()
	pipeLock.Unlock()

	v4List, v6List := buildScanSamples(v4, v6, subnetMode)
	targets := interleaveProbeTargets(v4List, v6List, ports)

	scanMutex.Lock()
	scanResults = []ScanResult{}
	scanMutex.Unlock()
	pipeLock.Lock()
	r2Eligible = make(map[string]struct{})
	r2RegionCursor = 0
	r2ZeroStreak = make(map[string]int)
	r2HistorySpeed = make(map[string]float64)
	r2RetryAfter = make(map[string]time.Time)
	pool2 = make(map[string]*CandidateIP)
	pipeLock.Unlock()

	activeTargets := make([]probeTarget, 0, len(targets))
	for _, target := range targets {
		if !isBlacklisted(target.IP) {
			activeTargets = append(activeTargets, target)
		}
	}
	targets = activeTargets
	total := len(targets)
	sendWSMessage(ws, "log", fmt.Sprintf("节点采样就绪，共 %d 个探测对 (IPv4: %d, IPv6: %d, 多端口: %v)", total, len(v4List), len(v6List), ports))
	sendWSMessage(ws, "log", "🧭 扫描阶段：TCP×4 合格即进入实时探测流；CF Trace 在扫描阶段负责分类/地区过滤。精测榜等待扫描结束或暂停后再统一整理；R2 不负责 Trace。")

	var wg sync.WaitGroup
	threadSlots := make(chan struct{}, threads)
	traceSlots := make(chan struct{}, scanTraceWorkers)
	var completedCount int

	var resultBatchMu sync.Mutex
	resultBatch := make([]ScanResult, 0, scanBatchSize)
	flushResults := func() {
		resultBatchMu.Lock()
		if len(resultBatch) == 0 {
			resultBatchMu.Unlock()
			return
		}
		payload := append([]ScanResult(nil), resultBatch...)
		resultBatch = resultBatch[:0]
		resultBatchMu.Unlock()
		sendWSMessage(ws, "scan_batch", payload)
	}

	var traceBatchMu sync.Mutex
	traceBatch := make([]ScanResult, 0, scanTraceBatchSize)
	flushTrace := func() {
		traceBatchMu.Lock()
		if len(traceBatch) == 0 {
			traceBatchMu.Unlock()
			return
		}
		payload := append([]ScanResult(nil), traceBatch...)
		traceBatch = traceBatch[:0]
		traceBatchMu.Unlock()
		sendWSMessage(ws, "scan_trace_batch", payload)
	}

	withColoFilter := scanHasColoFilter(colosFilter)
	canceled := false

probeLoop:
	for _, target := range targets {
		select {
		case <-ctx.Done():
			canceled = true
			break probeLoop
		case threadSlots <- struct{}{}:
		}

		wg.Add(1)
		go func(t probeTarget) {
			defer func() {
				<-threadSlots
				wg.Done()
				scanMutex.Lock()
				completedCount++
				current := completedCount
				scanMutex.Unlock()
				if current%50 == 0 || current == total {
					sendWSMessage(ws, "scan_progress", map[string]int{"current": current, "total": total})
				}
			}()

			report, probeErr := performProbeSeries(ctx, t.IP, t.Port, scanProbeCount, scanDialTimeout)
			if probeErr != nil || report.SuccessCount <= 0 || report.AvgLatency <= 0 || report.LossRate >= scanLossCutoff {
				return
			}

			candidate := ScanResult{
				IP:            t.IP,
				Port:          t.Port,
				DataCenter:    "Trace中",
				Country:       "",
				Region:        "Trace中",
				City:          "Trace中",
				Method:        "TCP×4",
				LatencyStr:    fmt.Sprintf("%d ms", int(report.AvgLatency/time.Millisecond)),
				TCPDuration:   report.AvgLatency,
				MinLatency:    report.MinLatency,
				MaxLatency:    report.MaxLatency,
				AvgLatency:    report.AvgLatency,
				LossRate:      report.LossRate,
				ProbeCount:    report.ProbeCount,
				SuccessCount:  report.SuccessCount,
				LocalAdaptive: true,
			}

			// 指定地区时，必须先 Trace 再决定是否进入扫描结果；全球扫描则先进入实时流，再后台补分类。
			if withColoFilter {
				select {
				case <-ctx.Done():
					return
				case traceSlots <- struct{}{}:
				}
				colo, countryCode, traceErr := resolveCFTrace(t.IP, t.Port, scanTraceTimeout)
				<-traceSlots
				if traceErr != nil || colo == "" || !isColoMatched(colo, colosFilter) {
					return
				}
				fillTraceFields(&candidate, colo, countryCode)
			}

			scanMutex.Lock()
			scanResults = append(scanResults, candidate)
			scanMutex.Unlock()

			// 指定地区扫描同样必须进入 R2 候选集合；此前这里漏记会导致 R2 扫描结束后长期空转。
			pipeLock.Lock()
			if !isBlacklisted(t.IP) {
				r2Eligible[t.IP] = struct{}{}
			}
			pipeLock.Unlock()

			resultBatchMu.Lock()
			resultBatch = append(resultBatch, candidate)
			needFlush := len(resultBatch) >= scanBatchSize
			resultBatchMu.Unlock()
			if needFlush {
				flushResults()
			}

			if !withColoFilter {
				select {
				case <-ctx.Done():
					return
				case traceSlots <- struct{}{}:
				}
				colo, countryCode, traceErr := resolveCFTrace(t.IP, t.Port, scanTraceTimeout)
				<-traceSlots
				if traceErr != nil || colo == "" {
					return
				}

				fillTraceFields(&candidate, colo, countryCode)
				replaceScanResult(candidate)

				pipeLock.Lock()
				if !isBlacklisted(t.IP) && isColoMatched(colo, colosFilter) {
					r2Eligible[t.IP] = struct{}{}
				}
				pipeLock.Unlock()

				traceBatchMu.Lock()
				traceBatch = append(traceBatch, candidate)
				needTraceFlush := len(traceBatch) >= scanTraceBatchSize
				traceBatchMu.Unlock()
				if needTraceFlush {
					flushTrace()
				}
			}
		}(target)
	}

	wg.Wait()
	flushResults()
	flushTrace()

	if canceled {
		sendWSMessage(ws, "log", "⏹️ 扫描已暂停/终止：当前已完成的结果保留，后端精测车道将恢复；网页榜单延迟 30 秒后统一整理。")
		return
	}

	scanMutex.Lock()
	if len(scanResults) == 0 {
		scanMutex.Unlock()
		sendWSMessage(ws, "error", "扫描未发现合格节点，请检查 IPv4/IPv6、端口或网络状态")
		return
	}
	sort.Slice(scanResults, func(i, j int) bool { return scanResultLess(scanResults[i], scanResults[j]) })
	snapshot := append([]ScanResult(nil), scanResults...)
	scanMutex.Unlock()

	// 收尾再统一校正一次 R2 候选集合，确保所有已完成 CF Trace 分类的节点都能被 R2 接住。
	pipeLock.Lock()
	for _, res := range snapshot {
		if res.DataCenter == "" || res.DataCenter == "Trace中" || isBlacklisted(res.IP) {
			continue
		}
		if !isColoMatched(res.DataCenter, colosFilter) {
			continue
		}
		r2Eligible[res.IP] = struct{}{}
	}
	pipeLock.Unlock()

	completedNormally = true
	pipeLock.Lock()
	eligibleCount := len(r2Eligible)
	pipeLock.Unlock()
	sendWSMessage(ws, "log", fmt.Sprintf("✅ 扫描海选完成：每个通过 TCP×4 的 IP 再完成 CF Trace 分类；地区筛选在扫描阶段执行。当前合格候选 %d 个；真正熔断由 R2 负责。", eligibleCount))
	sendPartialSummary(ws)
}

type probeTarget struct {
	IP   string
	Port int
}

type ScanProbeReport struct {
	ProbeCount   int
	SuccessCount int
	LossRate     float64
	MinLatency   time.Duration
	MaxLatency   time.Duration
	AvgLatency   time.Duration
}

func buildScanSamples(v4, v6 bool, subnetMode string) ([]string, []string) {
	var v4List, v6List []string
	if v4 {
		body := loadOrDownloadIPs("ips-v4.txt", "https://www.baipiao.eu.org/cloudflare/ips-v4", defaultIPv4CIDRs)
		v4List = sampleIPv4ForCycle(parseIPList(body), subnetMode)
	}
	if v6 {
		body := loadOrDownloadIPs("ips-v6.txt", "https://www.baipiao.eu.org/cloudflare/ips-v6", defaultIPv6CIDRs)
		v6List = sampleIPv6ForCycle(parseIPList(body))
	}
	return v4List, v6List
}

func interleaveProbeTargets(v4List, v6List []string, ports []int) []probeTarget {
	maxLen := len(v4List)
	if len(v6List) > maxLen {
		maxLen = len(v6List)
	}
	result := make([]probeTarget, 0, maxLen*len(ports))
	for i := 0; i < maxLen; i++ {
		for _, port := range ports {
			if i < len(v4List) {
				result = append(result, probeTarget{IP: v4List[i], Port: port})
			}
			if i < len(v6List) {
				result = append(result, probeTarget{IP: v6List[i], Port: port})
			}
		}
	}
	return result
}

func scanHasColoFilter(filter string) bool {
	clean := strings.TrimSpace(filter)
	return clean != "" && !strings.Contains(clean, "留空") && !strings.Contains(clean, "自动")
}

func performProbeSeries(ctx context.Context, ip string, port, probes int, timeout time.Duration) (ScanProbeReport, error) {
	if probes <= 0 {
		probes = scanProbeCount
	}
	report := ScanProbeReport{ProbeCount: probes, MinLatency: time.Duration(math.MaxInt64)}
	var latencySum time.Duration
	dialer := &net.Dialer{Timeout: timeout}
	for n := 0; n < probes; n++ {
		select {
		case <-ctx.Done():
			return report, ctx.Err()
		default:
		}

		started := time.Now()
		conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if err != nil {
			continue
		}
		rtt := time.Since(started)
		_ = conn.Close()
		report.SuccessCount++
		latencySum += rtt
		if rtt < report.MinLatency {
			report.MinLatency = rtt
		}
		if rtt > report.MaxLatency {
			report.MaxLatency = rtt
		}
	}

	report.LossRate = float64(probes-report.SuccessCount) / float64(probes)
	if report.SuccessCount > 0 {
		report.AvgLatency = latencySum / time.Duration(report.SuccessCount)
	} else {
		report.MinLatency = 0
	}
	return report, nil
}

func resolveCFTrace(ip string, port int, timeout time.Duration) (string, string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), timeout)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()

	request := "GET /cdn-cgi/trace HTTP/1.1\r\nHost: speed.cloudflare.com\r\nUser-Agent: Mozilla/5.0\r\nReferer: https://speed.cloudflare.com/\r\nConnection: close\r\n\r\n"
	var body string
	if scanPortNeedsTLS(port) {
		tlsConn := tls.Client(conn, &tls.Config{ServerName: "speed.cloudflare.com", InsecureSkipVerify: true})
		_ = tlsConn.SetDeadline(time.Now().Add(timeout))
		if err := tlsConn.Handshake(); err != nil {
			return "", "", err
		}
		if _, err := io.WriteString(tlsConn, request); err != nil {
			return "", "", err
		}
		body, _ = readTraceResponse(tlsConn)
	} else {
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if _, err := io.WriteString(conn, request); err != nil {
			return "", "", err
		}
		body, _ = readTraceResponse(conn)
	}

	coloMatch := regexp.MustCompile(`colo=([A-Z0-9]+)`).FindStringSubmatch(body)
	locMatch := regexp.MustCompile(`loc=([A-Z]+)`).FindStringSubmatch(body)
	colo, loc := "", ""
	if len(coloMatch) > 1 {
		colo = coloMatch[1]
	}
	if len(locMatch) > 1 {
		loc = locMatch[1]
	}
	if colo == "" {
		return "", loc, errors.New("trace 中没有 colo")
	}
	return colo, loc, nil
}

func scanPortNeedsTLS(port int) bool {
	switch port {
	case 443, 8443, 2053, 2083, 2087, 2096:
		return true
	default:
		return false
	}
}

func fillTraceFields(result *ScanResult, colo, countryCode string) {
	region, city := "Global", colo
	if info, ok := locationMap[colo]; ok {
		region, city = info.Region, info.City
	} else if countryCode != "" {
		region = countryCode
	}
	result.DataCenter = colo
	result.Country = countryCode
	result.Region = region
	result.City = city
	result.Method = "TCP×4+CF Trace"
}

func replaceScanResult(result ScanResult) {
	scanMutex.Lock()
	defer scanMutex.Unlock()
	for i := range scanResults {
		if scanResults[i].IP == result.IP && scanResults[i].Port == result.Port {
			scanResults[i] = result
			return
		}
	}
}

func sampleIPv4ForCycle(ipList []string, subnetMode string) []string {
	if subnetMode == "no" || subnetMode == "" {
		return sampleIPv4FixedCount(ipList, 120)
	}
	if subnetMode == "yes" {
		return sampleIPv4FixedCount(ipList, 18)
	}

	parts, ok := rotationParts(subnetMode)
	if !ok {
		parts = 2
	}
	epoch := currentScanRotationEpoch()
	part := int(epoch % uint64(parts))
	start := part * (120 / parts)
	end := start + 120/parts
	if part == parts-1 {
		end = 120
	}

	out := make([]string, 0, len(ipList)*(120/parts))
	seen := make(map[string]struct{})
	for _, subnet := range ipList {
		base := normalizeIPv4Prefix(subnet)
		all := stableIPv4Samples(base, 120)
		if start >= len(all) {
			continue
		}
		if end > len(all) {
			end = len(all)
		}
		for _, candidate := range all[start:end] {
			if isBlacklisted(candidate) {
				continue
			}
			if _, exists := seen[candidate]; exists {
				continue
			}
			seen[candidate] = struct{}{}
			out = append(out, candidate)
		}
	}
	return out
}

func sampleIPv4FixedCount(ipList []string, perSubnet int) []string {
	var out []string
	for _, subnet := range ipList {
		base := normalizeIPv4Prefix(subnet)
		parts := strings.Split(base, ".")
		if len(parts) != 4 {
			continue
		}
		for n := 0; n < perSubnet; n++ {
			candidate := fmt.Sprintf("%s.%s.%d.%d", parts[0], parts[1], rand.Intn(250)+1, rand.Intn(254)+1)
			if !isBlacklisted(candidate) {
				out = append(out, candidate)
			}
		}
	}
	return out
}

func normalizeIPv4Prefix(raw string) string {
	base := strings.TrimSpace(raw)
	for _, mask := range []string{"/24", "/13", "/14", "/15", "/17", "/18", "/20", "/22"} {
		base = strings.TrimSuffix(base, mask)
	}
	return base
}

func stableIPv4Samples(baseIP string, total int) []string {
	if total <= 0 {
		return nil
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte("cfdata-v5|" + baseIP))
	rnd := rand.New(rand.NewSource(int64(h.Sum64() & uint64(math.MaxInt64))))
	parts := strings.Split(baseIP, ".")
	if len(parts) != 4 {
		return nil
	}
	seen := make(map[string]struct{}, total)
	result := make([]string, 0, total)
	for len(result) < total {
		candidate := fmt.Sprintf("%s.%s.%d.%d", parts[0], parts[1], rnd.Intn(250)+1, rnd.Intn(254)+1)
		if _, exists := seen[candidate]; exists {
			continue
		}
		seen[candidate] = struct{}{}
		result = append(result, candidate)
	}
	return result
}

func sampleIPv6ForCycle(ipList []string) []string {
	var out []string
	for _, subnet := range ipList {
		line := strings.TrimSpace(subnet)
		if strings.Contains(line, "/") {
			line = strings.Split(line, "/")[0]
		}
		sections := strings.Split(line, ":")
		if len(sections) >= 3 && sections[0] != "" {
			a, b, c := sections[0], sections[1], sections[2]
			if c == "" {
				c = "0"
			}
			for n := 0; n < 8; n++ {
				candidate := fmt.Sprintf("%s:%s:%s:%x::%x", a, b, c, rand.Intn(65535), rand.Intn(254)+1)
				if !isBlacklisted(candidate) {
					out = append(out, candidate)
				}
			}
		}
	}

	for _, prefix := range []string{
		"2606:4700::6810", "2606:4700::6811", "2606:4700::6812", "2606:4700::6813",
		"2606:4700:30::6815", "2606:4700:30::6816", "2606:4700:30::6817",
		"2606:4700:4700::1111", "2606:4700:4700::1001",
	} {
		if strings.HasSuffix(prefix, "::1111") || strings.HasSuffix(prefix, "::1001") {
			if !isBlacklisted(prefix) {
				out = append(out, prefix)
			}
			continue
		}
		for n := 0; n < 15; n++ {
			first := rand.Intn(254) + 1
			second := rand.Intn(254) + 1
			candidate := fmt.Sprintf("%s:%02x%02x", prefix, first, second)
			if !isBlacklisted(candidate) {
				out = append(out, candidate)
			}
		}
	}
	return out
}

func runDetailedTest(ws *wsConn, selectedDC string, port int, delay int) {
	var testIPList []ScanResult
	scanMutex.Lock()
	for _, res := range scanResults {
		if selectedDC == "" || res.DataCenter == selectedDC {
			testIPList = append(testIPList, res)
		}
	}
	scanMutex.Unlock()

	if len(testIPList) == 0 {
		sendWSMessage(ws, "error", "没有找到可测试的 IP")
		return
	}

	sendWSMessage(ws, "log", fmt.Sprintf("开始对 %s 机房的 %d 个 IP 进行详细测试...", selectedDC, len(testIPList)))

	var results []TestResult
	var resMutex sync.Mutex
	var wg sync.WaitGroup
	thread := make(chan struct{}, 40)
	var count int
	total := len(testIPList)

	for _, item := range testIPList {
		wg.Add(1)
		thread <- struct{}{}
		go func(sc ScanResult) {
			defer func() {
				<-thread
				wg.Done()
				scanMutex.Lock()
				count++
				curr := count
				scanMutex.Unlock()
				if curr%5 == 0 || curr == total {
					sendWSMessage(ws, "test_progress", map[string]int{
						"current": curr,
						"total":   total,
					})
				}
			}()

			dialer := &net.Dialer{Timeout: time.Duration(delay) * time.Millisecond}
			successCount := 0
			totalLatency := time.Duration(0)
			minLatency := time.Duration(math.MaxInt64)
			maxLatency := time.Duration(0)

			for i := 0; i < scanProbeCount; i++ {
				start := time.Now()
				conn, err := dialer.Dial("tcp", net.JoinHostPort(sc.IP, strconv.Itoa(port)))
				if err != nil {
					continue
				}
				latency := time.Since(start)
				if latency > time.Duration(delay)*time.Millisecond {
					conn.Close()
					continue
				}
				successCount++
				totalLatency += latency
				if latency < minLatency {
					minLatency = latency
				}
				if latency > maxLatency {
					maxLatency = latency
				}
				conn.Close()
			}

			if successCount > 0 {
				avgLatency := totalLatency / time.Duration(successCount)
				lossRate := float64(scanProbeCount-successCount) / float64(scanProbeCount)
				res := TestResult{
					IP:         sc.IP,
					Port:       port,
					DataCenter: sc.DataCenter,
					Country:    sc.Country,
					Region:     sc.Region,
					City:       sc.City,
					Method:     sc.Method,
					MinLatency: minLatency,
					MaxLatency: maxLatency,
					AvgLatency: avgLatency,
					LossRate:   lossRate,
					Speed:      "未测速",
				}
				sendWSMessage(ws, "test_result", res)
				resMutex.Lock()
				results = append(results, res)
				resMutex.Unlock()
			}
		}(item)
	}
	wg.Wait()

	sort.Slice(results, func(i, j int) bool {
		if results[i].LossRate != results[j].LossRate {
			return results[i].LossRate < results[j].LossRate
		}
		minI := results[i].MinLatency / time.Millisecond
		minJ := results[j].MinLatency / time.Millisecond
		if minI != minJ {
			return minI < minJ
		}
		if results[i].MaxLatency != results[j].MaxLatency {
			return results[i].MaxLatency < results[j].MaxLatency
		}
		return results[i].AvgLatency < results[j].AvgLatency
	})

	sendWSMessage(ws, "test_complete", results)
}

func runSpeedTest(ws *wsConn, ip string, port int) {
	acquireSpeedBus("手动单IP测速")
	defer releaseSpeedBus("手动单IP测速")
	sendWSMessage(ws, "log", fmt.Sprintf("IP %s (端口 %d) 独占测速总线5秒纯净极限测速中...", ip, port))
	spd, reason := httpSpeedTestDirect(ip, port, 5*time.Second)

	speedStr := "0.00 MB/s"
	if spd > 0 {
		speedStr = fmt.Sprintf("%.2f MB/s", spd/8.0)
	}
	sendWSMessage(ws, "speed_test_result", map[string]string{
		"ip":     ip,
		"speed":  speedStr,
		"reason": reason,
	})
	if reason != "" {
		sendWSMessage(ws, "log", fmt.Sprintf("IP %s 测速完成: %s（%s）", ip, speedStr, reason))
	} else {
		sendWSMessage(ws, "log", fmt.Sprintf("IP %s 测速完成: %s", ip, speedStr))
	}
}

func initLocations() {
	filename := "locations.json"
	url := "https://www.baipiao.eu.org/cloudflare/locations"
	var locations []location
	var body []byte

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		resp, err := http.Get(url)
		if err == nil {
			defer resp.Body.Close()
			body, _ = io.ReadAll(resp.Body)
			_ = saveToFile(filename, string(body))
		}
	} else {
		body, _ = os.ReadFile(filename)
	}

	if err := json.Unmarshal(body, &locations); err == nil {
		locationMap = make(map[string]location)
		for _, loc := range locations {
			locationMap[loc.Iata] = loc
		}
	}
}

func loadOrDownloadIPs(filename, apiURL string, fallbackCIDRs []string) string {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		content, err := getURLContent(apiURL)
		if err == nil && len(content) > 10 {
			_ = saveToFile(filename, content)
			return content
		}
		return strings.Join(fallbackCIDRs, "\n")
	}
	content, err := getFileContent(filename)
	if err == nil && len(content) > 10 {
		return content
	}
	return strings.Join(fallbackCIDRs, "\n")
}

func getURLContent(targetURL string) (string, error) {
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(targetURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func getFileContent(filename string) (string, error) {
	data, err := os.ReadFile(filename)
	return string(data), err
}

func saveToFile(filename, content string) error {
	return os.WriteFile(filename, []byte(content), 0644)
}

func parseIPList(content string) []string {
	scanner := bufio.NewScanner(strings.NewReader(content))
	var ipList []string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			ipList = append(ipList, line)
		}
	}
	return ipList
}
