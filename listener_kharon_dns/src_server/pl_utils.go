package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"net"
	"strconv"
	"strings"
	"time"
)

func computeNextExpectedOffset(fb *dnsFragBuf) uint32 {
	if fb == nil || fb.total == 0 {
		return 0
	}
	step := fb.chunkSize
	if step == 0 {
		step = 120
	}
	for off := uint32(0); off < fb.total; off += step {
		if !fb.seenOffsets[off] {
			return off
		}
	}
	return fb.total
}

func deriveMaskKey(key []byte) byte {
	if len(key) == 0 {
		return 0
	}
	var h byte
	for _, b := range key {
		h ^= b
	}
	return h
}

func xor(data []byte, key byte) {
	for i := range data {
		data[i] ^= key
	}
}

func formatAddr(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func newTaskNonce() uint32 {
	return rand.New(rand.NewPCG(uint64(time.Now().UnixNano()), uint64(time.Now().UnixNano()))).Uint32()
}

// parseMetaV1 checks for a Meta V1 header in PUT data.
// Meta V1: [version:1][flags:1][reserved:2][downAckOffset:4]
func parseMetaV1(data []byte) (metaFlags byte, downAckOff uint32, rest []byte, hasMeta bool) {
	if len(data) < 8 {
		return 0, 0, data, false
	}
	if data[0] != 1 {
		return 0, 0, data, false
	}
	metaFlags = data[1]
	downAckOff = binary.LittleEndian.Uint32(data[4:8])
	return metaFlags, downAckOff, data[8:], true
}

func hexDump(data []byte, maxLen int) string {
	if len(data) > maxLen {
		data = data[:maxLen]
	}
	return hex.Dump(data)
}

func logf(format string, args ...interface{}) {
	fmt.Printf("[KharonDNS] "+format+"\n", args...)
}

func splitDomains(domainStr string) []string {
	parts := strings.Split(domainStr, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		p = strings.ToLower(p)
		if strings.HasSuffix(p, ".") {
			p = p[:len(p)-1]
		}
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
