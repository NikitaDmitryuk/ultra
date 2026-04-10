// Package trace captures per-connection latency timelines by intercepting
// xray-core's global log stream via common/log.RegisterHandler.
//
// xray emits structured log messages that include a session ID (uint32) and a
// component path for every significant connection event, e.g.:
//
//	[1024478894] proxy/vless/inbound: firstLen = 1186
//	[1024478894] app/dispatcher: taking detour [to-exit] for [tcp:example.com:443]
//	[1024478894] transport/internet/splithttp: XHTTP is dialing to tcp:…
//	[1024478894] proxy/vless/outbound: tunneling request to tcp:… via …
//
// The LogHandler parses these, groups them by session ID into Session timelines,
// and stores completed sessions in a ring buffer for later retrieval via the
// admin API (/v1/latency/sessions).
//
// IMPORTANT: common/log.RegisterHandler replaces the global handler — it is not
// additive. LogHandler therefore also writes every message to os.Stderr in
// xray's native format so normal logging is preserved.
package trace

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	xraylog "github.com/xtls/xray-core/common/log"
)

// logLineRE matches the session-ID prefix xray embeds in every log message:
//
//	[1024478894] proxy/vless/inbound: firstLen = 1186
//	          ^--- group 1 (session ID)
//	                ^--- group 2 (full message body)
var logLineRE = regexp.MustCompile(`^\[(\d+)\] (.+)$`)

// event classification patterns — evaluated in order; first match wins.
var classifiers = []struct {
	re    *regexp.Regexp
	stage string
	// capture indicates which submatch (1-indexed) to use as Detail; 0 = use full match.
	capture int
}{
	{regexp.MustCompile(`proxy/vless/inbound: firstLen`), StageClientFirstByte, 0},
	{regexp.MustCompile(`app/dispatcher: sniffed domain: (.+)`), StageDomainSniffed, 1},
	{regexp.MustCompile(`app/dispatcher: (?:Hit route rule.*?so )?taking detour \[([^\]]+)\] for \[([^\]]+)\]`), StageRoutingDecision, 0},
	{regexp.MustCompile(`splithttp: XHTTP is dialing to ([^,]+)`), StageDialExitStart, 1},
	{regexp.MustCompile(`vless/outbound: tunneling request to ([^ ]+) via ([^ ]+)`), StageTunnelUp, 0},
	{regexp.MustCompile(`proxy/socks: connecting to ([^ ]+) via`), StageWARPDialStart, 1},
	{regexp.MustCompile(`freedom/outbound.*connect`), StageDirectDialStart, 0},
}

// LogHandler implements common/log.Handler.
// Register it with xraylog.RegisterHandler after core.StartInstance.
type LogHandler struct {
	store *Store
}

// NewLogHandler returns a handler that feeds session events into store and
// also forwards every message to os.Stderr in xray's native log format.
func NewLogHandler(store *Store) *LogHandler {
	return &LogHandler{store: store}
}

// Handle is called for every xray log record.
func (h *LogHandler) Handle(msg xraylog.Message) {
	now := time.Now()

	// 1. Tee to stderr — preserve normal log output.
	// Format: "2006/01/02 15:04:05.000000 [Severity] [sessionID] component: text"
	fmt.Fprintf(os.Stderr, "%s %s\n", now.Format("2006/01/02 15:04:05.000000"), msg.String())

	// 2. Parse session ID and body from the message text.
	text := msg.String() // e.g. "[Info] [1024478894] app/dispatcher: sniffed domain: …"
	// Strip the leading "[Severity] " prefix that GeneralMessage.String() prepends.
	if idx := strings.Index(text, "] "); idx >= 0 {
		text = text[idx+2:] // now "[1024478894] app/dispatcher: …"
	}

	m := logLineRE.FindStringSubmatch(text)
	if m == nil {
		return // no session ID — not a per-connection event
	}
	idU64, err := strconv.ParseUint(m[1], 10, 32)
	if err != nil {
		return
	}
	sessionID := uint32(idU64)
	body := m[2] // "app/dispatcher: sniffed domain: …"

	// 3. Classify the event.
	stage, detail := classify(body)
	if stage == "" {
		return // unrecognised event — not interesting for timing
	}

	h.store.Append(sessionID, Event{At: now, Stage: stage, Detail: detail})
}

// classify returns the stage name and a detail string for the log body,
// or ("", "") if the line doesn't match any known event.
func classify(body string) (stage, detail string) {
	for _, c := range classifiers {
		m := c.re.FindStringSubmatch(body)
		if m == nil {
			continue
		}
		stage = c.stage
		switch {
		case c.capture > 0 && len(m) > c.capture:
			detail = m[c.capture]
		case stage == StageRoutingDecision && len(m) >= 3:
			// "taking detour [to-exit] for [tcp:example.com:443]"
			detail = m[1] + " → " + m[2]
		case stage == StageTunnelUp && len(m) >= 3:
			// "tunneling request to tcp:example.com:443 via 94.103.81.225:51001"
			detail = m[1] + " via " + m[2]
		default:
			detail = body
		}
		return
	}
	return "", ""
}
