package server

import (
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jm33-m0/emp3r0r/core/internal/cc/config"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/live"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// lastOperatorCommand stores the UnixNano timestamp of the last command
// dispatched by any operator. It is updated by handleSendCommand and read by
// the message-tunnel admission/teardown logic.
var lastOperatorCommand int64

// touchOperatorCommand marks the operator as active right now.
func touchOperatorCommand() {
	atomic.StoreInt64(&lastOperatorCommand, time.Now().UnixNano())
}

// operatorIsActive reports whether the operator is still within the configured
// idle timeout. A non-positive timeout disables idle-based rejection.
func operatorIsActive() bool {
	timeout := live.RuntimeConfig.OperatorIdleTimeout
	if timeout <= 0 {
		return true
	}
	last := atomic.LoadInt64(&lastOperatorCommand)
	if last == 0 {
		return false
	}
	return time.Since(time.Unix(0, last)) <= time.Duration(timeout)*time.Second
}

// handleUpdateOperatorIdleConfig updates the server-side operator idle timeout.
func handleUpdateOperatorIdleConfig(wrt http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			logging.Errorf("handleUpdateOperatorIdleConfig panicked: %v", r)
			http.Error(wrt, "Internal server error", http.StatusInternalServerError)
		}
	}()

	cfg, err := DecodeCBORBody[def.OperatorIdleConfig](wrt, req)
	if err != nil {
		return
	}
	if cfg.OperatorIdleTimeout < 0 {
		http.Error(wrt, "OperatorIdleTimeout must be >= 0", http.StatusBadRequest)
		return
	}

	live.RuntimeConfig.OperatorIdleTimeout = cfg.OperatorIdleTimeout
	if err := config.SaveConfigJSON(); err != nil {
		http.Error(wrt, err.Error(), http.StatusInternalServerError)
		return
	}
	logging.Infof("Operator idle timeout updated to %d seconds", cfg.OperatorIdleTimeout)
	wrt.WriteHeader(http.StatusOK)
}
