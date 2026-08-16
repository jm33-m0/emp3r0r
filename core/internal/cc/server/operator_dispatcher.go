package server

import (
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// operationDispatcher routes operator API requests to the correct handler.
// This is the OPERATOR-facing dispatcher (mTLS channel, untouched by C2 refactor).
func operationDispatcher(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			if r == http.ErrAbortHandler {
				return
			}
			logging.Errorf("operationDispatcher panicked: %v", r)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}()
	touchOperatorCommand()
	vars := mux.Vars(r)
	api := vars["api"]
	logging.Debugf("Operator request: API: %s", api)

	api = fmt.Sprintf("%s/%s", transport.OperatorRoot, api)
	switch api {
	case transport.OperatorMsgTunnel:
		handleOperatorConn(w, r)
	case transport.OperatorSetActiveAgent:
		handleSetActiveAgent(w, r)
	case transport.OperatorSendCommand:
		handleSendCommand(w, r)
	case transport.OperatorListConnectedAgents:
		handleListAgents(w, r)
	case transport.OperatorForgetAgent:
		handleForgetAgent(w, r)
	case transport.OperatorRegisterFTPStream:
		handleRegisterFTPStream(w, r)
	case transport.OperatorUnregisterFTPStream:
		handleUnregisterFTPStream(w, r)
	case transport.OperatorUpdateConfig:
		handleUpdateOperatorIdleConfig(w, r)
	case transport.OperatorResume:
		handleResumeOperator(w, r)
	case transport.OperatorGetCA:
		handleGetCA(w, r)
	case transport.OperatorSignAgent:
		handleSignAgent(w, r)
	default:
		http.Error(w, fmt.Sprintf("Invalid API: %s", api), http.StatusNotFound)
	}
}
