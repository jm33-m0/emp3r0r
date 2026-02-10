package server

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/fxamacker/cbor/v2"
	"github.com/jm33-m0/emp3r0r/core/internal/def"
	"github.com/jm33-m0/emp3r0r/core/internal/transport"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

func handleSignAgent(wrt http.ResponseWriter, req *http.Request) {
	var signReq def.SignRequest
	decoder := cbor.NewDecoder(req.Body)
	if err := decoder.Decode(&signReq); err != nil {
		logging.Errorf("handleSignAgent: failed to decode request: %v", err)
		http.Error(wrt, "Failed to decode request", http.StatusBadRequest)
		return
	}

	if len(signReq.Content) == 0 {
		http.Error(wrt, "Empty content", http.StatusBadRequest)
		return
	}

	// Sign the content (UUID)
	sig, err := transport.SignWithCAKey(signReq.Content)
	if err != nil {
		logging.Errorf("handleSignAgent: failed to sign content: %v", err)
		http.Error(wrt, fmt.Sprintf("Failed to sign content: %v", err), http.StatusInternalServerError)
		return
	}

	// Base64 encode the signature
	sigStr := base64.URLEncoding.EncodeToString(sig)

	data, err := cbor.Marshal(sigStr)
	if err != nil {
		logging.Errorf("handleSignAgent: failed to marshal response: %v", err)
		http.Error(wrt, "Failed to marshal response", http.StatusInternalServerError)
		return
	}

	wrt.Header().Set("Content-Type", "application/cbor")
	wrt.WriteHeader(http.StatusOK)
	wrt.Write(data)
}
