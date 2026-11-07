package def

// OpsecProfile is optional manifest metadata describing a module's operational
// footprint. It is advisory input to the deterministic OPSEC reviewer; it never
// changes how a module runs.
type OpsecProfile struct {
	Noise              string   `json:"noise,omitempty" cbor:"1,keyasint"` // low, medium, high
	WritesDisk         bool     `json:"writes_disk,omitempty" cbor:"2,keyasint"`
	NetworkEgress      []string `json:"network_egress,omitempty" cbor:"3,keyasint"`
	TouchesCredentials bool     `json:"touches_credentials,omitempty" cbor:"4,keyasint"`
	RequiresAdmin      bool     `json:"requires_admin,omitempty" cbor:"5,keyasint"`
	Artifacts          []string `json:"artifacts,omitempty" cbor:"6,keyasint"`
	Reversible         *bool    `json:"reversible,omitempty" cbor:"7,keyasint"`
	Notes              string   `json:"notes,omitempty" cbor:"8,keyasint"`
}

// OpsecReview is the deterministic footprint of a proposed action. It reports
// which capability rules matched, the telemetry they produce, the noise band,
// and whether the action changes target state. Policy decisions use the
// individual capability rules.
type OpsecReview struct {
	Reasons    []string `json:"reasons,omitempty" cbor:"2,keyasint"`
	Artifacts  []string `json:"artifacts,omitempty" cbor:"3,keyasint"`
	Noise      string   `json:"noise,omitempty" cbor:"4,keyasint"` // low, medium, high
	Reversible bool     `json:"reversible" cbor:"5,keyasint"`
	Requires   []string `json:"requires,omitempty" cbor:"6,keyasint"`
	Unknowns   []string `json:"unknowns,omitempty" cbor:"7,keyasint"`
	Rules      []string `json:"rules,omitempty" cbor:"8,keyasint"`
}
