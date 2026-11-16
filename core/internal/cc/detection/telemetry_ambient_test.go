package detection

import "testing"

func TestAmbientImageClassification(t *testing.T) {
	cases := []struct {
		name   string
		image  string
		role   string
		stack  string
		expect bool
	}{
		{name: "rededr dll", image: "RedEdrDll.dll", expect: true},
		{name: "rededr path", image: `C:\RedEdr\RedEdrDll.dll`, expect: true},
		{name: "scanner path", image: `C:\LitterBox\Scanners\Moneta.exe`, expect: true},
		{name: "msvc runtime", image: "MSVCP140.dll", expect: true},
		{name: "vcruntime", image: "VCRUNTIME140.dll", expect: true},
		{name: "apphelp", image: "apphelp.dll", expect: true},
		{name: "rededr stack", image: "unknown.dll", stack: "RedEdrDll!Hook", expect: true},
		{name: "ambient role", image: "payload-child.dll", role: "ambient", expect: true},
		{name: "payload image", image: `C:\Users\test\AppData\Local\Temp\loader.dll`, expect: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAmbientImage(tc.image, tc.role, tc.stack); got != tc.expect {
				t.Fatalf("isAmbientImage(%q, %q, %q) = %v, want %v", tc.image, tc.role, tc.stack, got, tc.expect)
			}
		})
	}
}

func TestNoiseFindingIsNotActionable(t *testing.T) {
	finding := Finding{
		Stage: StageTelemetry, Severity: "medium", Rule: "telemetry/user-module",
		Signal: "noise", Sources: []SourceLocation{{File: "loader.c"}},
	}
	if actionableFinding(finding) {
		t.Fatal("noise finding is actionable")
	}
	finding.Signal = "signal"
	if !actionableFinding(finding) {
		t.Fatal("signal finding was ignored")
	}
}
