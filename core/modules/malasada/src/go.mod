module malasada

go 1.25

require (
	github.com/moloch--/go-keystone v0.0.2
	github.com/tetratelabs/wazero v1.12.0
	golang.org/x/sys v0.47.0
)

replace github.com/moloch--/go-keystone => ./third_party/go-keystone

replace github.com/tetratelabs/wazero => ./third_party/wazero

replace golang.org/x/sys => ./third_party/x-sys
