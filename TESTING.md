# Testing Guide for emp3r0r

This document provides information on how to run and write tests for the emp3r0r project.

## Running Tests

### Run All Tests

To run all tests in the project:

```bash
cd core
go test ./...
```

### Run Tests for Specific Packages

To run tests for specific packages:

```bash
cd core
go test ./lib/util/...
go test ./lib/crypto/...
go test ./lib/sysinfo/...
```

### Run Tests with Coverage

To run tests and generate a coverage report:

```bash
cd core
go test -cover ./...
```

For detailed coverage information:

```bash
cd core
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

This will open an HTML report showing which lines of code are covered by tests.

### Run Tests with Verbose Output

To see detailed output from each test:

```bash
cd core
go test -v ./...
```

### Run Specific Tests

To run a specific test function:

```bash
cd core
go test -v -run TestFunctionName ./lib/util/...
```

To run tests matching a pattern:

```bash
cd core
go test -v -run "TestParseCmd.*" ./lib/util/...
```

### Run Tests with Race Detector

To detect race conditions in concurrent code:

```bash
cd core
go test -race ./...
```

## Platform-Specific Tests

Some tests are platform-specific and use build tags.

### Linux-Only Tests

Tests in `lib/sysinfo/virt_test.go` are Linux-only:

```bash
cd core
go test -tags linux ./lib/sysinfo/...
```

On non-Linux platforms, these tests will be skipped automatically.

## Writing Tests

### Test File Naming

- Test files should be named `*_test.go`
- Place test files in the same package as the code being tested
- Example: `str.go` → `str_test.go`

### Test Function Naming

- Test functions must start with `Test`
- Use descriptive names: `TestParseCmdWithQuotes`
- Benchmark functions start with `Benchmark`
- Example functions start with `Example`

### Table-Driven Tests

Use table-driven tests for testing multiple scenarios:

```go
func TestParseCmd(t *testing.T) {
    tests := []struct {
        name     string
        input    string
        expected []string
    }{
        {
            name:     "simple command",
            input:    "ls -la",
            expected: []string{"ls", "-la"},
        },
        // Add more test cases...
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            result := ParseCmd(tt.input)
            if !reflect.DeepEqual(result, tt.expected) {
                t.Errorf("got %v, want %v", result, tt.expected)
            }
        })
    }
}
```

### Test Helpers

Use the `testutil` package for common test utilities:

```go
import "github.com/jm33-m0/emp3r0r/core/lib/testutil"

func TestExample(t *testing.T) {
    tmpDir := testutil.TempDir(t)
    filePath := testutil.CreateTempFile(t, tmpDir, "test.txt", "content")
    
    testutil.AssertEqual(t, result, expected)
    testutil.AssertNoError(t, err)
}
```

### Platform-Specific Tests

Use build tags for platform-specific tests:

```go
//go:build linux
// +build linux

package sysinfo

import "testing"

func TestLinuxSpecificFunction(t *testing.T) {
    // Test code here
}
```

### Testing Best Practices

1. **Test both success and failure cases**: Include tests for error conditions
2. **Use descriptive test names**: Make it clear what each test is checking
3. **Keep tests independent**: Tests should not depend on each other
4. **Use subtests**: Group related tests using `t.Run()`
5. **Clean up resources**: Use `t.Cleanup()` or `defer` for cleanup
6. **Avoid external dependencies**: Mock external services where possible
7. **Test edge cases**: Empty strings, nil values, boundary conditions
8. **Use t.Helper()**: Mark helper functions with `t.Helper()` for better error messages

### Security Testing

For cryptographic and security-sensitive functions:

1. Use known test vectors where available
2. Test with invalid inputs (fuzzing candidates)
3. Verify proper error handling
4. Test boundary conditions
5. Ensure no secrets are logged

### Coverage Goals

- Aim for >70% code coverage for tested packages
- Focus on critical paths and security-sensitive code
- Don't sacrifice test quality for coverage percentage

## CI/CD Integration

Tests run automatically on:
- Push to main/master/develop branches
- Pull requests to main/master/develop branches

The CI pipeline:
- Tests on multiple Go versions (1.21, 1.22, 1.23)
- Tests on multiple platforms (Linux, macOS, Windows)
- Runs race detector
- Generates coverage reports
- Runs linters

### Checking CI Status

View test results in the GitHub Actions tab of the repository.

## Benchmarking

To run benchmarks:

```bash
cd core
go test -bench=. ./lib/util/...
```

To compare benchmarks:

```bash
cd core
go test -bench=. ./lib/util/... > old.txt
# Make changes
go test -bench=. ./lib/util/... > new.txt
go install golang.org/x/perf/cmd/benchstat@latest
benchstat old.txt new.txt
```

## Troubleshooting

### Tests Fail on Windows

Some tests may be Linux/macOS specific. Check for build tags and platform-specific code.

### Race Detector Failures

If `-race` flag causes failures, investigate concurrent access to shared variables.

### Coverage Too Low

Focus on:
1. Error paths that aren't tested
2. Edge cases
3. Complex conditional logic

### Import Cycle Errors

If you get import cycle errors in tests:
- Create a separate `_test` package
- Example: `package util_test` instead of `package util`

## Additional Resources

- [Go Testing Documentation](https://golang.org/pkg/testing/)
- [Table-Driven Tests](https://github.com/golang/go/wiki/TableDrivenTests)
- [Go Test Coverage](https://go.dev/blog/cover)
- [Testify Package](https://github.com/stretchr/testify) (if you want to use it)

## Contributing Tests

When contributing code:
1. Write tests for new functionality
2. Ensure existing tests pass
3. Add tests for bug fixes
4. Update this documentation if needed

For questions or issues with tests, please open an issue on GitHub.
