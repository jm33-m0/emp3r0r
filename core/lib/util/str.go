package util

import (
	"crypto/md5"
	crypto_rand "crypto/rand"
	"encoding/csv"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

// ParseCmd parse commands containing whitespace
func ParseCmd(cmd string) (parsedCmd []string) {
	isQuoted := strings.Contains(cmd, "'") && strings.Count(cmd, "'")%2 == 0 && !strings.Contains(cmd, "\\")
	isEscaped := strings.Contains(cmd, "\\")
	isDoubleQuoted := strings.Contains(cmd, "\"") && strings.Count(cmd, "\"")%2 == 0

	space := uuid.NewString()
	tab := uuid.NewString()

	if isEscaped && (isQuoted || isDoubleQuoted) {
		cmd = strings.ReplaceAll(cmd, "\\ ", space)
		cmd = strings.ReplaceAll(cmd, "\\t", tab)
		parsedCmd = parseQuotedCmd(cmd)
		for n, arg := range parsedCmd {
			parsedCmd[n] = strings.ReplaceAll(strings.ReplaceAll(arg, space, " "), tab, "\t")
		}
		return
	}

	if isEscaped {
		return parseEscapedCmd(cmd, space, tab)
	}

	if isQuoted || isDoubleQuoted {
		return parseQuotedCmd(cmd)
	}

	return strings.Fields(cmd)
}

func parseEscapedCmd(cmd, space, tab string) (parsedCmd []string) {
	temp := strings.ReplaceAll(cmd, "\\ ", space)
	temp = strings.ReplaceAll(temp, "\\t", tab)
	parsedCmd = strings.Fields(temp)
	for n, arg := range parsedCmd {
		parsedCmd[n] = strings.ReplaceAll(strings.ReplaceAll(arg, space, " "), tab, "\t")
	}
	return
}

func parseQuotedCmd(cmd string) (parsedCmd []string) {
	cmd = strings.ReplaceAll(cmd, "'", `"`) // use double quotes
	r := csv.NewReader(strings.NewReader(cmd))
	r.Comma = ' ' // space
	r.LazyQuotes = true
	fields, err := r.Read()
	if err != nil {
		logging.Debugf("ParseCmd: %v", err)
		return
	}
	for _, f := range fields {
		parsedCmd = append(parsedCmd, strings.TrimSpace(f))
	}
	return
}

func ReverseString(s string) string {
	rns := []rune(s) // convert to rune
	for i, j := 0, len(rns)-1; i < j; i, j = i+1, j-1 {
		rns[i], rns[j] = rns[j], rns[i]
	}
	return string(rns)
}

// Split long lines
func SplitLongLine(line string, linelen int) (ret string) {
	// No-op: return the original line without wrapping
	return line
}

// RandInt random int between given interval
func RandInt(min, max int) int {
	if min >= max || min < 0 || max < 0 {
		min = RandInt(0, 100)
		max = min + RandInt(1, 100)
	}

	bg := big.NewInt(int64(max - min))
	n, err := crypto_rand.Int(crypto_rand.Reader, bg)
	if err != nil {
		logging.Println("falling back to math/rand with time seed")
		return min + rand.New(rand.NewSource(time.Now().UnixNano())).Intn(max-min)
	}
	return min + int(n.Int64())
}

// RandStr random string
func RandStr(n int) string {
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[int64(RandInt(0, len(letters)))]
	}
	return string(b)
}

// RandMD5String random MD5 string for agent file names
func RandMD5String() string {
	randBytes := RandBytes(16)
	return fmt.Sprintf("%x", md5.Sum(randBytes))
}

// Random bytes
func RandBytes(n int) []byte {
	var allBytes []byte
	for b := 1; b <= 255; b++ {
		allBytes = append(allBytes, byte(b))
	}
	randBytes := make([]byte, n)
	for i := range randBytes {
		randBytes[i] = allBytes[int64(RandInt(0, len(allBytes)))]
	}
	return randBytes
}

// HexEncode hex encode string, eg. "Hello" -> "\x48\x65\x6c\x6c\x6f"
func HexEncode(s string) (result string) {
	for _, c := range s {
		result = fmt.Sprintf("%s\\x%x", result, c)
	}
	return
}

// LogStreamPrintf logs a message to the console and sends it to a log stream channel.
// Useful when agent wants to send back responses in real-time.
func LogStreamPrintf(logStream chan string, format string, v ...any) {
	logging.Debugf(format, v...)
	logStream <- fmt.Sprintf(format, v...)
}

// ParseEnvStr parses a string of environment variables in the format "VAR1=VAL1,VAR2=VAL2"
// and returns a map where the keys are the variable names and the values are the variable values.
func ParseEnvStr(envStr string) (envMap map[string]string) {
	envMap = make(map[string]string)
	lines := strings.Split(envStr, ",")
	for _, line := range lines {
		if strings.Contains(line, "=") {
			parts := strings.SplitN(line, "=", 2)
			key := strings.TrimSpace(parts[0])
			value := ""
			if len(parts) > 1 {
				value = strings.TrimSpace(parts[1])
			}
			envMap[key] = value
		}
	}
	return
}

// LimitString limits the length of a string
// It returns the string truncated to length n if it's longer than n
func LimitString(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
