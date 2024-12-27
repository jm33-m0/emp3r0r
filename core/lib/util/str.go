package util

import (
	"crypto/md5"
	crypto_rand "crypto/rand"
	"encoding/csv"
	"fmt"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/muesli/reflow/wordwrap"
	"github.com/muesli/reflow/wrap"
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
		log.Printf("ParseCmd: %v", err)
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
	ret = wordwrap.String(line, linelen)

	lines := strings.Split(ret, "\n")
	for _, wline := range lines {
		if len(wline) > linelen {
			ret = wrap.String(line, linelen)
			break
		}
	}
	return
}

// RandInt random int between given interval
func RandInt(min, max int) int {
	if min > max || min < 0 || max < 0 {
		min = RandInt(0, 100)
		max = min + RandInt(0, 100)
	}

	var b [8]byte
	_, err := crypto_rand.Read(b[:])
	if err != nil {
		log.Println("cannot seed math/rand package with cryptographically secure random number generator")
		log.Println("falling back to math/rand with time seed")
		return rand.New(rand.NewSource(time.Now().UnixNano())).Intn(max-min) + min
	}
	return min + rand.Intn(max-min)
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

func LogFilePrintf(filepath, format string, v ...any) {
	logf, err := os.OpenFile(filepath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	defer logf.Close()
	if err != nil {
		log.Printf("LogFilePrintf: %v", err)
		return
	}
	log.Printf(format, v...)

	fmt.Fprintf(logf, "%v\n", time.Now().String())
	fmt.Fprintf(logf, format, v...)
	fmt.Fprintf(logf, "\n")
}
