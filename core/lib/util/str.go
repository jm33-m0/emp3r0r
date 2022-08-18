package util

import (
	crypto_rand "crypto/rand"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ParseCmd parse commands containing whitespace
func ParseCmd(cmd string) (parsed_cmd []string) {
	is_quoted := strings.Contains(cmd, "'") && strings.Count(cmd, "'")%2 == 0 && !strings.Contains(cmd, "\\")
	is_escaped := strings.Contains(cmd, "\\")
	if !is_escaped && !is_quoted {
		return strings.Fields(cmd)
	}
	space := uuid.NewString()
	tab := uuid.NewString()

	// process cmds that looks like: cat /tmp/name\ with\ spaces.bin
	if is_escaped {
		temp := strings.ReplaceAll(cmd, "\\ ", space)
		temp = strings.ReplaceAll(temp, "\\t", tab)
		parsed_cmd = strings.Fields(temp)
		for n, arg := range parsed_cmd {
			parsed_cmd[n] = strings.ReplaceAll(strings.ReplaceAll(arg, space, " "), tab, "\t")
		}
		return
	}

	// process cmds that looks like: cat '/tmp/name with spaces.bin'
	if is_quoted {
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
			parsed_cmd = append(parsed_cmd, strings.TrimSpace(f))
		}
		return
	}

	return
}

func ReverseString(s string) string {
	rns := []rune(s) // convert to rune
	for i, j := 0, len(rns)-1; i < j; i, j = i+1, j-1 {
		// swap the letters of the string,
		// like first with last and so on.
		rns[i], rns[j] = rns[j], rns[i]
	}

	// return the reversed string.
	return string(rns)
}

// Split long lines
func SplitLongLine(line string, linelen int) (ret string) {
	if len(line) < linelen {
		return line
	}
	ret = line[:linelen]

	temp := ""
	for n, c := range line[linelen:] {
		if n >= linelen && n%linelen == 0 {
			ret = fmt.Sprintf("%s\n%s", ret, temp)
			temp = ""
		}
		temp += string(c)
	}
	ret = fmt.Sprintf("%s\n%s", ret, temp)
	temp = ""

	return
}

// RandInt random int between given interval
func RandInt(min, max int) int {
	// if we get nonsense values
	// give them random int anyway
	if min > max ||
		min < 0 ||
		max < 0 {
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
	rand.Seed(int64(binary.LittleEndian.Uint64(b[:])))
	return min + rand.Intn(max-min)
}

// RandStr random string
func RandStr(n int) string {
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	rand.Seed(int64(RandInt(0xff, 0xffffffff)))
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[int64(RandInt(0, len(letters)))]
	}
	return string(b)
}

// HexEncode hex encode string, eg. "Hello" -> "\x48\x65\x6c\x6c\x6f"
func HexEncode(s string) (result string) {
	for _, c := range s {
		result = fmt.Sprintf("%s\\x%x", result, c)
	}
	return
}
