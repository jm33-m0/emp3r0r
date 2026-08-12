//go:build windows

package coffloader

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"
	"unsafe"
)

func GetCoffOutputForChannel(channel chan<- interface{}) func(int, uintptr, int) uintptr {
	return func(beaconType int, data uintptr, length int) uintptr {
		if length <= 0 {
			return 0
		}
		out := ReadBytesFromPtr(data, uint32(length))

		channel <- string(out)
		return 1
	}
}

type formatBuffer struct {
	original uintptr
	buffer   uintptr
	length   int32
	size     int32
}

var (
	formatBuffers   = make(map[uintptr][]byte)
	formatBuffersMu sync.Mutex
)

func isLikelyWideString(ptr uintptr) bool {
	if ptr == 0 {
		return false
	}
	sample := ReadBytesFromPtr(ptr, 8)
	if len(sample) < 2 {
		return false
	}
	zeros := 0
	nonZeros := 0
	for i := 0; i+1 < len(sample); i += 2 {
		if sample[i] == 0 && sample[i+1] == 0 {
			break
		}
		if sample[i+1] == 0 {
			zeros++
		} else {
			nonZeros++
		}
	}
	return zeros > 0 && nonZeros == 0
}

func readCString(ptr uintptr, preferWide bool) string {
	if ptr == 0 {
		return ""
	}
	if preferWide || isLikelyWideString(ptr) {
		return ReadWStringFromPtr(ptr)
	}
	return ReadCStringFromPtr(ptr)
}

func formatPrintf(format string, args []uintptr) string {
	var builder strings.Builder
	argIndex := 0
	i := 0
	for i < len(format) {
		if format[i] != '%' {
			builder.WriteByte(format[i])
			i++
			continue
		}
		if i+1 < len(format) && format[i+1] == '%' {
			builder.WriteByte('%')
			i += 2
			continue
		}

		start := i
		i++

		flags := ""
		for i < len(format) && strings.ContainsRune("+-#0 ", rune(format[i])) {
			flags += string(format[i])
			i++
		}

		width := ""
		widthFromArg := false
		widthValue := 0
		if i < len(format) && format[i] == '*' {
			widthFromArg = true
			if argIndex < len(args) {
				widthValue = int(args[argIndex])
				argIndex++
			}
			i++
		} else {
			for i < len(format) && format[i] >= '0' && format[i] <= '9' {
				width += string(format[i])
				i++
			}
		}

		precision := ""
		precisionFromArg := false
		precisionValue := 0
		if i < len(format) && format[i] == '.' {
			precision = "."
			i++
			if i < len(format) && format[i] == '*' {
				precisionFromArg = true
				if argIndex < len(args) {
					precisionValue = int(args[argIndex])
					argIndex++
				}
				i++
			} else {
				for i < len(format) && format[i] >= '0' && format[i] <= '9' {
					precision += string(format[i])
					i++
				}
			}
		}

		length := ""
		switch {
		case i+2 < len(format) && format[i:i+3] == "I64":
			length = "I64"
			i += 3
		case i+1 < len(format) && format[i:i+2] == "ll":
			length = "ll"
			i += 2
		case i+1 < len(format) && format[i:i+2] == "hh":
			length = "hh"
			i += 2
		case i < len(format) && strings.ContainsRune("lhjztwL", rune(format[i])):
			length = string(format[i])
			i++
		}

		if i >= len(format) {
			builder.WriteString(format[start:])
			break
		}

		spec := format[i]
		i++

		if widthFromArg {
			if widthValue < 0 {
				if !strings.Contains(flags, "-") {
					flags += "-"
				}
				widthValue = -widthValue
			}
			width = strconv.Itoa(widthValue)
		}
		if precisionFromArg {
			if precisionValue >= 0 {
				precision = "." + strconv.Itoa(precisionValue)
			} else {
				precision = ""
			}
		}

		if argIndex >= len(args) {
			builder.WriteString(format[start:i])
			continue
		}

		switch spec {
		case 's':
			preferWide := length == "l" || length == "w" || length == "L"
			value := readCString(args[argIndex], preferWide)
			argIndex++
			builder.WriteString(fmt.Sprintf("%"+flags+width+precision+"s", value))
		case 'S':
			value := readCString(args[argIndex], true)
			argIndex++
			builder.WriteString(fmt.Sprintf("%"+flags+width+precision+"s", value))
		case 'c', 'C':
			value := rune(args[argIndex])
			argIndex++
			builder.WriteString(fmt.Sprintf("%"+flags+width+precision+"c", value))
		case 'p':
			value := unsafe.Pointer(args[argIndex])
			argIndex++
			builder.WriteString(fmt.Sprintf("%"+flags+width+precision+"p", value))
		case 'd', 'i':
			value := int64(args[argIndex])
			argIndex++
			builder.WriteString(fmt.Sprintf("%"+flags+width+precision+"d", value))
		case 'u':
			value := uint64(args[argIndex])
			argIndex++
			builder.WriteString(fmt.Sprintf("%"+flags+width+precision+"d", value))
		case 'x', 'X', 'o':
			value := uint64(args[argIndex])
			argIndex++
			builder.WriteString(fmt.Sprintf("%"+flags+width+precision+string(spec), value))
		case 'f', 'F', 'e', 'E', 'g', 'G':
			value := math.Float64frombits(uint64(args[argIndex]))
			argIndex++
			builder.WriteString(fmt.Sprintf("%"+flags+width+precision+string(spec), value))
		default:
			builder.WriteString(format[start:i])
		}
	}

	return builder.String()
}

func GetCoffPrintfForChannel(channel chan<- interface{}) func(int, uintptr, uintptr, uintptr) uintptr {
	return func(beaconType int, data uintptr, arg0 uintptr, arg1 uintptr) (res uintptr) {
		defer func() {
			if r := recover(); r != nil {
				res = 0
			}
		}()
		out := ReadCStringFromPtr(data)
		args := []uintptr{arg0, arg1}
		formatted := formatPrintf(out, args)
		channel <- formatted
		return 0
	}
}

// extractedBuffers keeps DataExtract allocations alive to prevent GC during BOF execution
var (
	extractedBuffers   = make(map[uintptr][]byte)
	extractedBuffersMu sync.Mutex
)

type DataParser struct {
	original uintptr
	buffer   uintptr
	length   uint32
	size     uint32
}

func DataExtract(datap *DataParser, size *uint32) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			res = 0
		}
	}()
	if datap == nil || datap.length < 4 || datap.buffer == 0 {
		return 0
	}

	binaryLength := *(*uint32)(unsafe.Pointer(datap.buffer))
	datap.buffer += uintptr(4)
	datap.length -= 4
	if datap.length < binaryLength {
		return 0
	}

	out := make([]byte, binaryLength)
	if binaryLength > 0 {
		CopyMemory(uintptr(unsafe.Pointer(&out[0])), datap.buffer, binaryLength)
	}
	if size != nil && unsafe.Pointer(size) != nil && binaryLength != 0 {
		*size = binaryLength
	}

	datap.buffer += uintptr(binaryLength)
	datap.length -= binaryLength
	if binaryLength == 0 {
		return 0
	}
	// Keep the buffer alive by storing it in a global map to prevent GC
	ptr := uintptr(unsafe.Pointer(&out[0]))
	extractedBuffersMu.Lock()
	extractedBuffers[ptr] = out
	extractedBuffersMu.Unlock()
	return ptr
}

func DataInt(datap *DataParser) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			res = 0
		}
	}()
	if datap == nil || datap.length < 4 || datap.buffer == 0 {
		return 0
	}
	value := ReadUIntFromPtr(datap.buffer)
	datap.buffer += uintptr(4)
	datap.length -= 4
	return uintptr(value)
}

func DataLength(datap *DataParser) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			res = 0
		}
	}()
	if datap == nil {
		return 0
	}
	return uintptr(datap.length)
}

func DataParse(datap *DataParser, buff uintptr, size uint32) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			res = 0
		}
	}()
	if datap == nil || buff == 0 || size <= 4 {
		return 0
	}
	datap.original = buff
	datap.buffer = buff + uintptr(4)
	datap.length = size - 4
	datap.size = size - 4
	return 1
}

func DataShort(datap *DataParser) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			res = 0
		}
	}()
	if datap == nil || datap.length < 2 || datap.buffer == 0 {
		return 0
	}

	value := ReadShortFromPtr(datap.buffer)
	datap.buffer += uintptr(2)
	datap.length -= 2
	return uintptr(value)
}

var (
	keyStore   = make(map[string]uintptr)
	keyStoreMu sync.RWMutex
)

func AddValue(key uintptr, ptr uintptr) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			res = 0
		}
	}()
	if key == 0 {
		return 0
	}
	sKey := ReadCStringFromPtr(key)
	keyStoreMu.Lock()
	keyStore[sKey] = ptr
	keyStoreMu.Unlock()
	return uintptr(1)
}

func GetValue(key uintptr) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			res = 0
		}
	}()
	if key == 0 {
		return 0
	}
	sKey := ReadCStringFromPtr(key)
	keyStoreMu.RLock()
	val, exists := keyStore[sKey]
	keyStoreMu.RUnlock()
	if exists {
		return val
	}
	return uintptr(0)
}

func RemoveValue(key uintptr) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			res = 0
		}
	}()
	if key == 0 {
		return 0
	}
	sKey := ReadCStringFromPtr(key)
	keyStoreMu.Lock()
	if _, exists := keyStore[sKey]; exists {
		delete(keyStore, sKey)
		keyStoreMu.Unlock()
		return uintptr(1)
	}
	keyStoreMu.Unlock()
	return uintptr(0)
}

// BeaconGetSpawnToStub fills the provided buffer with the default spawn-to
// process path for the requested architecture. This is a best-effort stub
// for BOFs that need to know the spawn-to binary (injection BOFs, etc.).
func BeaconGetSpawnToStub(x86 uintptr, buffer uintptr, length int32) uintptr {
	if buffer == 0 || length <= 0 {
		return 0
	}
	var spawnTo string
	if x86 != 0 {
		spawnTo = `C:\Windows\SysWOW64\cmd.exe`
	} else {
		spawnTo = `C:\Windows\System32\cmd.exe`
	}
	// Copy with null terminator, truncating if needed
	b := []byte(spawnTo)
	maxLen := int(length) - 1
	if maxLen > len(b) {
		maxLen = len(b)
	}
	copy((*[1 << 30]byte)(unsafe.Pointer(buffer))[:maxLen], b[:maxLen])
	*(*byte)(unsafe.Pointer(buffer + uintptr(maxLen))) = 0
	return 1
}

func swapEndianness(indata uint32) uint32 {
	return (indata>>24)&0x000000ff |
		(indata>>8)&0x0000ff00 |
		(indata<<8)&0x00ff0000 |
		(indata<<24)&0xff000000
}

func getFormatBuffer(format *formatBuffer) ([]byte, bool) {
	if format == nil {
		return nil, false
	}
	formatPtr := uintptr(unsafe.Pointer(format))
	formatBuffersMu.Lock()
	buf, ok := formatBuffers[formatPtr]
	formatBuffersMu.Unlock()
	return buf, ok
}

func appendToFormatBuffer(format *formatBuffer, data []byte) uintptr {
	if format == nil {
		return 0
	}
	buf, ok := getFormatBuffer(format)
	if !ok {
		return 0
	}
	if format.size <= 0 {
		return 0
	}
	used := int(format.buffer - format.original)
	if used < 0 || used > len(buf) {
		return 0
	}
	if used+len(data) > len(buf) {
		return 0
	}
	copy(buf[used:], data)
	used += len(data)
	format.buffer = format.original + uintptr(used)
	format.length = int32(used)
	return 1
}

func BeaconFormatAlloc(format *formatBuffer, maxsz int32) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			res = 0
		}
	}()
	if format == nil || maxsz <= 0 {
		return 0
	}
	buf := make([]byte, maxsz)
	format.original = uintptr(unsafe.Pointer(&buf[0]))
	format.buffer = format.original
	format.length = 0
	format.size = maxsz

	formatPtr := uintptr(unsafe.Pointer(format))
	formatBuffersMu.Lock()
	formatBuffers[formatPtr] = buf
	formatBuffersMu.Unlock()
	return 1
}

func BeaconFormatReset(format *formatBuffer) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			res = 0
		}
	}()
	if format == nil {
		return 0
	}
	buf, ok := getFormatBuffer(format)
	if !ok {
		return 0
	}
	for i := range buf {
		buf[i] = 0
	}
	format.buffer = format.original
	format.length = 0
	return 1
}

func BeaconFormatFree(format *formatBuffer) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			res = 0
		}
	}()
	if format == nil {
		return 0
	}
	formatPtr := uintptr(unsafe.Pointer(format))
	formatBuffersMu.Lock()
	delete(formatBuffers, formatPtr)
	formatBuffersMu.Unlock()

	format.original = 0
	format.buffer = 0
	format.length = 0
	format.size = 0
	return 1
}

func BeaconFormatAppend(format *formatBuffer, text uintptr, length int32) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			res = 0
		}
	}()
	if format == nil || text == 0 || length <= 0 {
		return 0
	}
	data := ReadBytesFromPtr(text, uint32(length))
	return appendToFormatBuffer(format, data)
}

func BeaconFormatPrintf(format *formatBuffer, fmtPtr uintptr, arg0 uintptr, arg1 uintptr) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			res = 0
		}
	}()
	if format == nil || fmtPtr == 0 {
		return 0
	}
	fmtString := ReadCStringFromPtr(fmtPtr)
	args := []uintptr{arg0, arg1}
	formatted := formatPrintf(fmtString, args)
	return appendToFormatBuffer(format, []byte(formatted))
}

func BeaconFormatToString(format *formatBuffer, size *int32) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			res = 0
		}
	}()
	if format == nil {
		return 0
	}
	if size != nil && unsafe.Pointer(size) != nil {
		*size = format.length
	}
	return format.original
}

func BeaconFormatInt(format *formatBuffer, value int32) (res uintptr) {
	defer func() {
		if r := recover(); r != nil {
			res = 0
		}
	}()
	if format == nil {
		return 0
	}
	buf, ok := getFormatBuffer(format)
	if !ok {
		return 0
	}
	if format.size <= 0 {
		return 0
	}
	used := int(format.buffer - format.original)
	if used < 0 || used > len(buf) {
		return 0
	}
	if used+4 > len(buf) {
		return 0
	}
	swapped := swapEndianness(uint32(value))
	binary.LittleEndian.PutUint32(buf[used:used+4], swapped)
	used += 4
	format.buffer = format.original + uintptr(used)
	format.length = int32(used)
	return 1
}

func LighthousePackArgs(data []string) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	var buff []byte
	for _, arg := range data {
		switch arg[0] {
		case 'b':
			data, err := PackBinary(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("Binary packing error:\n INPUT: '%s'\n ERROR:%s\n", arg[1:], err)
			}
			buff = append(buff, data...)
		case 'i':
			data, err := PackIntString(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("Int packing error:\n INPUT: '%s'\n ERROR:%s\n", arg[1:], err)
			}
			buff = append(buff, data...)
		case 's':
			data, err := PackShortString(arg[1:])
			if err != nil {
				return nil, fmt.Errorf("Short packing error:\n INPUT: '%s'\n ERROR:%s\n", arg[1:], err)
			}
			buff = append(buff, data...)
		case 'z':
			var packedData []byte
			var err error
			// Handler for packing empty strings
			if len(arg) < 2 {
				packedData, _ = PackString("")
			} else {
				packedData, err = PackString(arg[1:])
				if err != nil {
					return nil, fmt.Errorf("String packing error:\n INPUT: '%s'\n ERROR:%s\n", arg[1:], err)
				}
			}
			buff = append(buff, packedData...)
		case 'Z':
			var packedData []byte
			var err error
			if len(arg) < 2 {
				packedData, _ = PackWideString("")
			} else {
				packedData, err = PackWideString(arg[1:])
				if err != nil {
					return nil, fmt.Errorf("WString packing error:\n INPUT: '%s'\n ERROR:%s\n", arg[1:], err)
				}
			}
			buff = append(buff, packedData...)
		default:
			return nil, fmt.Errorf("Data must be prefixed with 'b', 'i', 's','z', or 'Z'\n")
		}
	}
	rData := make([]byte, 4)
	binary.LittleEndian.PutUint32(rData, uint32(len(buff)))
	rData = append(rData, buff...)
	return rData, nil
}

func PackBinary(data string) ([]byte, error) {
	hexData, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(hexData)))
	buff = append(buff, hexData...)
	return buff, nil
}

func PackInt(i uint32) ([]byte, error) {
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(i))
	return buff, nil
}

func PackIntString(s string) ([]byte, error) {
	i, err := strconv.ParseUint(s, 10, 32)
	if err != nil {
		return nil, err
	}
	return PackInt(uint32(i))
}

func PackShort(i uint16) ([]byte, error) {
	buff := make([]byte, 2)
	binary.LittleEndian.PutUint16(buff, uint16(i))
	return buff, nil
}

func PackShortString(s string) ([]byte, error) {
	i, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return nil, err
	}
	return PackShort(uint16(i))
}

func PackString(s string) ([]byte, error) {
	b := []byte(s)
	buff := make([]byte, 4)
	// Length includes the null terminator, matching the standard BOF arg format.
	binary.LittleEndian.PutUint32(buff, uint32(len(b)+1))
	buff = append(buff, b...)
	buff = append(buff, 0)
	return buff, nil
}

func convertToWindowsUnicode(s string) []byte {
	runes := []rune(s)
	utf16Encoded := utf16.Encode(runes)
	buf := make([]byte, len(utf16Encoded)*2)
	for i, utf16Char := range utf16Encoded {
		binary.LittleEndian.PutUint16(buf[i*2:], utf16Char)
	}
	return buf
}

func PackWideString(s string) ([]byte, error) {
	d := convertToWindowsUnicode(s)
	buff := make([]byte, 4)
	binary.LittleEndian.PutUint32(buff, uint32(len(d)))
	buff = append(buff, d...)
	return buff, nil
}
