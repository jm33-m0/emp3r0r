//go:build windows

package script

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// dummyLDAPServer is a minimal LDAP v3 server used to exercise the starlark
// ldapsearch module end-to-end. It accepts a simple bind and returns two dummy
// person entries for any non-root search. It speaks just enough BER/LDAP for
// wldap32's bind and search calls.
type dummyLDAPServer struct {
	ln   net.Listener
	done chan struct{}
}

func startDummyLDAP(t *testing.T) *dummyLDAPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:389")
	if err != nil {
		t.Skipf("cannot listen on 389 for dummy LDAP server: %v", err)
	}
	s := &dummyLDAPServer{ln: ln, done: make(chan struct{})}
	go s.serve()
	return s
}

func (s *dummyLDAPServer) close() {
	close(s.done)
	_ = s.ln.Close()
}

func (s *dummyLDAPServer) serve() {
	for {
		select {
		case <-s.done:
			return
		default:
		}
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *dummyLDAPServer) handle(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	for {
		select {
		case <-s.done:
			return
		default:
		}
		msgID, opTag, err := readLDAPMessage(r)
		if err != nil {
			return
		}
		switch opTag {
		case 0x60: // BindRequest
			_ = writeMessage(conn, msgID, tlv(0x61, bindResponse()))
		case 0x63: // SearchRequest
			for _, entry := range dummyEntries() {
				if err := writeMessage(conn, msgID, tlv(0x64, entry)); err != nil {
					return
				}
			}
			_ = writeMessage(conn, msgID, tlv(0x65, searchDone()))
		default:
			// Ignore unbind/abandon/etc.
		}
	}
}

func bindResponse() []byte {
	// BindResponse ::= [APPLICATION 1] SEQUENCE {
	//   resultCode ENUMERATED { success(0), ... },
	//   matchedDN OCTET STRING,
	//   errorMessage OCTET STRING }
	return concat(
		tlv(0x0A, []byte{0}), // ENUMERATED success
		tlv(0x04, nil),       // matchedDN
		tlv(0x04, nil),       // errorMessage
	)
}

func searchDone() []byte {
	return concat(
		tlv(0x0A, []byte{0}), // resultCode success
		tlv(0x04, nil),       // matchedDN
		tlv(0x04, nil),       // errorMessage
	)
}

func dummyEntries() [][]byte {
	type attr struct {
		name string
		vals []string
	}
	type entry struct {
		dn    string
		attrs []attr
	}
	entries := []entry{
		{
			dn: "CN=Alice,DC=dummy,DC=test",
			attrs: []attr{
				{name: "cn", vals: []string{"Alice"}},
				{name: "sn", vals: []string{"Smith"}},
				{name: "objectClass", vals: []string{"person", "top"}},
				{name: "mail", vals: []string{"alice@dummy.test"}},
			},
		},
		{
			dn: "CN=Bob,DC=dummy,DC=test",
			attrs: []attr{
				{name: "cn", vals: []string{"Bob"}},
				{name: "sn", vals: []string{"Jones"}},
				{name: "objectClass", vals: []string{"person", "top"}},
				{name: "mail", vals: []string{"bob@dummy.test"}},
			},
		},
	}

	out := make([][]byte, 0, len(entries))
	for _, e := range entries {
		attrSeq := make([]byte, 0)
		for _, a := range e.attrs {
			vals := make([]byte, 0)
			for _, v := range a.vals {
				vals = append(vals, tlv(0x04, []byte(v))...)
			}
			partial := concat(tlv(0x04, []byte(a.name)), tlv(0x31, vals))
			attrSeq = append(attrSeq, tlv(0x30, partial)...)
		}
		entryBytes := concat(tlv(0x04, []byte(e.dn)), tlv(0x30, attrSeq))
		out = append(out, entryBytes)
	}
	return out
}

func readLDAPMessage(r *bufio.Reader) (msgID int, opTag byte, err error) {
	tag, err := r.ReadByte()
	if err != nil {
		return 0, 0, err
	}
	if tag != 0x30 {
		return 0, 0, fmt.Errorf("expected LDAPMessage sequence, got 0x%02x", tag)
	}
	length, err := readBERLength(r)
	if err != nil {
		return 0, 0, err
	}
	body := make([]byte, length)
	if _, err = io.ReadFull(r, body); err != nil {
		return 0, 0, err
	}

	// body: [0x02 msgID] [protocolOp]
	off := 0
	if body[0] != 0x02 {
		return 0, 0, fmt.Errorf("expected messageID integer, got 0x%02x", body[0])
	}
	off++
	idLen, n := readLength(body[off:])
	off += n
	idBytes := body[off : off+idLen]
	off += idLen
	for _, b := range idBytes {
		msgID = msgID<<8 | int(b)
	}
	if off >= len(body) {
		return 0, 0, fmt.Errorf("missing protocolOp")
	}
	return msgID, body[off], nil
}

func readBERLength(r *bufio.Reader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if b&0x80 == 0 {
		return int(b), nil
	}
	n := int(b & 0x7F)
	if n == 0 || n > 4 {
		return 0, fmt.Errorf("unsupported BER length %d", n)
	}
	var length int
	for i := 0; i < n; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		length = length<<8 | int(c)
	}
	return length, nil
}

func readLength(data []byte) (length, n int) {
	b := data[0]
	if b&0x80 == 0 {
		return int(b), 1
	}
	n = int(b & 0x7F)
	for i := 0; i < n; i++ {
		length = length<<8 | int(data[1+i])
	}
	return length, 1 + n
}

func writeMessage(w io.Writer, msgID int, op []byte) error {
	msg := tlv(0x30, concat(tlv(0x02, intBytes(msgID)), op))
	_, err := w.Write(msg)
	return err
}

func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, encodeLen(len(content))...)
	out = append(out, content...)
	return out
}

func encodeLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(n))
	i := 0
	for i < 4 && buf[i] == 0 {
		i++
	}
	return append([]byte{0x80 | byte(4-i)}, buf[i:]...)
}

func intBytes(n int) []byte {
	if n == 0 {
		return []byte{0}
	}
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], uint32(n))
	i := 0
	for i < 4 && buf[i] == 0 {
		i++
	}
	return buf[i:]
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestLdapsearchAgainstDummyServer(t *testing.T) {
	srv := startDummyLDAP(t)
	defer srv.close()

	starPath := filepath.Join("..", "..", "modules", "SA", "ldapsearch.star")
	data, err := os.ReadFile(starPath)
	if err != nil {
		t.Fatalf("read %s: %v", starPath, err)
	}

	// The dummy server only implements simple bind. The real module uses
	// LDAP_AUTH_NEGOTIATE (Windows integrated auth), so swap just the bind
	// method for the test; everything else (arg handling, search, parsing)
	// stays identical to the shipped module.
	original := string(data)
	patched := strings.Replace(original, `ldap_bind_sW", ld, dn, 0, 0x0486`, `ldap_bind_sW", ld, dn, 0, 0x0080`, 1)
	if patched == original {
		t.Fatalf("failed to patch ldap_bind_sW method; ldapsearch.star changed?")
	}
	data = []byte(patched)

	argv := []string{"(objectclass=*)", "", "0", "0", "127.0.0.1", "DC=dummy,DC=test", "false"}
	out, err := Run(data, argv, nil, 0)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	t.Logf("ldapsearch output:\n%s", out)

	for _, want := range []string{
		"[*] Filter: (objectclass=*)",
		"cn: Alice",
		"cn: Bob",
		"mail: alice@dummy.test",
		"mail: bob@dummy.test",
		"[+] Total entries retrieved: 2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}
