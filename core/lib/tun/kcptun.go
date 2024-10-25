package tun

// Modified from xtaci/kcptun/client

import (
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"github.com/fatih/color"
	"github.com/pkg/errors"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/kcptun/std"
	"github.com/xtaci/qpp"
	"github.com/xtaci/smux"
	"github.com/xtaci/tcpraw"
)

const (
	maxSmuxVer     = 2 // maximum supported smux version
	scavengePeriod = 5 // scavenger check period
	TGT_UNIX       = iota
	TGT_TCP
)

// Config holds the client configuration for KCP tunneling.
type Config struct {
	LocalAddr    string `json:"localaddr"`   // Local listen address, e.g., ":12948"
	Listen       string `json:"listen"`      // kcp server listen address, eg: "IP:29900" for a single port, "IP:minport-maxport"
	Target       string `json:"target"`      // target server address, or path/to/unix_socket
	RemoteAddr   string `json:"remoteaddr"`  // KCP server address, e.g., "vps:29900", can be a single port or port range "IP:minport-maxport"
	Key          string `json:"key"`         // Pre-shared secret between client and server, e.g., "it's a secret"
	Crypt        string `json:"crypt"`       // Encryption method, e.g., aes, aes-128, aes-192, salsa20, blowfish, twofish, etc.
	Mode         string `json:"mode"`        // Performance profile, e.g., fast, fast2, fast3, normal, or manual
	Conn         int    `json:"conn"`        // Number of UDP connections to the server
	AutoExpire   int    `json:"autoexpire"`  // Auto expiration time (in seconds) for a single UDP connection, 0 disables auto-expire
	ScavengeTTL  int    `json:"scavengettl"` // Time (in seconds) an expired connection can remain active before scavenging
	MTU          int    `json:"mtu"`         // Maximum Transmission Unit size for UDP packets
	SndWnd       int    `json:"sndwnd"`      // Send window size (number of packets)
	RcvWnd       int    `json:"rcvwnd"`      // Receive window size (number of packets)
	DataShard    int    `json:"datashard"`   // Number of data shards for Reed-Solomon erasure coding
	ParityShard  int    `json:"parityshard"` // Number of parity shards for Reed-Solomon erasure coding
	DSCP         int    `json:"dscp"`        // DSCP value for quality of service (QoS) marking (6-bit)
	NoComp       bool   `json:"nocomp"`      // Disable compression if set to true
	AckNodelay   bool   `json:"acknodelay"`  // Flush ACK immediately when a packet is received (reduces latency)
	NoDelay      int    `json:"nodelay"`     // KCP 'NoDelay' mode configuration (latency vs throughput trade-off)
	Interval     int    `json:"interval"`    // KCP update interval in milliseconds
	Resend       int    `json:"resend"`      // KCP resend parameter, controls packet retransmission
	NoCongestion int    `json:"nc"`          // Disable KCP congestion control (1 = disable, 0 = enable)
	SockBuf      int    `json:"sockbuf"`     // Per-socket buffer size (in bytes), e.g., 4194304
	SmuxVer      int    `json:"smuxver"`     // Smux version, either 1 or 2
	SmuxBuf      int    `json:"smuxbuf"`     // Overall de-mux buffer size (in bytes), e.g., 4194304
	StreamBuf    int    `json:"streambuf"`   // Per-stream receive buffer size (in bytes) for Smux v2+, e.g., 2097152
	KeepAlive    int    `json:"keepalive"`   // NAT keep-alive interval in seconds
	Log          string `json:"log"`         // Path to the log file, default is empty (logs to stderr)
	SnmpLog      string `json:"snmplog"`     // Path to collect SNMP logs, follows Go time format e.g., "./snmp-20060102.log"
	SnmpPeriod   int    `json:"snmpperiod"`  // SNMP collection period in seconds
	Quiet        bool   `json:"quiet"`       // Suppress 'stream open/close' messages if set to true
	TCP          bool   `json:"tcp"`         // Emulate a TCP connection (Linux only)
	Pprof        bool   `json:"pprof"`       // Enable a profiling server on port :6060 if set to true
	QPP          bool   `json:"qpp"`         // Enable Quantum Permutation Pads (QPP) for added encryption security
	QPPCount     int    `json:"qpp-count"`   // Number of pads to use for QPP (must be a prime number)
	CloseWait    int    `json:"closewait"`   // Time (in seconds) to wait before tearing down a connection
}

func parseJSONConfig(config *Config, path string) error {
	file, err := os.Open(path) // For read access.
	if err != nil {
		return err
	}
	defer file.Close()

	return json.NewDecoder(file).Decode(config)
}

func NewConfig(remote_addr, target, port, password, salt string) *Config {
	config := Config{}
	config.LocalAddr = fmt.Sprintf("127.0.0.1:%s", port) // client local listen address for incming connections
	config.Listen = fmt.Sprintf(":%s", port)             // server listen address

	// if target is empty, then it is a client
	if target == "" {
		config.RemoteAddr = fmt.Sprintf("%s:%s", remote_addr, port)
	} else {
		config.Target = target
	}

	// KCP parameters
	config.Key = password      // pre-shared secret between client and server
	config.Crypt = "aes"       // encryption method, e.g., aes, aes-128, aes-192, salsa20, blowfish, twofish, etc.
	config.Mode = "fast3"      // Performance profile, e.g., fast, fast2, fast3, normal, or manual
	config.QPP = false         // Quantum Permutation Pads (QPP) for added encryption security
	config.QPPCount = 67       // Number of pads to use for QPP (must be a prime number)
	config.Conn = 1            // Number of UDP connections to the server
	config.AutoExpire = 0      // Auto expiration time (in seconds) for a single UDP connection, 0 disables auto-expire
	config.ScavengeTTL = 600   // Time (in seconds) an expired connection can remain active before scavenging
	config.MTU = 1350          // Maximum Transmission Unit size for UDP packets
	config.SndWnd = 128        // Send window size (number of packets)
	config.RcvWnd = 512        // Receive window size (number of packets)
	config.DataShard = 10      // Reed-Solomon erasure coding
	config.ParityShard = 3     // Reed-Solomon erasure coding
	config.DSCP = 0            // DSCP value for QoS marking
	config.NoComp = false      // enable compression
	config.NoDelay = 0         // KCP 'NoDelay' mode, 0: normal, 1: fast, 2: fast2, 3: fast3
	config.Interval = 50       // KCP update interval in milliseconds
	config.Resend = 0          // 0: disable fast resend
	config.SockBuf = 4194304   // socket buffer size in bytes
	config.SmuxVer = 1         // smux version
	config.SmuxBuf = 4194304   // smux buffer size in bytes
	config.StreamBuf = 2097152 // stream buffer size in bytes
	config.KeepAlive = 10      // nat keepalive interval in seconds
	config.CloseWait = 0       // time to wait before tearing down a connection
	config.Log = ""            // log to stderr
	config.Quiet = true        // suppress 'stream open/close' messages
	config.TCP = false         // emulate a TCP connection (Linux only), requires root

	switch config.Mode {
	case "normal":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 40, 2, 1
	case "fast":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 0, 30, 2, 1
	case "fast2":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 20, 2, 1
	case "fast3":
		config.NoDelay, config.Interval, config.Resend, config.NoCongestion = 1, 10, 2, 1
	}
	return &config
}

// main function for KCP tunneling using smux
// remote_addr: KCP server address
// port: KCP server listen port Runtime.KCPPort
// password: Runtime password
// salt: emp3r0r_data.MagicString
func KCPTunClient(remote_addr, port, password, salt string) error {
	config := NewConfig(remote_addr, "", port, password, salt)
	var listener net.Listener
	var isUnix bool
	if _, _, err := net.SplitHostPort(config.LocalAddr); err != nil {
		isUnix = true
	}
	if isUnix {
		addr, err := net.ResolveUnixAddr("unix", config.LocalAddr)
		checkError(err)
		listener, err = net.ListenUnix("unix", addr)
		checkError(err)
	} else {
		addr, err := net.ResolveTCPAddr("tcp", config.LocalAddr)
		checkError(err)
		listener, err = net.ListenTCP("tcp", addr)
		checkError(err)
	}

	LogInfo("smux version:", config.SmuxVer)
	LogInfo("listening on:", listener.Addr())
	LogInfo("encryption:", config.Crypt)
	LogInfo("QPP:", config.QPP)
	LogInfo("QPP Count:", config.QPPCount)
	LogInfo("nodelay parameters:", config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
	LogInfo("remote address:", config.RemoteAddr)
	LogInfo("sndwnd:", config.SndWnd, "rcvwnd:", config.RcvWnd)
	LogInfo("compression:", !config.NoComp)
	LogInfo("mtu:", config.MTU)
	LogInfo("datashard:", config.DataShard, "parityshard:", config.ParityShard)
	LogInfo("acknodelay:", config.AckNodelay)
	LogInfo("dscp:", config.DSCP)
	LogInfo("sockbuf:", config.SockBuf)
	LogInfo("smuxbuf:", config.SmuxBuf)
	LogInfo("streambuf:", config.StreamBuf)
	LogInfo("keepalive:", config.KeepAlive)
	LogInfo("conn:", config.Conn)
	LogInfo("autoexpire:", config.AutoExpire)
	LogInfo("scavengettl:", config.ScavengeTTL)
	LogInfo("snmplog:", config.SnmpLog)
	LogInfo("snmpperiod:", config.SnmpPeriod)
	LogInfo("quiet:", config.Quiet)
	LogInfo("tcp:", config.TCP)
	LogInfo("pprof:", config.Pprof)

	// QPP parameters check
	if config.QPP {
		minSeedLength := qpp.QPPMinimumSeedLength(8)
		if len(config.Key) < minSeedLength {
			color.Red("QPP Warning: 'key' has size of %d bytes, required %d bytes at least", len(config.Key), minSeedLength)
		}

		minPads := qpp.QPPMinimumPads(8)
		if config.QPPCount < minPads {
			color.Red("QPP Warning: QPPCount %d, required %d at least", config.QPPCount, minPads)
		}

		if new(big.Int).GCD(nil, nil, big.NewInt(int64(config.QPPCount)), big.NewInt(8)).Int64() != 1 {
			color.Red("QPP Warning: QPPCount %d, choose a prime number for security", config.QPPCount)
		}
	}

	// Scavenge parameters check
	if config.AutoExpire != 0 && config.ScavengeTTL > config.AutoExpire {
		color.Red("WARNING: scavengettl is bigger than autoexpire, connections may race hard to use bandwidth.")
		color.Red("Try limiting scavengettl to a smaller value.")
	}

	// SMUX Version check
	if config.SmuxVer > maxSmuxVer {
		log.Fatal("unsupported smux version:", config.SmuxVer)
	}

	LogInfo("initiating key derivation")
	pass := pbkdf2.Key([]byte(config.Key), []byte(salt), 4096, 32, sha1.New)
	LogInfo("key derivation done")
	var block kcp.BlockCrypt
	switch config.Crypt {
	case "null":
		block = nil
	case "sm4":
		block, _ = kcp.NewSM4BlockCrypt(pass[:16])
	case "tea":
		block, _ = kcp.NewTEABlockCrypt(pass[:16])
	case "xor":
		block, _ = kcp.NewSimpleXORBlockCrypt(pass)
	case "none":
		block, _ = kcp.NewNoneBlockCrypt(pass)
	case "aes-128":
		block, _ = kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		block, _ = kcp.NewAESBlockCrypt(pass[:24])
	case "blowfish":
		block, _ = kcp.NewBlowfishBlockCrypt(pass)
	case "twofish":
		block, _ = kcp.NewTwofishBlockCrypt(pass)
	case "cast5":
		block, _ = kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
	case "xtea":
		block, _ = kcp.NewXTEABlockCrypt(pass[:16])
	case "salsa20":
		block, _ = kcp.NewSalsa20BlockCrypt(pass)
	default:
		config.Crypt = "aes"
		block, _ = kcp.NewAESBlockCrypt(pass)
	}

	createConn := func() (*smux.Session, error) {
		kcpconn, err := dial(config, block)
		if err != nil {
			return nil, errors.Wrap(err, "dial()")
		}
		kcpconn.SetStreamMode(true)
		kcpconn.SetWriteDelay(false)
		kcpconn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
		kcpconn.SetWindowSize(config.SndWnd, config.RcvWnd)
		kcpconn.SetMtu(config.MTU)
		kcpconn.SetACKNoDelay(config.AckNodelay)

		if err := kcpconn.SetDSCP(config.DSCP); err != nil {
			LogInfo("SetDSCP:", err)
		}
		if err := kcpconn.SetReadBuffer(config.SockBuf); err != nil {
			LogInfo("SetReadBuffer:", err)
		}
		if err := kcpconn.SetWriteBuffer(config.SockBuf); err != nil {
			LogInfo("SetWriteBuffer:", err)
		}
		LogInfo("smux version:", config.SmuxVer, "on connection:", kcpconn.LocalAddr(), "->", kcpconn.RemoteAddr())
		smuxConfig := smux.DefaultConfig()
		smuxConfig.Version = config.SmuxVer
		smuxConfig.MaxReceiveBuffer = config.SmuxBuf
		smuxConfig.MaxStreamBuffer = config.StreamBuf
		smuxConfig.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second

		if err := smux.VerifyConfig(smuxConfig); err != nil {
			log.Fatalf("%+v", err)
		}

		// stream multiplex
		var session *smux.Session
		if config.NoComp {
			session, err = smux.Client(kcpconn, smuxConfig)
		} else {
			session, err = smux.Client(std.NewCompStream(kcpconn), smuxConfig)
		}
		if err != nil {
			return nil, errors.Wrap(err, "createConn()")
		}
		return session, nil
	}

	// wait until a connection is ready
	waitConn := func() *smux.Session {
		for {
			if session, err := createConn(); err == nil {
				return session
			} else {
				LogInfo("re-connecting:", err)
				time.Sleep(time.Second)
			}
		}
	}

	// start snmp logger
	go std.SnmpLogger(config.SnmpLog, config.SnmpPeriod)

	// start pprof
	if config.Pprof {
		go http.ListenAndServe(":6060", nil)
	}

	// start scavenger if autoexpire is set
	chScavenger := make(chan timedSession, 128)
	if config.AutoExpire > 0 {
		go scavenger(chScavenger, config)
	}

	// start listener
	numconn := uint16(config.Conn)
	muxes := make([]timedSession, numconn)
	rr := uint16(0)

	// create shared QPP
	var _Q_ *qpp.QuantumPermutationPad
	if config.QPP {
		_Q_ = qpp.NewQPP([]byte(config.Key), uint16(config.QPPCount))
	}

	for {
		p1, err := listener.Accept()
		if err != nil {
			log.Fatalf("%+v", err)
		}
		idx := rr % numconn

		// do auto expiration && reconnection
		if muxes[idx].session == nil || muxes[idx].session.IsClosed() ||
			(config.AutoExpire > 0 && time.Now().After(muxes[idx].expiryDate)) {
			muxes[idx].session = waitConn()
			muxes[idx].expiryDate = time.Now().Add(time.Duration(config.AutoExpire) * time.Second)
			if config.AutoExpire > 0 { // only when autoexpire set
				chScavenger <- muxes[idx]
			}
		}

		go clientHandleConn(_Q_, []byte(config.Key), muxes[idx].session, p1, config.Quiet, config.CloseWait)
		rr++
	}
}

// clientHandleConn aggregates connection p1 on mux
func clientHandleConn(_Q_ *qpp.QuantumPermutationPad, seed []byte, session *smux.Session, p1 net.Conn, quiet bool, closeWait int) {
	logln := func(v ...interface{}) {
		if !quiet {
			log.Print(v...)
		}
	}

	// handles transport layer
	defer p1.Close()
	p2, err := session.OpenStream()
	if err != nil {
		logln(err)
		return
	}
	defer p2.Close()

	logln("stream opened", "in:", p1.RemoteAddr(), "out:", fmt.Sprint(p2.RemoteAddr(), "(", p2.ID(), ")"))
	defer logln("stream closed", "in:", p1.RemoteAddr(), "out:", fmt.Sprint(p2.RemoteAddr(), "(", p2.ID(), ")"))

	var s1, s2 io.ReadWriteCloser = p1, p2
	// if QPP is enabled, create QPP read write closer
	if _Q_ != nil {
		// replace s2 with QPP port
		s2 = std.NewQPPPort(p2, _Q_, seed)
	}

	// stream layer
	err1, err2 := std.Pipe(s1, s2, closeWait)

	// handles transport layer errors
	if err1 != nil && err1 != io.EOF {
		logln("pipe:", err1, "in:", p1.RemoteAddr(), "out:", fmt.Sprint(p2.RemoteAddr(), "(", p2.ID(), ")"))
	}
	if err2 != nil && err2 != io.EOF {
		logln("pipe:", err2, "in:", p1.RemoteAddr(), "out:", fmt.Sprint(p2.RemoteAddr(), "(", p2.ID(), ")"))
	}
}

// timedSession is a wrapper for smux.Session with expiry date
type timedSession struct {
	session    *smux.Session
	expiryDate time.Time
}

// scavenger goroutine is used to close expired sessions
func scavenger(ch chan timedSession, config *Config) {
	ticker := time.NewTicker(scavengePeriod * time.Second)
	defer ticker.Stop()
	var sessionList []timedSession
	for {
		select {
		case item := <-ch:
			sessionList = append(sessionList, timedSession{
				item.session,
				item.expiryDate.Add(time.Duration(config.ScavengeTTL) * time.Second),
			})
		case <-ticker.C:
			var newList []timedSession
			for k := range sessionList {
				s := sessionList[k]
				if s.session.IsClosed() {
					LogInfo("scavenger: session normally closed:", s.session.LocalAddr())
				} else if time.Now().After(s.expiryDate) {
					s.session.Close()
					LogInfo("scavenger: session closed due to ttl:", s.session.LocalAddr())
				} else {
					newList = append(newList, sessionList[k])
				}
			}
			sessionList = newList
		}
	}
}

// dial connects to the remote address
func dial(config *Config, block kcp.BlockCrypt) (*kcp.UDPSession, error) {
	mp, err := std.ParseMultiPort(config.RemoteAddr)
	if err != nil {
		return nil, err
	}

	// generate a random port
	var randport uint64
	err = binary.Read(rand.Reader, binary.LittleEndian, &randport)
	if err != nil {
		return nil, err
	}
	remoteAddr := fmt.Sprintf("%v:%v", mp.Host, uint64(mp.MinPort)+randport%uint64(mp.MaxPort-mp.MinPort+1))

	// emulate TCP connection
	if config.TCP {
		conn, err := tcpraw.Dial("tcp", remoteAddr)
		if err != nil {
			return nil, errors.Wrap(err, "tcpraw.Dial()")
		}

		udpaddr, err := net.ResolveUDPAddr("udp", remoteAddr)
		if err != nil {
			return nil, errors.WithStack(err)
		}

		var convid uint32
		binary.Read(rand.Reader, binary.LittleEndian, &convid)
		return kcp.NewConn4(convid, udpaddr, block, config.DataShard, config.ParityShard, true, conn)
	}

	// default UDP connection
	return kcp.DialWithOptions(remoteAddr, block, config.DataShard, config.ParityShard)
}

// target: target address (shadowsocks server port)
// port: KCP server listen port
// password: Runtime password
// salt: emp3r0r_data.MagicString
func KCPTunServer(target, port, password, salt string) error {
	config := NewConfig("", target, port, password, salt)
	if config.QPP {
		minSeedLength := qpp.QPPMinimumSeedLength(8)
		if len(config.Key) < minSeedLength {
			LogWarn("QPP Warning: 'key' has size of %d bytes, required %d bytes at least", len(config.Key), minSeedLength)
		}

		minPads := qpp.QPPMinimumPads(8)
		if config.QPPCount < minPads {
			LogWarn("QPP Warning: QPPCount %d, required %d at least", config.QPPCount, minPads)
		}

		if new(big.Int).GCD(nil, nil, big.NewInt(int64(config.QPPCount)), big.NewInt(8)).Int64() != 1 {
			LogWarn("QPP Warning: QPPCount %d, choose a prime number for security", config.QPPCount)
		}
	}
	// parameters check
	if config.SmuxVer > maxSmuxVer {
		return fmt.Errorf("unsupported smux version:", config.SmuxVer)
	}

	pass := pbkdf2.Key([]byte(config.Key), []byte(salt), 4096, 32, sha1.New)
	var block kcp.BlockCrypt
	switch config.Crypt {
	case "null":
		block = nil
	case "sm4":
		block, _ = kcp.NewSM4BlockCrypt(pass[:16])
	case "tea":
		block, _ = kcp.NewTEABlockCrypt(pass[:16])
	case "xor":
		block, _ = kcp.NewSimpleXORBlockCrypt(pass)
	case "none":
		block, _ = kcp.NewNoneBlockCrypt(pass)
	case "aes-128":
		block, _ = kcp.NewAESBlockCrypt(pass[:16])
	case "aes-192":
		block, _ = kcp.NewAESBlockCrypt(pass[:24])
	case "blowfish":
		block, _ = kcp.NewBlowfishBlockCrypt(pass)
	case "twofish":
		block, _ = kcp.NewTwofishBlockCrypt(pass)
	case "cast5":
		block, _ = kcp.NewCast5BlockCrypt(pass[:16])
	case "3des":
		block, _ = kcp.NewTripleDESBlockCrypt(pass[:24])
	case "xtea":
		block, _ = kcp.NewXTEABlockCrypt(pass[:16])
	case "salsa20":
		block, _ = kcp.NewSalsa20BlockCrypt(pass)
	default:
		config.Crypt = "aes"
		block, _ = kcp.NewAESBlockCrypt(pass)
	}

	go std.SnmpLogger(config.SnmpLog, config.SnmpPeriod)
	if config.Pprof {
		go http.ListenAndServe(":6060", nil)
	}

	// create shared QPP
	var _Q_ *qpp.QuantumPermutationPad
	if config.QPP {
		_Q_ = qpp.NewQPP([]byte(config.Key), uint16(config.QPPCount))
	}

	// main loop
	var wg sync.WaitGroup
	loop := func(lis *kcp.Listener) {
		defer wg.Done()
		if err := lis.SetDSCP(config.DSCP); err != nil {
			LogInfo("SetDSCP:", err)
		}
		if err := lis.SetReadBuffer(config.SockBuf); err != nil {
			LogInfo("SetReadBuffer:", err)
		}
		if err := lis.SetWriteBuffer(config.SockBuf); err != nil {
			LogInfo("SetWriteBuffer:", err)
		}

		for {
			if conn, err := lis.AcceptKCP(); err == nil {
				LogInfo("remote address:", conn.RemoteAddr())
				conn.SetStreamMode(true)
				conn.SetWriteDelay(false)
				conn.SetNoDelay(config.NoDelay, config.Interval, config.Resend, config.NoCongestion)
				conn.SetMtu(config.MTU)
				conn.SetWindowSize(config.SndWnd, config.RcvWnd)
				conn.SetACKNoDelay(config.AckNodelay)

				if config.NoComp {
					go handleMux(_Q_, conn, config)
				} else {
					go handleMux(_Q_, std.NewCompStream(conn), config)
				}
			} else {
				LogError("%+v", err)
			}
		}
	}

	mp, err := std.ParseMultiPort(config.Listen)
	if err != nil {
		return fmt.Errorf("parseMultiPort(%v): %v", config.Listen, err)
	}

	// create multiple listener
	for port := mp.MinPort; port <= mp.MaxPort; port++ {
		listenAddr := fmt.Sprintf("%v:%v", mp.Host, port)
		if config.TCP { // tcp dual stack
			if conn, err := tcpraw.Listen("tcp", listenAddr); err == nil {
				LogInfo("Listening on: %v/tcp", listenAddr)
				lis, err := kcp.ServeConn(block, config.DataShard, config.ParityShard, conn)
				checkError(err)
				wg.Add(1)
				go loop(lis)
			} else {
				LogError("%v", err)
			}
		}

		// udp stack
		LogInfo("Listening on: %v/udp", listenAddr)
		lis, err := kcp.ListenWithOptions(listenAddr, block, config.DataShard, config.ParityShard)
		checkError(err)
		wg.Add(1)
		go loop(lis)
	}

	wg.Wait()
	return nil
}

// handle multiplex-ed connection
func handleMux(_Q_ *qpp.QuantumPermutationPad, conn net.Conn, config *Config) {
	// check target type
	targetType := TGT_TCP
	if _, _, err := net.SplitHostPort(config.Target); err != nil {
		targetType = TGT_UNIX
	}
	LogInfo("smux version:", config.SmuxVer, "on connection:", conn.LocalAddr(), "->", conn.RemoteAddr())

	// stream multiplex
	smuxConfig := smux.DefaultConfig()
	smuxConfig.Version = config.SmuxVer
	smuxConfig.MaxReceiveBuffer = config.SmuxBuf
	smuxConfig.MaxStreamBuffer = config.StreamBuf
	smuxConfig.KeepAliveInterval = time.Duration(config.KeepAlive) * time.Second

	mux, err := smux.Server(conn, smuxConfig)
	if err != nil {
		LogWarn("%v", err)
		return
	}
	defer mux.Close()

	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			LogWarn("%v", err)
			return
		}

		go func(p1 *smux.Stream) {
			var p2 net.Conn
			var err error

			switch targetType {
			case TGT_TCP:
				p2, err = net.Dial("tcp", config.Target)
				if err != nil {
					LogWarn("%v", err)
					p1.Close()
					return
				}
				handleClient(_Q_, []byte(config.Key), p1, p2, config.Quiet, config.CloseWait)
			case TGT_UNIX:
				p2, err = net.Dial("unix", config.Target)
				if err != nil {
					LogWarn("%v", err)
					p1.Close()
					return
				}
				handleClient(_Q_, []byte(config.Key), p1, p2, config.Quiet, config.CloseWait)
			}
		}(stream)
	}
}

// handleClient pipes two streams
func handleClient(_Q_ *qpp.QuantumPermutationPad, seed []byte, p1 *smux.Stream, p2 net.Conn, quiet bool, closeWait int) {
	logln := func(v ...interface{}) {
		if !quiet {
			log.Print(v...)
		}
	}

	defer p1.Close()
	defer p2.Close()

	logln("stream opened", "in:", fmt.Sprint(p1.RemoteAddr(), "(", p1.ID(), ")"), "out:", p2.RemoteAddr())
	defer logln("stream closed", "in:", fmt.Sprint(p1.RemoteAddr(), "(", p1.ID(), ")"), "out:", p2.RemoteAddr())

	var s1, s2 io.ReadWriteCloser = p1, p2
	// if QPP is enabled, create QPP read write closer
	if _Q_ != nil {
		// replace s1 with QPP port
		s1 = std.NewQPPPort(p1, _Q_, seed)
	}

	// stream layer
	err1, err2 := std.Pipe(s1, s2, closeWait)

	// handles transport layer errors
	if err1 != nil && err1 != io.EOF {
		logln("pipe:", err1, "in:", p1.RemoteAddr(), "out:", fmt.Sprint(p2.RemoteAddr(), "(", p2.RemoteAddr(), ")"))
	}
	if err2 != nil && err2 != io.EOF {
		logln("pipe:", err2, "in:", p1.RemoteAddr(), "out:", fmt.Sprint(p2.RemoteAddr(), "(", p2.RemoteAddr(), ")"))
	}
}

func checkError(err error) {
	if err != nil {
		LogError("%+v\n", err)
		os.Exit(-1)
	}
}
