package listener

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
)

var (
	listenerNotifyMu sync.RWMutex
	listenerNotifyFn func(string)

	tcpListeners sync.Map // map[string]net.Listener, key is port
	udpListeners sync.Map // map[string]*net.UDPConn, key is port
)

func SetNotifyCallback(cb func(string)) {
	listenerNotifyMu.Lock()
	listenerNotifyFn = cb
	listenerNotifyMu.Unlock()
}

func listenerLogf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)

	listenerNotifyMu.RLock()
	cb := listenerNotifyFn
	listenerNotifyMu.RUnlock()
	if cb != nil {
		cb(msg)
		return
	}

	logging.Infof("%s", msg)
}

func registerTCPListener(port string, l net.Listener) {
	tcpListeners.Store(port, l)
}

func unregisterTCPListener(port string) {
	tcpListeners.Delete(port)
}

func registerUDPListener(port string, c *net.UDPConn) {
	udpListeners.Store(port, c)
}

func unregisterUDPListener(port string) {
	udpListeners.Delete(port)
}

func StopTCPListener(port string) error {
	v, ok := tcpListeners.Load(port)
	if !ok {
		return fmt.Errorf("tcp listener on port %s not found", port)
	}
	l, ok := v.(net.Listener)
	if !ok || l == nil {
		tcpListeners.Delete(port)
		return fmt.Errorf("tcp listener on port %s is invalid", port)
	}
	err := l.Close()
	tcpListeners.Delete(port)
	if err != nil {
		return fmt.Errorf("stop tcp listener on port %s: %v", port, err)
	}
	return nil
}

func StopUDPListener(port string) error {
	v, ok := udpListeners.Load(port)
	if !ok {
		return fmt.Errorf("udp listener on port %s not found", port)
	}
	c, ok := v.(*net.UDPConn)
	if !ok || c == nil {
		udpListeners.Delete(port)
		return fmt.Errorf("udp listener on port %s is invalid", port)
	}
	err := c.Close()
	udpListeners.Delete(port)
	if err != nil {
		return fmt.Errorf("stop udp listener on port %s: %v", port, err)
	}
	return nil
}

func ListTCPListenerPorts() []string {
	ports := []string{}
	tcpListeners.Range(func(key, value any) bool {
		port, ok := key.(string)
		if ok {
			ports = append(ports, port)
		}
		return true
	})
	sort.Strings(ports)
	return ports
}

func ListUDPListenerPorts() []string {
	ports := []string{}
	udpListeners.Range(func(key, value any) bool {
		port, ok := key.(string)
		if ok {
			ports = append(ports, port)
		}
		return true
	})
	sort.Strings(ports)
	return ports
}

func HTTPListenerPort() (string, bool) {
	httpServerMu.RLock()
	defer httpServerMu.RUnlock()
	if server == nil {
		return "", false
	}
	return strings.TrimPrefix(server.Addr, ":"), true
}
