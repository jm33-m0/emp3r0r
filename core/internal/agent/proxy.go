package agent

import (
	"errors"
	"log"

	"github.com/txthinking/socks5"
)

// Socks5Proxy sock5 local proxy server, like `ss-local`
func Socks5Proxy(op string) error {
	socks5.Debug = true
	s, err := socks5.NewClassicServer("127.0.0.1:10800", "127.0.0.1", "", "", 0, 0, 0, 60)
	if err != nil {
		return err
	}
	defer func() {
		err = s.Stop()
		if err != nil {
			log.Print(err)
		}
	}()

	switch op {
	case "on":
		err = s.Run(nil)
		if err != nil {
			log.Println(err)
		}
	case "off":
		err = s.Stop()
		if err != nil {
			log.Println(err)
		}
	default:
		return errors.New("Operation not supported")
	}

	return nil
}
