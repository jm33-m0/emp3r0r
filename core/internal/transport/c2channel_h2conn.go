package transport

import (
	"context"
	"io"
	"net/http"

	"github.com/posener/h2conn"
)

type h2ConnChannelWrapper struct{}

func (h2ConnChannelWrapper) Dial(ctx context.Context, client *http.Client, url string) (io.ReadWriteCloser, *http.Response, error) {
	connector := h2conn.Client{Client: client, Method: http.MethodPost}
	conn, resp, err := connector.Connect(ctx, url)
	return conn, resp, err
}

func (h2ConnChannelWrapper) Accept(w http.ResponseWriter, req *http.Request) (io.ReadWriteCloser, error) {
	return h2conn.Accept(w, req)
}

func init() {
	RegisterC2Channel("h2conn", "HTTP/2 duplex stream wrapper", h2ConnChannelWrapper{})
}
