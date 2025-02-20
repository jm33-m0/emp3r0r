package tun

import (
	"context"
	"fmt"
	"net/http"
)

var (
	Stager_HTTP_Server http.Server
	Stager_Ctx         context.Context
	Stager_Cancel      context.CancelFunc
)

func ServeFileHTTP(file_path, port string, ctx context.Context, cancel context.CancelFunc) (err error) {
	file_handler := func(w http.ResponseWriter, r *http.Request) {
		LogInfo("Got stager request from %s for %s", r.RemoteAddr, r.URL)
		http.ServeFile(w, r, file_path)
	}
	Stager_HTTP_Server = http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: http.HandlerFunc(file_handler),
	}

	go func() {
		LogInfo("Serving %s on http://localhost:%s Please reverse proxy this URL", file_path, port)
		err = Stager_HTTP_Server.ListenAndServe()
		if err == http.ErrServerClosed {
			LogInfo("Stager HTTP server is shutdown")
		}
	}()

	return
}
