package transport

import (
	"context"
	"fmt"
	"net/http"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"github.com/jm33-m0/emp3r0r/core/lib/util"
)

var (
	Stager_HTTP_Server http.Server
	Stager_Ctx         context.Context
	Stager_Cancel      context.CancelFunc
)

func ServeFileHTTP(file_path, port string, ctx context.Context, cancel context.CancelFunc) (err error) {
	file_handler := func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, file_path)
	}
	Stager_HTTP_Server = http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: http.HandlerFunc(file_handler),
	}

	errChan := make(chan error)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				logging.Errorf("ServeFileHTTP goroutine panicked: %v\n%s", r, util.CallStack())
				errChan <- fmt.Errorf("http server panic: %v", r)
			}
		}()

		err = Stager_HTTP_Server.ListenAndServe()
		if err == http.ErrServerClosed {
			err = fmt.Errorf("stager HTTP server is shutdown")
			errChan <- err
		}
	}()

	select {
	case <-ctx.Done():
		err = Stager_HTTP_Server.Shutdown(context.Background())
		if err != nil {
			err = fmt.Errorf("shutdown Stager HTTP server: %v", err)
		}
		return
	case err = <-errChan:
		return
	}
}
