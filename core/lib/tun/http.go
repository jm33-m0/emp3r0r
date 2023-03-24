package tun

import (
	"fmt"
	"net/http"
)

func ServeFileHTTP(file_path string, port string) (err error) {
	server := func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, file_path)
	}

	urlpath := "jquery.js.gz"
	http.HandleFunc(urlpath, server)
	Info("Serving %s on http://localhost:%s/%s Please reverse proxy this URL", file_path, port, urlpath)

	return http.ListenAndServe(fmt.Sprintf(":%s", port), nil)
}
