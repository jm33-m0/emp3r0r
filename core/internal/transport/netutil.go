package transport

import (
	"io"
	"github.com/jm33-m0/emp3r0r/core/lib/logging"
	"net/http"
	"time"
)

const (
	// MicrosoftNCSIURL is the URL used by Microsoft to check internet connectivity
	MicrosoftNCSIURL  = "http://www.msftncsi.com/ncsi.txt"
	MicrosoftNCSIResp = "Microsoft NCSI"

	// UbuntuConnectivityURL is the URL used by Ubuntu to check internet connectivity
	UbuntuConnectivityURL = "https://connectivity-check.ubuntu.com"
	// UbuntuConnectivityResp will be empty with 204 status code
	UbuntuConnectivityResp = 204
)

// TestConnectivity does this machine has internet access,
func TestConnectivity(test_url, proxy string) bool {
	// use Microsoft NCSI as default
	// NCSI is an HTTP service therefore we don't need
	// uTLS to talk to it
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	// if not using Microsoft NCSI, we need to use uTLS
	if test_url != MicrosoftNCSIURL {
		client = CreateEmp3r0rHTTPClient(test_url, proxy)
		if client == nil {
			logging.Printf("TestConnectivity: cannot create http client for %s", test_url)
			return false
		}
	}

	resp, err := client.Get(test_url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}

	// MicrosoftNCSIURL
	if test_url == MicrosoftNCSIURL {
		return string(respData) == MicrosoftNCSIResp
	}

	// UbuntuConnectivityURL
	if test_url == UbuntuConnectivityURL {
		return resp.StatusCode == UbuntuConnectivityResp
	}
	return true
}

// IsProxyOK test if the proxy works against the test URL
func IsProxyOK(proxy, test_url string) bool {
	if proxy == "" || test_url == "" {
		return false
	}
	logging.Printf("IsProxyOK: testing proxy %s with %s", proxy, test_url)
	client := CreateEmp3r0rHTTPClient(test_url, proxy)
	if client == nil {
		logging.Printf("IsProxyOK: cannot create http client")
		return false
	}
	resp, err := client.Get(test_url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return false
	}
	logging.Printf("IsProxyOK: testing proxy %s: %s, looks fine", proxy, respData)

	// MicrosoftNCSIURL
	if test_url == MicrosoftNCSIURL {
		return string(respData) == MicrosoftNCSIResp
	}

	// UbuntuConnectivityURL
	if test_url == UbuntuConnectivityURL {
		return resp.StatusCode == UbuntuConnectivityResp
	}
	return true
}
