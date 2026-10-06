package transport

import (
	"io"

	"github.com/jm33-m0/emp3r0r/core/lib/logging"
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

// IsProxyOK test if the proxy works against the test URL
func IsProxyOK(proxy, test_url string) bool {
	if proxy == "" || test_url == "" {
		return false
	}
	logging.Infof("IsProxyOK: testing proxy %s with %s", proxy, test_url)
	client := CreateEmp3r0rHTTPClient(test_url, proxy)
	if client == nil {
		logging.Infof("IsProxyOK: cannot create http client")
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
	logging.Infof("IsProxyOK: testing proxy %s: %s, looks fine", proxy, respData)

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
