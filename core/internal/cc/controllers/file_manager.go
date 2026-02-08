package controllers

// FileInfo represents a file/directory entry
type FileInfo struct {
	Name    string
	IsDir   bool
	Size    int64
	ModTime string
}

// Note: File manager operations (ListDirectory, DownloadFile, UploadFile)
// are already well-abstracted in the ftp package.
// This file is a placeholder for future file management controller logic
// if needed for consistency with the controller pattern.
//
// Current file operations can be accessed via:
// - ftp.CmdDownloadFromAgent
// - ftp.CmdUploadToAgent
// These already return errors and don't have UI dependencies.
