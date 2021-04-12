package util

import (
	"fmt"
	"image/png"
	"log"
	"os"
	"time"

	"github.com/kbinani/screenshot"
	"github.com/mholt/archiver"
)

// Screenshot take a screenshot in a cross-platform way
// returns path of taken screenshot
func Screenshot() (path string) {
	n := screenshot.NumActiveDisplays()
	var pics []string

	now := time.Now()
	timedate := fmt.Sprintf("%d-%02d-%02d_%02d-%02d-%02d",
		now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())

	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)

		img, err := screenshot.CaptureRect(bounds)
		if err != nil {
			panic(err)
		}
		path = fmt.Sprintf("%s-%d_%dx%d.png", timedate, i, bounds.Dx(), bounds.Dy())
		picfile, _ := os.Create(path)
		defer picfile.Close()
		err = png.Encode(picfile, img)
		if err != nil {
			log.Printf("PNG encode: %v", err)
			return
		}
		pics = append(pics, path)
	}

	// if we get more than one pictures
	// pack them into one zip archive
	if len(pics) > 1 {
		path = timedate + ".zip"
		err := archiver.Archive(pics, path)
		if err != nil {
			log.Printf("Making archive: %v", err)
			return ""
		}
	}

	return
}
