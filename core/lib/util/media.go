package util

import (
	"fmt"
	"image/png"
	"os"
	"time"

	"github.com/kbinani/screenshot"
	"github.com/mholt/archiver"
)

// Screenshot take a screenshot in a cross-platform way
// returns path of taken screenshot
func Screenshot() (path string, err error) {
	n := screenshot.NumActiveDisplays()
	var pics []string

	now := time.Now()
	timedate := fmt.Sprintf("%d-%02d-%02d_%02d-%02d-%02d",
		now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second())

	for i := 0; i < n; i++ {
		bounds := screenshot.GetDisplayBounds(i)

		img, e := screenshot.CaptureRect(bounds)
		if e != nil {
			err = e
			return
		}
		path = fmt.Sprintf("%s-%d_%dx%d.png", timedate, i, bounds.Dx(), bounds.Dy())
		picfile, e := os.Create(path)
		if e != nil {
			err = fmt.Errorf("Create %s: %v", path, e)
			return
		}
		defer picfile.Close()
		err = png.Encode(picfile, img)
		if err != nil {
			err = fmt.Errorf("PNG encode: %v", err)
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
			return
		}
	}

	return
}
