package interop

import (
	"os/exec"
	"runtime"
	"strings"
)

func OpenBrowser(url string) error {
	var cmd string
	var args []string

	switch runtime.GOOS {
	case "windows":
		cmd = "cmd"
		args = []string{"/c", "start"}
		// Escape the url for windows: https://gist.github.com/threeaccents/607f3bc3a57a2ddd9d57
		args = append(args, strings.ReplaceAll(url, "&", "^&"))
	case "darwin":
		cmd = "open"
		args = append(args, url)
	default: // "linux", "freebsd", "openbsd", "netbsd"
		cmd = "xdg-open"
		args = append(args, url)
	}
	return exec.Command(cmd, args...).Start()
}
