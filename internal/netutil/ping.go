package netutil

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"time"
)

func Ping(host string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var args []string
	switch runtime.GOOS {
	case "windows":
		ms := int(timeout / time.Millisecond)
		args = []string{"-n", "1", "-w", fmt.Sprintf("%d", ms), host}
	default:
		sec := int(timeout / time.Second)
		if sec <= 0 {
			sec = 1
		}
		args = []string{"-c", "1", "-W", fmt.Sprintf("%d", sec), host}
	}
	cmd := exec.CommandContext(ctx, "ping", args...)
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}
