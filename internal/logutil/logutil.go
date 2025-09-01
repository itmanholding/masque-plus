package logutil

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"
)

var timePattern = regexp.MustCompile(`(\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(\.\d+)?)`)

// Msg logs a line in key=value style, e.g.:
// time=2025-09-01T11:09:07.942+03:30 level=INFO msg="serving proxy" address=127.0.0.1:8086
// lvl should be "INFO" | "WARN" | "ERROR".
func Msg(lvl string, msg string, kv map[string]string) {
	if kv == nil {
		kv = map[string]string{}
	}

	msg = timePattern.ReplaceAllString(msg, "")
	msg = strings.TrimSpace(msg)

	ts := time.Now().Format(time.RFC3339Nano)

	// stable key order
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	parts := []string{
		fmt.Sprintf("time=%s", ts),
		fmt.Sprintf("level=%s", lvl),
		fmt.Sprintf(`msg=%q`, msg),
	}
	for _, k := range keys {
		v := kv[k]
		if v == "" {
			continue
		}
		// quote if contains spaces/tabs
		if strings.ContainsAny(v, " \t") {
			parts = append(parts, fmt.Sprintf(`%s=%q`, k, v))
		} else {
			parts = append(parts, fmt.Sprintf(`%s=%s`, k, v))
		}
	}

	fmt.Fprintln(os.Stdout, strings.Join(parts, " "))
}

func Info(msg string, kv map[string]string)  { Msg("INFO", msg, kv) }
func Warn(msg string, kv map[string]string)  { Msg("WARN", msg, kv) }
func Error(msg string, kv map[string]string) { Msg("ERROR", msg, kv) }
