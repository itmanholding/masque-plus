package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	defaultV4 = []string{
		"162.159.198.1:443",
		"162.159.198.2:443",
	}
	defaultV6 = []string{
		"2606:4700:103::1",
		"2606:4700:103::2",
	}

	defaultBind           = "127.0.0.1:1080"
	defaultConfigFile     = "./config.json"
	defaultUsquePath      = "./usque"
	defaultConnectTimeout = 15 * time.Minute
)

func main() {
	endpoint := flag.String("endpoint", "", "Endpoint to connect (IPv4/IPv6; supports IP or IP:Port; for IPv6 with port use [IPv6]:Port)")
	bind := flag.String("bind", defaultBind, "IP:Port to bind SOCKS proxy")
	renew := flag.Bool("renew", false, "Force renewal of config even if config.json exists")
	scan := flag.Bool("scan", false, "Scan/auto-select a default endpoint")
	v4Flag := flag.Bool("4", false, "Force IPv4 endpoint list (with --scan or engage.cloudflareclient.com:2408)")
	v6Flag := flag.Bool("6", false, "Force IPv6 endpoint list (with --scan or engage.cloudflareclient.com:2408)")
	connectTimeout := flag.Duration("connect-timeout", defaultConnectTimeout, "Timeout for initial connect (e.g. 15s, 1m, 15m); default 15m")
	rtt := flag.Bool("rtt", false, "placeholder flag, not used")
	reserved := flag.String("reserved", "", "placeholder flag, not used")
	dns := flag.String("dns", "", "placeholder flag, not used")
	testURL := flag.String("test-url", "", "placeholder flag, not used")
	flag.Parse()

	_ = rtt
	_ = reserved
	_ = dns
	_ = testURL

	if *v4Flag && *v6Flag {
		logMsg("ERROR", "both -4 and -6 provided", nil)
		os.Exit(1)
	}
	if *endpoint == "" && !*scan {
		logMsg("ERROR", "--endpoint is required", nil)
		os.Exit(1)
	}

	usquePath := defaultUsquePath
	configFile := defaultConfigFile

	logMsg("INFO", "running in masque mode", nil)

	if *scan || strings.EqualFold(*endpoint, "engage.cloudflareclient.com:2408") {
		logMsg("INFO", "scanner mode enabled", nil)
		chosen, err := pickDefaultEndpoint(*v6Flag)
		if err != nil {
			logMsg("ERROR", err.Error(), nil)
			os.Exit(1)
		}
		*endpoint = chosen
	}

	bindIP, bindPort, err := splitBind(*bind)
	if err != nil {
		logMsg("ERROR", err.Error(), nil)
		os.Exit(1)
	}

	needRegister := *renew
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		needRegister = true
	}
	if needRegister {
		logMsg("INFO", "registering usque (renew or config missing)...", nil)
		if err := runRegister(usquePath); err != nil {
			logMsg("ERROR", fmt.Sprintf("registration failed: %v", err), nil)
			os.Exit(1)
		}
	} else {
		logMsg("INFO", "successfully loaded masque identity", nil)
	}

	cfg := make(map[string]interface{})
	if _, err := os.Stat(configFile); err == nil {
		if data, err := os.ReadFile(configFile); err == nil {
			_ = json.Unmarshal(data, &cfg)
		} else {
			logMsg("ERROR", fmt.Sprintf("failed to read config: %v", err), nil)
			os.Exit(1)
		}
	}

	ip, port, err := parseEndpoint(*endpoint)
	if err != nil {
		logMsg("ERROR", fmt.Sprintf("invalid endpoint: %v", err), nil)
		os.Exit(1)
	}

	if ip.To4() != nil {
		cfg["endpoint_v4"] = ip.String()
		if port != "" {
			cfg["endpoint_v4_port"] = port
		}
		logMsg("INFO", "using IPv4 endpoint", nil)
	} else {
		cfg["endpoint_v6"] = ip.String()
		if port != "" {
			cfg["endpoint_v6_port"] = port
		}
		logMsg("INFO", "using IPv6 endpoint", nil)
	}

	if err := writeConfig(configFile, cfg); err != nil {
		logMsg("ERROR", fmt.Sprintf("failed to write config: %v", err), nil)
		os.Exit(1)
	}

	if err := runSocks(usquePath, configFile, bindIP, bindPort, *connectTimeout); err != nil {
		// re-register only if private key issue
		if strings.Contains(err.Error(), "Failed to get private key") {
			logMsg("ERROR", "private key error detected, re-registering...", nil)
			_ = runRegister(usquePath)
			if err := runSocks(usquePath, configFile, bindIP, bindPort, *connectTimeout); err != nil {
				logMsg("ERROR", fmt.Sprintf("failed to start SOCKS proxy after re-register: %v", err), nil)
				os.Exit(1)
			}
		} else {
			logMsg("ERROR", fmt.Sprintf("%v", err), nil)
			os.Exit(1)
		}
	}
}

func pickDefaultEndpoint(v6 bool) (string, error) {
	pool := defaultV4
	if v6 {
		pool = defaultV6
	}
	if len(pool) == 0 {
		return "", fmt.Errorf("no default endpoints available for this IP version")
	}
	nBig, _ := rand.Int(rand.Reader, big.NewInt(int64(len(pool))))
	return pool[nBig.Int64()], nil
}

func splitBind(b string) (string, string, error) {
	parts := strings.Split(b, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("--bind must be in format IP:Port")
	}
	if err := validatePort(parts[1]); err != nil {
		return "", "", err
	}
	return parts[0], parts[1], nil
}

func parseEndpoint(ep string) (net.IP, string, error) {
	if host, port, err := net.SplitHostPort(ep); err == nil {
		host = strings.Trim(host, "[]")
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, "", fmt.Errorf("invalid IP in endpoint")
		}
		if err := validatePort(port); err != nil {
			return nil, "", err
		}
		return ip, port, nil
	}
	if ip := net.ParseIP(ep); ip != nil {
		return ip, "", nil
	}
	if strings.Count(ep, ":") >= 2 && strings.Contains(ep, ":") {
		return nil, "", fmt.Errorf("IPv6 with port must be in the form [IPv6]:Port")
	}
	return nil, "", fmt.Errorf("could not parse endpoint")
}

func validatePort(p string) error {
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q", p)
	}
	return nil
}

func writeConfig(path string, cfg map[string]interface{}) error {
	newData, _ := json.MarshalIndent(cfg, "", "  ")
	return os.WriteFile(path, newData, 0644)
}

func runRegister(path string) error {
	cmd := exec.Command(path, "register", "-n", "masque-plus")
	stdin, _ := cmd.StdinPipe()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	// Accept prompts
	_, _ = stdin.Write([]byte("y\ny\n"))
	_ = stdin.Close()
	return cmd.Wait()
}

type procState struct {
	mu             sync.Mutex
	servedLogged   bool
	privateKeyErr  bool
	endpointErr    bool
	handshakeFail  bool
	connectedOnce  sync.Once
	connectedCh    chan struct{}
	serveAddrShown bool
}

func newProcState() *procState {
	return &procState{
		connectedCh: make(chan struct{}),
	}
}

func (ps *procState) markConnected() {
	ps.connectedOnce.Do(func() { close(ps.connectedCh) })
}

func runSocks(path, config, bindIP, bindPort string, connectTimeout time.Duration) error {
	cmd := exec.Command(path, "socks", "--config", config, "-b", bindIP, "-p", bindPort)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	state := newProcState()
	bind := bindIP + ":" + bindPort

	outScan := bufio.NewScanner(stdout)
	errScan := bufio.NewScanner(stderr)

	// scanners; pass cmd so we can kill on fatal conditions
	go handleScanner(outScan, bind, state, cmd)
	go handleScanner(errScan, bind, state, cmd)

	// Wait for initial connect or timeout
	timer := time.NewTimer(connectTimeout)
	defer timer.Stop()

	waitCh := make(chan error, 1)
	go func() { waitCh <- cmd.Wait() }()

	// If we connect before timeout, continue and just wait for process end
	select {
	case <-state.connectedCh:
		// connected; normal lifecycle
	case err := <-waitCh:
		// process exited before connect
		// inspect state for reasons
		if state.privateKeyErr {
			return fmt.Errorf("Failed to get private key")
		}
		if state.endpointErr {
			return fmt.Errorf("failed to set endpoint")
		}
		if state.handshakeFail {
			return fmt.Errorf("handshake failure")
		}
		return err
	case <-timer.C:
		// timeout before connected: kill process and return timeout
		_ = cmd.Process.Kill()
		return fmt.Errorf("connect timeout after %s", connectTimeout)
	}

	// Connected; keep running until process exits (or fatal condition kills it)
	err = <-waitCh

	state.mu.Lock()
	defer state.mu.Unlock()
	if state.privateKeyErr {
		return fmt.Errorf("Failed to get private key")
	}
	if state.endpointErr {
		return fmt.Errorf("failed to set endpoint")
	}
	if state.handshakeFail {
		return fmt.Errorf("handshake failure")
	}
	return err
}

func handleScanner(scan *bufio.Scanner, bind string, st *procState, cmd *exec.Cmd) {
	for scan.Scan() {
		line := scan.Text()
		lower := strings.ToLower(line)

		switch {
		case strings.Contains(line, "Connected to MASQUE server"):
			st.mu.Lock()
			if !st.serveAddrShown {
				logMsg("INFO", "serving proxy", map[string]string{"address": bind})
				st.serveAddrShown = true
			}
			st.mu.Unlock()
			st.markConnected()

		case strings.Contains(line, "no recent network activity"):
			// Just log info; do not stop
			logMsg("INFO", "connection test failed", nil)

		case strings.Contains(line, "handshake failure"):
			// Stop operation on handshake failure
			logMsg("ERROR", "handshake failure", nil)
			st.mu.Lock()
			st.handshakeFail = true
			st.mu.Unlock()
			_ = cmd.Process.Kill()

		case strings.Contains(line, "invalid endpoint"):
			logMsg("ERROR", "failed to set endpoint", nil)
			st.mu.Lock()
			st.endpointErr = true
			st.mu.Unlock()
			_ = cmd.Process.Kill()

		case strings.Contains(line, "Failed to get private key"):
			st.mu.Lock()
			st.privateKeyErr = true
			st.mu.Unlock()
			_ = cmd.Process.Kill()

		case strings.Contains(lower, "error"):
			// Keep consistent log formatting
			logMsg("INFO", lower, nil)
		}
	}
}

func logMsg(level, msg string, kv map[string]string) {
	ts := time.Now().Format("2006-01-02T15:04:05.000-07:00")
	line := fmt.Sprintf("time=%s level=%s msg=%q", ts, level, msg)
	for k, v := range kv {
		line += fmt.Sprintf(" %s=%s", k, v)
	}
	fmt.Println(line)
}
