package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func main() {
	endpoint := flag.String("endpoint", "", "Endpoint to connect (IPv4/IPv6; supports IP or IP:Port; for IPv6 with port use [IPv6]:Port)")
	bind := flag.String("bind", "127.0.0.1:1080", "IP:Port to bind SOCKS proxy")
	renew := flag.Bool("renew", false, "Force renewal of config even if config.json exists")
	flag.Parse()

	if *endpoint == "" {
		fmt.Println("Error: --endpoint is required")
		os.Exit(1)
	}

	usquePath := "./usque" // Path to usque binary
	configFile := "./config.json"

	// Split bind into IP and Port
	parts := strings.Split(*bind, ":")
	if len(parts) != 2 {
		fmt.Println("Error: --bind must be in format IP:Port")
		os.Exit(1)
	}
	bindIP, bindPort := parts[0], parts[1]

	// Determine if registration is needed
	needRegister := *renew
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		needRegister = true
	}

	if needRegister {
		fmt.Println("Registering usque (renew or config missing)...")
		if err := runRegister(usquePath); err != nil {
			fmt.Printf("Registration failed: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Println("Config found, skipping registration...")
	}

	// Load existing config (if any)
	cfg := make(map[string]interface{})
	if _, err := os.Stat(configFile); err == nil {
		data, err := os.ReadFile(configFile)
		if err != nil {
			fmt.Printf("Failed to read config: %v\n", err)
			os.Exit(1)
		}
		_ = json.Unmarshal(data, &cfg)
	}

	// Parse endpoint: support IP and IP:Port (IPv6 with port must be [ip]:port)
	ip, port, err := parseEndpoint(*endpoint)
	if err != nil {
		fmt.Printf("Error: invalid endpoint: %v\n", err)
		os.Exit(1)
	}

	if ip.To4() != nil {
		// IPv4
		cfg["endpoint_v4"] = ip.String()
		if port != "" {
			cfg["endpoint_v4_port"] = port
		}
		fmt.Println("Using IPv4 endpoint")
	} else {
		// IPv6
		cfg["endpoint_v6"] = ip.String()
		if port != "" {
			cfg["endpoint_v6_port"] = port
		}
		fmt.Println("Using IPv6 endpoint")
	}

	newData, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(configFile, newData, 0644); err != nil {
		fmt.Printf("Failed to write config: %v\n", err)
		os.Exit(1)
	}

	// Run SOCKS proxy
	if err := runSocks(usquePath, configFile, bindIP, bindPort); err != nil {
		if strings.Contains(err.Error(), "Failed to get private key") {
			fmt.Println("Private key error detected, re-registering...")
			_ = runRegister(usquePath)
			if err := runSocks(usquePath, configFile, bindIP, bindPort); err != nil {
				fmt.Printf("Failed to start SOCKS proxy after re-register: %v\n", err)
				os.Exit(1)
			}
		} else {
			fmt.Printf("Failed to start SOCKS proxy: %v\n", err)
			os.Exit(1)
		}
	}
}

func parseEndpoint(ep string) (net.IP, string, error) {
	// Try to split host:port first (works for IPv4 and for bracketed IPv6)
	host, port, err := net.SplitHostPort(ep)
	if err == nil {
		// Validate IP
		ip := net.ParseIP(host)
		if ip == nil {
			return nil, "", fmt.Errorf("invalid IP in endpoint")
		}
		// Validate port range
		if err := validatePort(port); err != nil {
			return nil, "", err
		}
		return ip, port, nil
	}

	// If SplitHostPort failed, it might be a bare IP (IPv4 or IPv6 without port)
	ip := net.ParseIP(ep)
	if ip != nil {
		return ip, "", nil
	}

	// Special case: some users might pass raw IPv6 with port without brackets (ambiguous).
	// We treat that as invalid and instruct to use [IPv6]:Port.
	if strings.Count(ep, ":") >= 2 && strings.Contains(ep, ":") {
		return nil, "", fmt.Errorf("IPv6 with port must be in the form [IPv6]:Port")
	}

	// Otherwise, it's just invalid.
	return nil, "", fmt.Errorf("could not parse endpoint")
}

func validatePort(p string) error {
	n, err := strconv.Atoi(p)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("invalid port %q", p)
	}
	return nil
}

func runRegister(path string) error {
	cmd := exec.Command(path, "register", "-n", "masque-plus")
	stdin, _ := cmd.StdinPipe()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	stdin.Write([]byte("y\ny\n"))
	stdin.Close()
	return cmd.Wait()
}

func runSocks(path, config, bindIP, bindPort string) error {
	cmd := exec.Command(path, "socks", "--config", config, "-b", bindIP, "-p", bindPort)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
