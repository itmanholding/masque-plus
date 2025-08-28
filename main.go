package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
)

func main() {
	endpoint := flag.String("endpoint", "", "Endpoint to connect (IPv4 or IPv6)")
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

	// Patch config
	cfg := make(map[string]interface{})
	if _, err := os.Stat(configFile); err == nil {
		data, err := os.ReadFile(configFile)
		if err != nil {
			fmt.Printf("Failed to read config: %v\n", err)
			os.Exit(1)
		}
		json.Unmarshal(data, &cfg)
	}

	ip := net.ParseIP(*endpoint)
	if ip == nil {
		fmt.Println("Error: invalid endpoint IP")
		os.Exit(1)
	}

	if ip.To4() != nil {
		// IPv4
		cfg["endpoint_v4"] = *endpoint
		fmt.Println("Using IPv4 endpoint")
	} else {
		// IPv6
		cfg["endpoint_v6"] = *endpoint
		fmt.Println("Using IPv6 endpoint")
	}

	newData, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile(configFile, newData, 0644)

	// Run SOCKS proxy
	if err := runSocks(usquePath, configFile, bindIP, bindPort); err != nil {
		if strings.Contains(err.Error(), "Failed to get private key") {
			fmt.Println("Private key error detected, re-registering...")
			runRegister(usquePath)
			runSocks(usquePath, configFile, bindIP, bindPort)
		} else {
			fmt.Printf("Failed to start SOCKS proxy: %v\n", err)
			os.Exit(1)
		}
	}
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
