# Masque-Plus

A simple Go launcher for `usque` that handles registration, configuration, and running a SOCKS proxy.
Designed for **Cloudflare MASQUE protocol** usage.

Cross-platform: works on **Linux, macOS, and Windows**. The binaries are automatically built via **GitHub Actions**.

## Features

- Automatically registers `usque` if config is missing or renewal is requested.
- Supports both **IPv4** and **IPv6** endpoints.
- Starts a local SOCKS proxy on a specified IP and port.
- Handles private key errors by re-registering automatically.
- Cross-platform support for Linux, macOS, and Windows.

## Installation

Download the latest release for your system architecture from the [Releases page](https://github.com/ircfspace/masque-plus/releases/latest).

Place the `usque` binary in the same folder as this launcher (`Masque-Plus.exe` for Windows, or `Masque-Plus` for Linux/macOS).

## Usage

```bash
./Masque-Plus --endpoint <IP> [--bind <IP:Port>] [--renew]
```

### Flags

| Flag         | Description                                                               | Default          |
| ------------ | ------------------------------------------------------------------------- | ---------------- |
| `--endpoint` | **Required**. The MASQUE server endpoint to connect. Can be IPv4 or IPv6. | -                |
| `--bind`     | IP and port to bind the local SOCKS proxy. Format: `IP:Port`.             | `127.0.0.1:8086` |
| `--renew`    | Force renewal of the configuration even if `config.json` already exists.  | `false`          |

### Example

```bash
# Connect to MASQUE server at 162.159.198.2:443 and start a SOCKS proxy on default 127.0.0.1:8086
./Masque-Plus --endpoint 162.159.198.2:443

# Bind SOCKS proxy to custom IP and port
./Masque-Plus --endpoint 162.159.198.2:443 --bind 127.0.0.1:8086

# Force configuration renewal
./Masque-Plus --endpoint 162.159.198.2:443 --renew
```

## Notes

- Make sure the `usque` binary has execution permissions (`chmod +x usque` on Linux/macOS).
- Configurations are saved in `config.json` in the same folder.
- If a private key error occurs, the launcher will attempt to re-register `usque` automatically.

## Credits

- This project uses [`usque`](https://github.com/Diniboy1123/usque) as the core MASQUE implementation.
- MASQUE protocol and Cloudflare 1.1.1.1 inspired the functionality.
