# AlertPriority Agent

A lightweight, high-performance monitoring agent for Linux systems. The AlertPriority Agent collects system metrics, monitors services, and integrates with Falco for security event detection.

## Features

- **System Metrics Collection**: CPU usage, memory utilization, load averages
- **Service Monitoring**: Track systemd services and listening ports
- **Package Inventory**: Monitor installed packages across your infrastructure
- **Falco Integration**: Real-time security event monitoring with Falco support
- **Secure Communication**: TLS-encrypted communication with the AlertPriority platform
- **Lightweight**: Minimal resource footprint with efficient metric collection

## Requirements

- Linux kernel 4.16 or later
- Go 1.21 or later (for building from source)
- CMake 2.8.12 or later (for packaging)
- systemd (for service management)

## Quick Start

### Installation from Package

Download the latest release for your distribution:

```bash
# Debian/Ubuntu
sudo dpkg -i alertpriority-agent_*.deb

# RHEL/CentOS/Fedora
sudo rpm -i alertpriority-agent-*.rpm
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/alertpriority/apagent.git
cd apagent

# Build the agent
make build

# The binary will be available at build/alertpriority-agent
```

### Running the Agent

1. **Create a configuration file:**

```bash
sudo mkdir -p /etc/alertpriority
sudo cp alertpriority-agent.conf.example /etc/alertpriority/alertpriority-agent.conf
# Edit the configuration with your agent credentials
sudo nano /etc/alertpriority/alertpriority-agent.conf
```

2. **Start the agent:**

```bash
# Using systemd
sudo systemctl enable alertpriority-agent
sudo systemctl start alertpriority-agent

# Or run directly
sudo /usr/bin/alertpriority-agent
```

## Configuration

The agent configuration file is located at `/etc/alertpriority/alertpriority-agent.conf`. Example configuration:

```json
{
  "Debug": false,
  "AgentToken": "your-agent-token",
  "AgentID": "your-agent-id",
  "AgentName": "my-server",
  "Subdomain": "your-subdomain",
  "Endpoint": "monit.alertpriority.com:8484",
  "FalcoEnabled": false,
  "TLSInsecure": false
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `Debug` | Enable debug logging | `false` |
| `AgentToken` | Authentication token from AlertPriority | Required |
| `AgentID` | Unique identifier for this agent | Required |
| `AgentName` | Human-readable name for this host | Optional |
| `Subdomain` | Your AlertPriority subdomain | Required |
| `Endpoint` | AlertPriority server endpoint | `monit.alertpriority.com:8484` |
| `FalcoEnabled` | Enable Falco security event monitoring | `false` |
| `TLSInsecure` | Skip TLS certificate verification | `false` |
| `TLSCAFilePath` | Path to additional CA certificate | Optional |

### Environment Variables

The agent can also be configured via environment variables during setup:

| Variable | Description |
|----------|-------------|
| `AP_AGENT_ENV` | Environment (staging/production) |
| `AP_AGENT_TOKEN` | Agent authentication token |
| `AP_AGENT_ID` | Unique agent identifier |
| `AP_AGENT_HOST_LABEL` | Host label for display |
| `AP_AGENT_SUBDOMAIN` | Your AlertPriority subdomain |

## Building Packages

### Build a DEB package (Debian/Ubuntu)

```bash
make package
# Output: build/alertpriority-agent-*.deb
```

### Build an RPM package (RHEL/CentOS/Fedora)

```bash
make package
# Output: build/alertpriority-agent-*.rpm
```

## Development

### Project Structure

```
.
├── agent/              # Core agent logic and server communication
├── checker/            # Check execution and scheduling
├── checks/             # Individual monitoring checks
│   ├── cpu/            # CPU usage monitoring
│   ├── memory/         # Memory usage monitoring
│   ├── load_avg/       # Load average monitoring
│   ├── http/           # HTTP endpoint checks
│   ├── ports/          # Port monitoring
│   └── services/       # Service status monitoring
├── client/             # TLS connection and RPC client
├── cmd/                # Main application entry point
├── config/             # Configuration management
├── falco_manager/      # Falco integration
├── internal/           # Internal packages
│   ├── api/            # API types and interfaces
│   └── systemd/        # systemd integration
├── logger/             # Logging utilities
├── proc/               # /proc filesystem utilities
└── certs/              # TLS certificates
```

### Running Tests

```bash
make test
```

### Code Quality

```bash
# Format code
make tidy

# Run linters and checks
make audit
```

## Falco Integration

The agent supports integration with [Falco](https://falco.org/) for runtime security monitoring. When enabled, the agent:

1. Configures Falco to send events via HTTP
2. Receives and forwards security events to AlertPriority
3. Manages Falco rule files in `/etc/falco/rules.alertpriority/`

To enable Falco integration:

1. Install Falco on your system
2. Set `FalcoEnabled: true` in the agent configuration
3. Restart the agent

## Troubleshooting

### Check Agent Status

```bash
sudo systemctl status alertpriority-agent
```

### View Logs

```bash
sudo journalctl -u alertpriority-agent -f
```

### Debug Mode

Run the agent with debug output:

```bash
sudo /usr/bin/alertpriority-agent -debug
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE.txt](LICENSE.txt) file for details.

## Support

For support and documentation, visit [https://alertpriority.com/docs](https://alertpriority.com/docs)

