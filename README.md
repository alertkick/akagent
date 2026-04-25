# AlertKick Agent

A lightweight, high-performance security monitoring agent for Linux systems using native eBPF technology. The AlertKick Agent captures system events using eBPF probes and ships them to the AlertKick platform for analysis.

## Architecture

- **Agent**: Captures and enriches raw system events using native eBPF
- **Backend**: Provides intelligence - compliance tagging, LLM analysis, alert rules

The agent captures events and enriches them with process/container context. All compliance logic, alert rules, and threat analysis happen in the AlertKick backend.

## Features

- **Native eBPF Security Monitoring**: Real-time kernel-level event capture
- **Process Events**: execve, process lifecycle, privilege changes
- **File Events**: File access, modifications, deletions
- **Network Events**: Connection attempts, DNS lookups
- **Privilege Events**: setuid, setgid, capability changes
- **Kernel Events**: Module loading, kernel parameter changes
- **Memory Events**: Executable memory regions (W+X)
- **Event Enrichment**: Full process context, container detection, parent chain
- **Secure Communication**: TLS-encrypted communication with AlertKick platform
- **Lightweight**: Minimal resource footprint with efficient eBPF-based collection

## Requirements

- Linux kernel 5.8 or later (for BPF CO-RE support)
- Go 1.21 or later (for building from source)
- CMake 2.8.12 or later (for packaging)
- systemd (for service management)
- Root/CAP_BPF privileges (for loading eBPF programs)

## Quick Start

### Installation from Package

Download the latest release for your distribution:

```bash
# Debian/Ubuntu
sudo dpkg -i alertkick-agent_*.deb

# RHEL/CentOS/Fedora
sudo rpm -i alertkick-agent-*.rpm
```

### Building from Source

```bash
# Clone the repository
git clone https://github.com/alertpriority/apagent.git
cd apagent

# Build the agent (includes eBPF programs)
make build

# The binary will be available at build/alertkick-agent
```

### Running the Agent

1. **Create a configuration file:**

```bash
sudo mkdir -p /etc/alertkick-agent
sudo cp alertkick-agent.conf.example /etc/alertkick-agent/alertkick-agent.conf
# Edit the configuration with your agent credentials
sudo nano /etc/alertkick-agent/alertkick-agent.conf
```

2. **Start the agent:**

```bash
# Using systemd
sudo systemctl enable alertkick-agent
sudo systemctl start alertkick-agent

# Or run directly
sudo /usr/bin/alertkick-agent
```

## Configuration

The agent configuration file is located at `/etc/alertkick-agent/alertkick-agent.conf`. Example configuration:

```json
{
  "Debug": false,
  "AgentToken": "your-agent-token",
  "AgentID": "your-agent-id",
  "AgentName": "my-server",
  "Subdomain": "your-subdomain",
  "Endpoint": "your-endpoint.alertkick.com:8585",
  "TLSInsecure": false
}
```

### Configuration Options

| Option | Description | Default |
|--------|-------------|---------|
| `Debug` | Enable debug logging | `false` |
| `AgentToken` | Authentication token from AlertKick | Required |
| `AgentID` | Unique identifier for this agent | Required |
| `AgentName` | Human-readable name for this host | Optional |
| `Subdomain` | Your AlertKick subdomain | Required |
| `Endpoint` | AlertKick server endpoint | Provided during setup |
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
| `AP_AGENT_SUBDOMAIN` | Your AlertKick subdomain |
| `AP_AGENT_ENDPOINT` | Override default server endpoint |

## Building Packages

### Build a DEB package (Debian/Ubuntu)

```bash
make package
# Output: build/alertkick-agent-*.deb
```

### Build an RPM package (RHEL/CentOS/Fedora)

```bash
make package
# Output: build/alertkick-agent-*.rpm
```

## Development

### Project Structure

```
.
├── agent/              # Core agent logic and server communication
├── ebpf/               # Native eBPF implementation
│   ├── native.go       # Main eBPF agent
│   ├── events.go       # Event types and handling
│   ├── enrichment.go   # Process/container enrichment
│   └── probes/         # eBPF C programs
│       ├── common.h
│       ├── process.bpf.c
│       ├── file.bpf.c
│       ├── network.bpf.c
│       ├── privilege.bpf.c
│       ├── kernel.bpf.c
│       └── memory.bpf.c
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
├── internal/           # Internal packages
│   ├── api/            # API types and interfaces
│   └── systemd/        # systemd integration
├── logger/             # Logging utilities
├── proc/               # /proc filesystem utilities
└── certs/              # TLS certificates
```

### Event Categories

The agent captures the following event categories:

| Category | Description | eBPF Probes |
|----------|-------------|-------------|
| `process` | Process execution, lifecycle | execve, exit, fork |
| `file` | File operations | openat, unlinkat, renameat |
| `network` | Network connections | connect, accept, bind |
| `privilege` | Privilege changes | setuid, setgid, capset |
| `kernel` | Kernel modifications | init_module, finit_module |
| `memory` | Memory protection | mprotect (W+X detection) |

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

## Event Flow

```
Kernel (eBPF) → Agent (Enrichment) → Endpoint (Gateway) → Kafka → API (Intelligence)
```

1. **eBPF probes** capture raw syscall events in kernel
2. **Agent** enriches events with process context (args, cwd, container info)
3. **Agent** waits for process end to capture full context (like Tetragon)
4. **Endpoint** receives events and pushes to Kafka
5. **API** applies compliance tags, runs LLM analysis, creates alerts

## Troubleshooting

### Check Agent Status

```bash
sudo systemctl status alertkick-agent
```

### View Logs

```bash
sudo journalctl -u alertkick-agent -f
```

### Debug Mode

Run the agent with debug output:

```bash
sudo /usr/bin/alertkick-agent -debug
```

### Check eBPF Programs

```bash
# List loaded BPF programs
sudo bpftool prog list | grep alertkick

# Check ring buffer
sudo bpftool map list | grep events
```

## License

This software is proprietary and requires a valid AlertKick subscription. See [LICENSE.txt](LICENSE.txt) for the full license agreement. Third-party open-source components and their licenses are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

## Support

For support and documentation, visit [https://alertkick.com/docs](https://alertkick.com/docs)
