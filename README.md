# IkeProbe - IKE Service Detector

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Scapy](https://img.shields.io/badge/requires-scapy-orange.svg)](https://scapy.net/)

**IkeProbe** is a specialized network reconnaissance tool for detecting Internet Key Exchange (IKE) VPN services. It supports both IKEv1 and IKEv2 protocols across IPv4 and IPv6 networks, with NAT-T awareness for modern VPN deployments.

## Features

- **Multi-Protocol Support**: Detects both IKEv1 and IKEv2 services
- **IPv4 & IPv6**: Full support for both IP versions
- **NAT-T Aware**: Automatic detection on ports 500 and 4500 with proper non-ESP marker handling
- **Multiple Detection Methods**: 
  - Simple UDP reachability test
  - IKEv1 Main Mode probe
  - IKEv1 Aggressive Mode probe  
  - IKEv2 IKE_SA_INIT probe
- **Robust Packet Construction**: Uses proper Scapy IKE/ISAKMP layers for spec-compliant packets
- **Advanced Options**: Configurable timeouts, retries, source ports, and network interfaces
- **Detailed Output**: Verbose mode with packet dumps and header analysis

## Installation

### Prerequisites

- Python 3.6 or higher
- Scapy library
- Root/Administrator privileges (recommended for reliable results)

### Install Dependencies

```bash
# Install Scapy
pip install scapy

# For IKEv2 support (optional but recommended)
pip install scapy[complete]
```

### Download IkeProbe

```bash
git clone https://github.com/5u5urrus/IkeProbe.git
cd IkeProbe
chmod +x ikeprobe.py
```

## Usage

### Basic Usage

```bash
# Scan default IKE port (500/udp)
sudo python3 ikeprobe.py 192.168.1.1

# Scan specific port
sudo python3 ikeprobe.py 192.168.1.1 -p 4500

# IPv6 target
sudo python3 ikeprobe.py 2001:db8::1
```

### Advanced Options

```bash
# Verbose output with packet dumps
sudo python3 ikeprobe.py 192.168.1.1 -v -d

# Try NAT-T port first, then standard port
sudo python3 ikeprobe.py 192.168.1.1 --natt-first

# Custom timeout and retries
sudo python3 ikeprobe.py 192.168.1.1 -t 5 -r 2

# Fixed source port (helpful for NAT environments)
sudo python3 ikeprobe.py 192.168.1.1 --sport 12345

# Test all methods even after detection
sudo python3 ikeprobe.py 192.168.1.1 -a
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `target` | Target IP address (IPv4 or IPv6) |
| `-p, --port` | UDP port to scan (default: 500) |
| `-t, --timeout` | Timeout in seconds (default: 3) |
| `-r, --retries` | Number of retries on timeout (default: 0) |
| `--iface` | Network interface to use |
| `--sport` | Source UDP port (helps with NAT) |
| `--natt-first` | Try NAT-T port 4500 before specified port |
| `-v, --verbose` | Enable verbose output |
| `-d, --dump` | Hex dump sent/received packets |
| `-a, --all` | Continue testing all methods after detection |

## Detection Methods

### Method 0: Simple UDP Probe
Tests basic UDP reachability to provide context for subsequent tests.

### Method 1: IKEv1 Main Mode
Sends a properly formatted IKEv1 Main Mode SA proposal with:
- 3DES and AES-128 encryption options
- SHA1 hash and PSK authentication
- MODP-2048 (Group 14) Diffie-Hellman

### Method 2: IKEv1 Aggressive Mode
Attempts IKEv1 Aggressive Mode detection (best-effort approach).

### Method 3: IKEv2 IKE_SA_INIT
Sends a complete IKEv2 IKE_SA_INIT message including:
- SA payload with AES-128/SHA1/HMAC-SHA1-96/DH14 proposal
- Key Exchange (KE) payload with MODP-2048 data
- Nonce (Ni) payload

## Example Output

```
╔═══════════════════════════════════════════════╗
║                                               ║
║  IKEProbe - IKE Service Detector              ║
║  IKEv1 / IKEv2 • IPv4/IPv6 • NAT-T aware      ║
║  Version: 1.4.0                               ║
║                                               ║
╚═══════════════════════════════════════════════╝

[*] Target: 192.168.1.1:500
[*] Timeout: 3 seconds • Retries: 0
[*] Probing IKE service (v1/v2, NAT-T aware)...

[*] Method 1: IKEv1 Main Mode probe (SA: 3DES + AES)
  [+] IKEv1 service detected (Main/Aggressive).

======== DETECTION SUMMARY ========
[+] IKE service detected on 192.168.1.1 (port 500)
[+] Hit: 1@500
====================================
```

## Technical Details

### Packet Construction
IkeProbe uses Scapy's native IKE/ISAKMP layers to construct protocol-compliant packets, ensuring compatibility with legitimate IKE implementations.

### NAT-T Support
Automatically handles NAT Traversal (RFC 3947) by:
- Testing both UDP/500 and UDP/4500
- Adding/removing non-ESP markers as needed
- Detecting NAT-T usage in responses

### Error Handling
Robust handling of:
- ICMP Port Unreachable responses
- Truncated or malformed packets
- Network timeouts and retries
- Missing Scapy contrib modules

## Use Cases

- **Network Security Assessments**: Identify VPN endpoints during penetration testing
- **Network Discovery**: Map VPN infrastructure in enterprise environments  
- **Compliance Auditing**: Verify IKE service configurations
- **Troubleshooting**: Diagnose VPN connectivity issues

## Limitations

- Requires root privileges for optimal packet crafting and raw socket access
- Some enterprise firewalls may drop crafted packets
- Detection success depends on IKE implementation's response behavior
- Does not attempt to crack or bypass VPN authentication

## Contributing

Contributions are welcome! Please feel free to:
- Report bugs or issues
- Suggest new features or detection methods
- Submit pull requests with improvements
- Share feedback from real-world testing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is intended for authorized security testing and network administration purposes only. Users are responsible for complying with applicable laws and regulations. The author assumes no liability for misuse of this software.

## Author

**Vahe Demirkhanyan**
- GitHub: [@5u5urrus](https://github.com/5u5urrus)

---

*IkeProbe - Professional IKE service detection for security professionals*
