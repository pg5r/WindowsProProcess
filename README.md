# WindowsProProcess 1.1

WindowsProProcess is a Windows-based CLI tool for process monitoring, network inspection, and packet analysis

It provides real-time process tracking, network connection inspection, and packet sniffing through an interactive command-line interface.

---

## Features

- List and filter running processes
- Monitor process creation and termination in real-time
- Suspend and resume processes
- Inspect network connections per process
- Scan process connections by name
- Capture and analyze network traffic between specific IPs
- Detect HTTP requests and responses
- Detect TLS encrypted traffic
- AutoFreeze mode (automatically suspends new processes)

---

## Requirements

- Windows OS
- Python 3.9+
- Administrator privileges (optitional)

### Python Dependencies

Install dependencies using:



## Launching the Tool

Start the CLI:

```bash
python main.py
```

You will enter an interactive shell:

```
[  $
```

---

## Commands

### Process Management

```bash
process show all
```

```bash
process show pid <pid>
```

```bash
process grep <name>
```

```bash
process show connections <pid>
```

---

### Process Monitoring

```bash
process detect <count> create
```

```bash
process detect <count> deleted
```

---

### Process Control

```bash
process freeze <pid>
```

```bash
process hot <pid>
```

---

### Network Inspection

```bash
process scan connections <process_name>
```

---

### Packet Sniffing

```bash
sniff connection <src>=<dst> <count>
```

Example:

```bash
sniff connection 192.168.1.10=8.8.8.8 5
```

---

## Parameters

### AutoFreeze

```bash
params autofreeze
```

```bash
params autofreeze <on|off>
```

---

### Capture Created and Deleted files
```bash
sniff files <count> <path>
```

## Notes

- Requires administrator privileges
- Scapy may need elevated permissions
- TLS traffic is detected but not decrypted
- Use only in authorized environments

---

## Disclaimer

Educational use only.
Unauthorized usage may violate laws.
