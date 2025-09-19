# Demo PCAP File

This directory should contain a demo PCAP file (`demo.pcap`) for testing Blue Team Toolkit functionality.

## Creating a Demo PCAP

To create a demo PCAP file with suspicious traffic patterns:

### Option 1: Use tcpdump/Wireshark
```bash
# Capture some network traffic
sudo tcpdump -i any -w demo.pcap -c 1000

# Or use Wireshark to capture and save traffic
```

### Option 2: Generate synthetic traffic with scapy
```python
#!/usr/bin/env python3
from scapy.all import *

packets = []

# Port scan simulation - single IP scanning multiple ports
src_ip = "192.168.1.100"
dst_ip = "192.168.1.1"

for port in range(20, 100):  # Scan ports 20-99
    pkt = IP(src=src_ip, dst=dst_ip) / TCP(dport=port, flags="S")
    packets.append(pkt)

# Brute force simulation - multiple failed SSH attempts
for i in range(15):
    pkt = IP(src="10.0.0.50", dst="192.168.1.10") / TCP(dport=22, flags="R")
    packets.append(pkt)

# DoS simulation - high rate of packets
for i in range(600):
    pkt = IP(src="172.16.0.200", dst="192.168.1.1") / TCP(dport=80, flags="S")
    packets.append(pkt)

# Write to PCAP file
wrpcap("demo.pcap", packets)
print(f"Created demo.pcap with {len(packets)} packets")
```

### Option 3: Download sample PCAP files
- [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/training-exercises.html)
- [PCAP samples from various sources](https://github.com/automayt/ICS-pcap)

## Expected Detections

The demo PCAP should trigger:
- **Port Scan**: Multiple unique ports accessed from single source
- **Brute Force**: Repeated authentication failures
- **DoS**: High packet rate from single source

## Usage

```bash
# Run demo with the PCAP file
bluetool demo

# Or use offline mode with custom PCAP
bluetool start --offline demo.pcap
```
