# Blue Team Toolkit Detection Rules

## Port Scan Detection

**Rule**: Detect when a single source IP attempts to connect to multiple unique ports within a time window.

**Parameters**:
- `window_sec`: Time window in seconds (default: 5)
- `unique_ports_threshold`: Number of unique ports to trigger alert (default: 20)

**Logic**: Track unique destination ports per source IP within sliding window. Alert when threshold exceeded.

## Brute Force Detection

**Rule**: Detect repeated authentication failures from a single source IP.

**Parameters**:
- `services`: List of services to monitor ["ssh", "http", "https"]
- `window_sec`: Time window in seconds (default: 60)
- `fail_threshold`: Number of failures to trigger alert (default: 10)

**Logic**: 
- SSH: Count TCP RST packets to port 22
- HTTP/HTTPS: Count HTTP 401/403 responses on ports 80/443
- Alert when failure count exceeds threshold within window

## DoS Detection

**Rule**: Detect high packet rate from single source IP indicating potential DoS attack.

**Parameters**:
- `window_sec`: Time window in seconds (default: 5)
- `packet_threshold`: Number of packets to trigger alert (default: 500)

**Logic**: Count all packets from source IP within sliding window. Alert when rate exceeds threshold.

## Event Types

- **PORTSCAN**: Port scanning activity detected
- **BRUTEFORCE**: Brute force authentication attempts detected  
- **DOS**: Denial of Service attack pattern detected

## Alert Format

Each alert contains:
- Event ID (UUID)
- Event type (PORTSCAN/BRUTEFORCE/DOS)
- Source IP address
- Destination IP address (if applicable)
- Count of suspicious activity
- Additional details (ports scanned, service targeted, etc.)
- UTC timestamp
