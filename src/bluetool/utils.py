"""Utility functions and classes for Blue Team Toolkit."""

import ipaddress
import logging
import socket
import time
from collections import defaultdict
from typing import Any

logger = logging.getLogger(__name__)


class SlidingWindowCounter:
    """Thread-safe sliding window counter with TTL expiry."""

    def __init__(self, window_sec: int):
        """Initialize sliding window counter.

        Args:
            window_sec: Window size in seconds.
        """
        self.window_sec = window_sec
        self._data: dict[str, dict[float, Any]] = defaultdict(dict)

    def add(self, key: str, value: Any = 1, timestamp: float = None) -> None:
        """Add value to sliding window.

        Args:
            key: Counter key.
            value: Value to add (default: 1).
            timestamp: Event timestamp (default: current time).
        """
        if timestamp is None:
            timestamp = time.time()

        self._data[key][timestamp] = value
        self._cleanup(key, timestamp)

    def count(self, key: str, timestamp: float = None) -> int:
        """Get count of items in sliding window.

        Args:
            key: Counter key.
            timestamp: Current timestamp (default: current time).

        Returns:
            Count of items in window.
        """
        if timestamp is None:
            timestamp = time.time()

        self._cleanup(key, timestamp)
        return len(self._data[key])

    def get_unique_values(self, key: str, timestamp: float = None) -> set[Any]:
        """Get unique values in sliding window.

        Args:
            key: Counter key.
            timestamp: Current timestamp (default: current time).

        Returns:
            Set of unique values in window.
        """
        if timestamp is None:
            timestamp = time.time()

        self._cleanup(key, timestamp)
        return set(self._data[key].values())

    def _cleanup(self, key: str, current_time: float) -> None:
        """Remove expired entries from window.

        Args:
            key: Counter key.
            current_time: Current timestamp.
        """
        cutoff_time = current_time - self.window_sec
        expired_keys = [ts for ts in self._data[key].keys() if ts < cutoff_time]

        for ts in expired_keys:
            del self._data[key][ts]

        # Clean up empty keys
        if not self._data[key]:
            del self._data[key]

    def clear(self) -> None:
        """Clear all data."""
        self._data.clear()

    def get_stats(self) -> dict[str, int]:
        """Get statistics about the counter.

        Returns:
            Dictionary with counter statistics.
        """
        return {
            "active_keys": len(self._data),
            "total_entries": sum(len(entries) for entries in self._data.values()),
        }


def is_valid_ip(ip_str: str) -> bool:
    """Check if string is a valid IP address.

    Args:
        ip_str: IP address string.

    Returns:
        True if valid IP address.
    """
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_private_ip(ip_str: str) -> bool:
    """Check if IP address is in private range.

    Args:
        ip_str: IP address string.

    Returns:
        True if private IP address.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.is_private
    except ValueError:
        return False


def get_ip_version(ip_str: str) -> int:
    """Get IP version (4 or 6).

    Args:
        ip_str: IP address string.

    Returns:
        IP version (4 or 6), or 0 if invalid.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return ip.version
    except ValueError:
        return 0


def resolve_hostname(hostname: str) -> str:
    """Resolve hostname to IP address.

    Args:
        hostname: Hostname to resolve.

    Returns:
        IP address string, or original hostname if resolution fails.
    """
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        logger.warning(f"Failed to resolve hostname: {hostname}")
        return hostname


def format_bytes(num_bytes: int) -> str:
    """Format bytes in human readable format.

    Args:
        num_bytes: Number of bytes.

    Returns:
        Human readable string (e.g., "1.5 KB").
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


def format_duration(seconds: float) -> str:
    """Format duration in human readable format.

    Args:
        seconds: Duration in seconds.

    Returns:
        Human readable duration string.
    """
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.1f}m"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.1f}h"
    else:
        days = seconds / 86400
        return f"{days:.1f}d"


def get_service_name(port: int, protocol: str = "tcp") -> str:
    """Get service name for port number.

    Args:
        port: Port number.
        protocol: Protocol (tcp/udp).

    Returns:
        Service name or port number as string.
    """
    well_known_ports = {
        20: "ftp-data",
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        993: "imaps",
        995: "pop3s",
        3389: "rdp",
        5432: "postgresql",
        3306: "mysql",
        1433: "mssql",
        6379: "redis",
        27017: "mongodb",
    }

    return well_known_ports.get(port, str(port))


def sanitize_filename(filename: str) -> str:
    """Sanitize filename by removing invalid characters.

    Args:
        filename: Original filename.

    Returns:
        Sanitized filename.
    """
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, "_")
    return filename


def truncate_string(text: str, max_length: int = 100) -> str:
    """Truncate string to maximum length.

    Args:
        text: Text to truncate.
        max_length: Maximum length.

    Returns:
        Truncated text with ellipsis if needed.
    """
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def get_network_interfaces():
    """Get available network interfaces.

    Returns:
        List of network interface names.
    """
    try:
        import scapy.all as scapy

        return scapy.get_if_list()
    except ImportError:
        logger.error("Scapy not available for interface detection")
        return []
    except Exception as e:
        logger.error(f"Failed to get network interfaces: {e}")
        return []


def auto_select_interface() -> str:
    """Auto-select best network interface for monitoring.

    Returns:
        Interface name or empty string if none found.
    """
    try:
        import scapy.all as scapy

        # Get default route interface
        try:
            default_iface = scapy.conf.route.route("0.0.0.0")[0]
            if default_iface:
                return default_iface
        except Exception:
            pass

        # Fallback to first non-loopback interface
        interfaces = scapy.get_if_list()
        for iface in interfaces:
            if not iface.startswith(("lo", "Loopback")):
                return iface

        # Last resort - use any interface
        if interfaces:
            return interfaces[0]

    except ImportError:
        logger.error("Scapy not available for interface auto-selection")
    except Exception as e:
        logger.error(f"Failed to auto-select interface: {e}")

    return ""
