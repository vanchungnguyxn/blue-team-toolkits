"""Packet analysis and threat detection for Blue Team Toolkit."""

import logging
import time

from .capture import PacketInfo
from .config import DetectionConfig
from .storage import Event
from .utils import SlidingWindowCounter

logger = logging.getLogger(__name__)


class PortScanDetector:
    """Detect port scanning activity."""

    def __init__(self, config):
        """Initialize port scan detector.

        Args:
            config: PortscanConfig object.
        """
        self.config = config
        self.port_trackers = SlidingWindowCounter(config.window_sec)

    def process_packet(self, packet: PacketInfo) -> list[Event]:
        """Process packet for port scan detection.

        Args:
            packet: Packet information.

        Returns:
            List of events (empty if no detection).
        """
        events = []

        # Only track TCP and UDP packets with destination ports
        if packet.protocol in ["TCP", "UDP"] and packet.dst_port:
            # Track unique destination ports per source IP
            key = packet.src_ip
            self.port_trackers.add(key, packet.dst_port, packet.timestamp)

            # Check if threshold exceeded
            unique_ports = self.port_trackers.get_unique_values(key, packet.timestamp)
            if len(unique_ports) >= self.config.unique_ports_threshold:
                # Create port scan event
                port_list = sorted(list(unique_ports))[:10]  # Limit for readability
                details = f"Scanned ports: {port_list}"
                if len(unique_ports) > 10:
                    details += f" (and {len(unique_ports) - 10} more)"

                event = Event.create(
                    event_type="PORTSCAN",
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    count=len(unique_ports),
                    details=details,
                    timestamp=packet.timestamp,
                )
                events.append(event)

                logger.warning(
                    f"Port scan detected from {packet.src_ip}: "
                    f"{len(unique_ports)} unique ports in {self.config.window_sec}s"
                )

        return events

    def get_stats(self) -> dict[str, int]:
        """Get detector statistics."""
        return self.port_trackers.get_stats()


class BruteForceDetector:
    """Detect brute force authentication attempts."""

    def __init__(self, config):
        """Initialize brute force detector.

        Args:
            config: BruteforceConfig object.
        """
        self.config = config
        self.failure_trackers = SlidingWindowCounter(config.window_sec)

        # Service port mappings
        self.service_ports = {
            "ssh": [22],
            "http": [80, 8080, 8000],
            "https": [443, 8443],
            "ftp": [21],
            "telnet": [23],
            "smtp": [25, 587],
            "pop3": [110, 995],
            "imap": [143, 993],
        }

    def _is_monitored_service(self, port: int) -> str | None:
        """Check if port belongs to monitored service.

        Args:
            port: Port number.

        Returns:
            Service name if monitored, None otherwise.
        """
        for service in self.config.services:
            if port in self.service_ports.get(service, []):
                return service
        return None

    def _is_auth_failure(self, packet: PacketInfo, service: str) -> bool:
        """Determine if packet indicates authentication failure.

        Args:
            packet: Packet information.
            service: Service name.

        Returns:
            True if authentication failure detected.
        """
        # SSH: TCP RST indicates connection rejection/failure
        if service == "ssh" and packet.protocol == "TCP":
            return packet.tcp_flags and "RST" in packet.tcp_flags

        # HTTP/HTTPS: Look for potential auth failure indicators
        # Note: This is simplified - real implementation would need
        # HTTP response code inspection
        if service in ["http", "https"] and packet.protocol == "TCP":
            # Multiple rapid connections to same port could indicate brute force
            return packet.tcp_flags and "SYN" in packet.tcp_flags

        return False

    def process_packet(self, packet: PacketInfo) -> list[Event]:
        """Process packet for brute force detection.

        Args:
            packet: Packet information.

        Returns:
            List of events (empty if no detection).
        """
        events = []

        if not packet.dst_port:
            return events

        # Check if this is a monitored service
        service = self._is_monitored_service(packet.dst_port)
        if not service:
            return events

        # Check if this indicates an authentication failure
        if self._is_auth_failure(packet, service):
            key = f"{packet.src_ip}:{service}"
            self.failure_trackers.add(key, 1, packet.timestamp)

            # Check if threshold exceeded
            failure_count = self.failure_trackers.count(key, packet.timestamp)
            if failure_count >= self.config.fail_threshold:
                event = Event.create(
                    event_type="BRUTEFORCE",
                    src_ip=packet.src_ip,
                    dst_ip=packet.dst_ip,
                    count=failure_count,
                    details=f"Service: {service}, Port: {packet.dst_port}",
                    timestamp=packet.timestamp,
                )
                events.append(event)

                logger.warning(
                    f"Brute force detected from {packet.src_ip} against {service}: "
                    f"{failure_count} failures in {self.config.window_sec}s"
                )

        return events

    def get_stats(self) -> dict[str, int]:
        """Get detector statistics."""
        return self.failure_trackers.get_stats()


class DosDetector:
    """Detect Denial of Service attacks."""

    def __init__(self, config):
        """Initialize DoS detector.

        Args:
            config: DosConfig object.
        """
        self.config = config
        self.packet_trackers = SlidingWindowCounter(config.window_sec)

    def process_packet(self, packet: PacketInfo) -> list[Event]:
        """Process packet for DoS detection.

        Args:
            packet: Packet information.

        Returns:
            List of events (empty if no detection).
        """
        events = []

        # Track packet count per source IP
        key = packet.src_ip
        self.packet_trackers.add(key, 1, packet.timestamp)

        # Check if threshold exceeded
        packet_count = self.packet_trackers.count(key, packet.timestamp)
        if packet_count >= self.config.packet_threshold:
            event = Event.create(
                event_type="DOS",
                src_ip=packet.src_ip,
                dst_ip=packet.dst_ip,
                count=packet_count,
                details=f"Protocol: {packet.protocol}",
                timestamp=packet.timestamp,
            )
            events.append(event)

            logger.warning(
                f"DoS attack detected from {packet.src_ip}: "
                f"{packet_count} packets in {self.config.window_sec}s"
            )

        return events

    def get_stats(self) -> dict[str, int]:
        """Get detector statistics."""
        return self.packet_trackers.get_stats()


class ThreatAnalyzer:
    """Main threat analysis engine."""

    def __init__(self, config: DetectionConfig):
        """Initialize threat analyzer.

        Args:
            config: Detection configuration.
        """
        self.config = config
        self.portscan_detector = PortScanDetector(config.portscan)
        self.bruteforce_detector = BruteForceDetector(config.bruteforce)
        self.dos_detector = DosDetector(config.dos)

        self.packet_count = 0
        self.event_count = 0
        self.start_time = time.time()

    def process_packet(self, packet: PacketInfo) -> list[Event]:
        """Process packet through all threat detectors.

        Args:
            packet: Packet information.

        Returns:
            List of detected events.
        """
        self.packet_count += 1
        all_events = []

        try:
            # Run packet through all detectors
            events = self.portscan_detector.process_packet(packet)
            all_events.extend(events)

            events = self.bruteforce_detector.process_packet(packet)
            all_events.extend(events)

            events = self.dos_detector.process_packet(packet)
            all_events.extend(events)

            self.event_count += len(all_events)

        except Exception as e:
            logger.error(f"Error processing packet: {e}")

        return all_events

    def get_stats(self) -> dict[str, any]:
        """Get analyzer statistics.

        Returns:
            Dictionary with analyzer statistics.
        """
        duration = time.time() - self.start_time
        pps = self.packet_count / duration if duration > 0 else 0

        return {
            "packet_count": self.packet_count,
            "event_count": self.event_count,
            "duration_sec": duration,
            "packets_per_sec": pps,
            "portscan_stats": self.portscan_detector.get_stats(),
            "bruteforce_stats": self.bruteforce_detector.get_stats(),
            "dos_stats": self.dos_detector.get_stats(),
        }

    def reset_stats(self) -> None:
        """Reset analyzer statistics."""
        self.packet_count = 0
        self.event_count = 0
        self.start_time = time.time()

    def cleanup(self) -> None:
        """Clean up detector state."""
        self.portscan_detector.port_trackers.clear()
        self.bruteforce_detector.failure_trackers.clear()
        self.dos_detector.packet_trackers.clear()
