"""Tests for packet analysis and threat detection."""

import time
import pytest

from bluetool.analyze import (
    PortScanDetector,
    BruteForceDetector,
    DosDetector,
    ThreatAnalyzer,
)
from bluetool.capture import PacketInfo
from bluetool.config import DetectionConfig, PortscanConfig, BruteforceConfig, DosConfig


class TestPortScanDetector:
    """Test port scan detection."""

    def test_port_scan_detection(self):
        """Test port scan detection with multiple unique ports."""
        config = PortscanConfig(window_sec=10, unique_ports_threshold=5)
        detector = PortScanDetector(config)

        src_ip = "192.168.1.100"
        dst_ip = "192.168.1.1"
        timestamp = time.time()

        # Send packets to different ports
        events = []
        for port in range(80, 90):  # 10 unique ports
            packet = PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="TCP",
                src_port=12345,
                dst_port=port,
                tcp_flags="S",
                length=60,
            )
            events.extend(detector.process_packet(packet))

        # Should detect port scan after 5th unique port
        assert len(events) >= 1
        event = events[0]
        assert event.type == "PORTSCAN"
        assert event.src_ip == src_ip
        assert event.count >= 5

    def test_no_port_scan_below_threshold(self):
        """Test that no port scan is detected below threshold."""
        config = PortscanConfig(window_sec=10, unique_ports_threshold=10)
        detector = PortScanDetector(config)

        src_ip = "192.168.1.100"
        dst_ip = "192.168.1.1"
        timestamp = time.time()

        # Send packets to only 5 unique ports (below threshold)
        events = []
        for port in range(80, 85):
            packet = PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="TCP",
                src_port=12345,
                dst_port=port,
                tcp_flags="S",
                length=60,
            )
            events.extend(detector.process_packet(packet))

        # Should not detect port scan
        assert len(events) == 0

    def test_port_scan_window_expiry(self):
        """Test that port scan detection respects time window."""
        config = PortscanConfig(window_sec=1, unique_ports_threshold=5)
        detector = PortScanDetector(config)

        src_ip = "192.168.1.100"
        dst_ip = "192.168.1.1"

        # Send packets to 3 ports at time T
        timestamp1 = time.time()
        for port in range(80, 83):
            packet = PacketInfo(
                timestamp=timestamp1,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="TCP",
                src_port=12345,
                dst_port=port,
                tcp_flags="S",
                length=60,
            )
            detector.process_packet(packet)

        # Wait for window to expire
        time.sleep(1.1)

        # Send packets to 3 more ports at time T+1.1
        timestamp2 = time.time()
        events = []
        for port in range(90, 93):
            packet = PacketInfo(
                timestamp=timestamp2,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="TCP",
                src_port=12345,
                dst_port=port,
                tcp_flags="S",
                length=60,
            )
            events.extend(detector.process_packet(packet))

        # Should not detect port scan (old ports expired)
        assert len(events) == 0

    def test_port_scan_udp_packets(self):
        """Test port scan detection with UDP packets."""
        config = PortscanConfig(window_sec=10, unique_ports_threshold=3)
        detector = PortScanDetector(config)

        src_ip = "192.168.1.100"
        dst_ip = "192.168.1.1"
        timestamp = time.time()

        # Send UDP packets to different ports
        events = []
        for port in range(53, 58):  # 5 unique ports
            packet = PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="UDP",
                src_port=12345,
                dst_port=port,
                length=60,
            )
            events.extend(detector.process_packet(packet))

        # Should detect port scan
        assert len(events) >= 1
        assert events[0].type == "PORTSCAN"

    def test_port_scan_ignores_no_dst_port(self):
        """Test that packets without destination port are ignored."""
        config = PortscanConfig(window_sec=10, unique_ports_threshold=3)
        detector = PortScanDetector(config)

        # ICMP packet without ports
        packet = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            protocol="ICMP",
            length=60,
        )

        events = detector.process_packet(packet)
        assert len(events) == 0


class TestBruteForceDetector:
    """Test brute force detection."""

    def test_ssh_brute_force_detection(self):
        """Test SSH brute force detection."""
        config = BruteforceConfig(services=["ssh"], window_sec=60, fail_threshold=5)
        detector = BruteForceDetector(config)

        src_ip = "10.0.0.50"
        dst_ip = "192.168.1.10"
        timestamp = time.time()

        # Send multiple SSH connection attempts with RST flags
        events = []
        for i in range(10):
            packet = PacketInfo(
                timestamp=timestamp + i,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="TCP",
                src_port=12345 + i,
                dst_port=22,  # SSH port
                tcp_flags="RST",
                length=60,
            )
            events.extend(detector.process_packet(packet))

        # Should detect brute force after 5th failure
        assert len(events) >= 1
        event = events[0]
        assert event.type == "BRUTEFORCE"
        assert event.src_ip == src_ip
        assert "ssh" in event.details.lower()

    def test_http_brute_force_detection(self):
        """Test HTTP brute force detection."""
        config = BruteforceConfig(services=["http"], window_sec=60, fail_threshold=3)
        detector = BruteForceDetector(config)

        src_ip = "10.0.0.50"
        dst_ip = "192.168.1.10"
        timestamp = time.time()

        # Send multiple HTTP connection attempts
        events = []
        for i in range(5):
            packet = PacketInfo(
                timestamp=timestamp + i,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="TCP",
                src_port=12345 + i,
                dst_port=80,  # HTTP port
                tcp_flags="SYN",
                length=60,
            )
            events.extend(detector.process_packet(packet))

        # Should detect brute force
        assert len(events) >= 1
        event = events[0]
        assert event.type == "BRUTEFORCE"
        assert "http" in event.details.lower()

    def test_no_brute_force_below_threshold(self):
        """Test that no brute force is detected below threshold."""
        config = BruteforceConfig(services=["ssh"], window_sec=60, fail_threshold=10)
        detector = BruteForceDetector(config)

        src_ip = "10.0.0.50"
        dst_ip = "192.168.1.10"
        timestamp = time.time()

        # Send only 5 attempts (below threshold)
        events = []
        for i in range(5):
            packet = PacketInfo(
                timestamp=timestamp + i,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="TCP",
                src_port=12345 + i,
                dst_port=22,
                tcp_flags="RST",
                length=60,
            )
            events.extend(detector.process_packet(packet))

        # Should not detect brute force
        assert len(events) == 0

    def test_brute_force_unmonitored_service(self):
        """Test that unmonitored services don't trigger detection."""
        config = BruteforceConfig(
            services=["ssh"], window_sec=60, fail_threshold=3  # Only monitor SSH
        )
        detector = BruteForceDetector(config)

        src_ip = "10.0.0.50"
        dst_ip = "192.168.1.10"
        timestamp = time.time()

        # Send packets to unmonitored port (FTP)
        events = []
        for i in range(10):
            packet = PacketInfo(
                timestamp=timestamp + i,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="TCP",
                src_port=12345 + i,
                dst_port=21,  # FTP port (not monitored)
                tcp_flags="RST",
                length=60,
            )
            events.extend(detector.process_packet(packet))

        # Should not detect brute force
        assert len(events) == 0


class TestDosDetector:
    """Test DoS detection."""

    def test_dos_detection(self):
        """Test DoS detection with high packet rate."""
        config = DosConfig(window_sec=5, packet_threshold=100)
        detector = DosDetector(config)

        src_ip = "172.16.0.200"
        dst_ip = "192.168.1.1"
        timestamp = time.time()

        # Send high volume of packets
        events = []
        for i in range(150):
            packet = PacketInfo(
                timestamp=timestamp + (i * 0.01),  # 10ms intervals
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="TCP",
                src_port=12345,
                dst_port=80,
                tcp_flags="S",
                length=60,
            )
            events.extend(detector.process_packet(packet))

        # Should detect DoS after threshold
        assert len(events) >= 1
        event = events[0]
        assert event.type == "DOS"
        assert event.src_ip == src_ip
        assert event.count >= 100

    def test_no_dos_below_threshold(self):
        """Test that no DoS is detected below threshold."""
        config = DosConfig(window_sec=5, packet_threshold=1000)
        detector = DosDetector(config)

        src_ip = "172.16.0.200"
        dst_ip = "192.168.1.1"
        timestamp = time.time()

        # Send moderate volume of packets (below threshold)
        events = []
        for i in range(100):
            packet = PacketInfo(
                timestamp=timestamp + (i * 0.01),
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="TCP",
                src_port=12345,
                dst_port=80,
                tcp_flags="S",
                length=60,
            )
            events.extend(detector.process_packet(packet))

        # Should not detect DoS
        assert len(events) == 0

    def test_dos_different_protocols(self):
        """Test DoS detection across different protocols."""
        config = DosConfig(window_sec=5, packet_threshold=50)
        detector = DosDetector(config)

        src_ip = "172.16.0.200"
        dst_ip = "192.168.1.1"
        timestamp = time.time()

        # Send mix of TCP, UDP, and ICMP packets
        events = []
        protocols = ["TCP", "UDP", "ICMP"]

        for i in range(75):  # Above threshold
            protocol = protocols[i % 3]
            packet = PacketInfo(
                timestamp=timestamp + (i * 0.01),
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=12345 if protocol != "ICMP" else None,
                dst_port=80 if protocol != "ICMP" else None,
                tcp_flags="S" if protocol == "TCP" else None,
                length=60,
            )
            events.extend(detector.process_packet(packet))

        # Should detect DoS
        assert len(events) >= 1
        assert events[0].type == "DOS"


class TestThreatAnalyzer:
    """Test integrated threat analyzer."""

    def test_analyzer_initialization(self):
        """Test threat analyzer initialization."""
        config = DetectionConfig()
        analyzer = ThreatAnalyzer(config)

        assert analyzer.packet_count == 0
        assert analyzer.event_count == 0
        assert analyzer.portscan_detector is not None
        assert analyzer.bruteforce_detector is not None
        assert analyzer.dos_detector is not None

    def test_analyzer_processes_all_detectors(self):
        """Test that analyzer runs all detectors."""
        config = DetectionConfig()
        config.portscan.unique_ports_threshold = 2
        config.bruteforce.fail_threshold = 2
        config.dos.packet_threshold = 5

        analyzer = ThreatAnalyzer(config)

        # Create packet that could trigger multiple detectors
        packet = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            protocol="TCP",
            src_port=12345,
            dst_port=22,
            tcp_flags="RST",
            length=60,
        )

        # Process multiple similar packets
        all_events = []
        for i in range(10):
            packet.dst_port = 80 + i  # Different ports for port scan
            packet.timestamp = time.time() + i * 0.1
            events = analyzer.process_packet(packet)
            all_events.extend(events)

        # Should have processed packets and potentially detected events
        assert analyzer.packet_count == 10
        assert analyzer.event_count == len(all_events)

    def test_analyzer_stats(self):
        """Test analyzer statistics."""
        config = DetectionConfig()
        analyzer = ThreatAnalyzer(config)

        # Process some packets
        packet = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            protocol="TCP",
            src_port=12345,
            dst_port=80,
            tcp_flags="S",
            length=60,
        )

        analyzer.process_packet(packet)
        analyzer.process_packet(packet)

        stats = analyzer.get_stats()
        assert stats["packet_count"] == 2
        assert "duration_sec" in stats
        assert "packets_per_sec" in stats
        assert "portscan_stats" in stats
        assert "bruteforce_stats" in stats
        assert "dos_stats" in stats

    def test_analyzer_reset_stats(self):
        """Test analyzer statistics reset."""
        config = DetectionConfig()
        analyzer = ThreatAnalyzer(config)

        # Process some packets
        packet = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            protocol="TCP",
            src_port=12345,
            dst_port=80,
            tcp_flags="S",
            length=60,
        )

        analyzer.process_packet(packet)
        assert analyzer.packet_count == 1

        # Reset stats
        analyzer.reset_stats()
        assert analyzer.packet_count == 0
        assert analyzer.event_count == 0

    def test_analyzer_cleanup(self):
        """Test analyzer cleanup."""
        config = DetectionConfig()
        analyzer = ThreatAnalyzer(config)

        # Process some packets to populate state
        packet = PacketInfo(
            timestamp=time.time(),
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            protocol="TCP",
            src_port=12345,
            dst_port=80,
            tcp_flags="S",
            length=60,
        )

        analyzer.process_packet(packet)

        # Cleanup should not raise errors
        analyzer.cleanup()

    def test_analyzer_error_handling(self):
        """Test analyzer error handling with invalid packet."""
        config = DetectionConfig()
        analyzer = ThreatAnalyzer(config)

        # Create packet with missing required fields
        packet = PacketInfo(
            timestamp=time.time(),
            src_ip="",  # Invalid IP
            dst_ip="192.168.1.1",
            protocol="TCP",
            length=60,
        )

        # Should handle error gracefully
        events = analyzer.process_packet(packet)
        assert isinstance(events, list)  # Should return empty list, not crash
