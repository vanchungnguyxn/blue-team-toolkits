"""Packet capture functionality for Blue Team Toolkit."""

import logging
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import scapy.all as scapy

    SCAPY_AVAILABLE = True
except ImportError:
    logger.warning("Scapy not available - packet capture disabled")
    SCAPY_AVAILABLE = False


class PacketInfo:
    """Extracted packet information."""

    def __init__(
        self,
        timestamp: float,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: int | None = None,
        dst_port: int | None = None,
        tcp_flags: str | None = None,
        length: int = 0,
        raw_packet: Any | None = None,
    ):
        """Initialize packet info.

        Args:
            timestamp: Packet timestamp.
            src_ip: Source IP address.
            dst_ip: Destination IP address.
            protocol: Protocol (TCP, UDP, ICMP).
            src_port: Source port (if applicable).
            dst_port: Destination port (if applicable).
            tcp_flags: TCP flags string (if TCP).
            length: Packet length in bytes.
            raw_packet: Original scapy packet object.
        """
        self.timestamp = timestamp
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.src_port = src_port
        self.dst_port = dst_port
        self.tcp_flags = tcp_flags
        self.length = length
        self.raw_packet = raw_packet

    def __repr__(self) -> str:
        """String representation of packet info."""
        port_info = ""
        if self.src_port and self.dst_port:
            port_info = f":{self.src_port} -> :{self.dst_port}"

        return (
            f"PacketInfo({self.protocol} {self.src_ip}{port_info} -> "
            f"{self.dst_ip}, {self.length}B)"
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert packet info to dictionary.

        Returns:
            Packet info as dictionary.
        """
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "protocol": self.protocol,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "tcp_flags": self.tcp_flags,
            "length": self.length,
        }


class PacketCapture:
    """Packet capture manager."""

    def __init__(self):
        """Initialize packet capture."""
        self.is_running = False
        self.packet_count = 0
        self.start_time = 0.0
        self._stop_event = threading.Event()

    def _extract_packet_info(self, packet: Any) -> PacketInfo | None:
        """Extract relevant information from scapy packet.

        Args:
            packet: Scapy packet object.

        Returns:
            PacketInfo object or None if packet cannot be processed.
        """
        if not SCAPY_AVAILABLE:
            return None

        try:
            timestamp = float(packet.time) if hasattr(packet, "time") else time.time()
            length = len(packet)

            # Extract IP layer
            if packet.haslayer(scapy.IP):
                ip_layer = packet[scapy.IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
            elif packet.haslayer(scapy.IPv6):
                ip_layer = packet[scapy.IPv6]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
            else:
                # No IP layer, skip packet
                return None

            # Extract transport layer info
            src_port = dst_port = None
            protocol = "UNKNOWN"
            tcp_flags = None

            if packet.haslayer(scapy.TCP):
                tcp_layer = packet[scapy.TCP]
                protocol = "TCP"
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport

                # Extract TCP flags
                flags = []
                if tcp_layer.flags.F:
                    flags.append("FIN")
                if tcp_layer.flags.S:
                    flags.append("SYN")
                if tcp_layer.flags.R:
                    flags.append("RST")
                if tcp_layer.flags.P:
                    flags.append("PSH")
                if tcp_layer.flags.A:
                    flags.append("ACK")
                if tcp_layer.flags.U:
                    flags.append("URG")
                tcp_flags = "|".join(flags) if flags else ""

            elif packet.haslayer(scapy.UDP):
                udp_layer = packet[scapy.UDP]
                protocol = "UDP"
                src_port = udp_layer.sport
                dst_port = udp_layer.dport

            elif packet.haslayer(scapy.ICMP):
                protocol = "ICMP"

            return PacketInfo(
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                tcp_flags=tcp_flags,
                length=length,
                raw_packet=packet,
            )

        except Exception as e:
            logger.debug(f"Failed to extract packet info: {e}")
            return None

    def start_live_capture(
        self,
        interface: str,
        bpf_filter: str,
        callback: Callable[[PacketInfo], None],
        promisc: bool = True,
    ) -> None:
        """Start live packet capture.

        Args:
            interface: Network interface to capture on.
            bpf_filter: BPF filter string.
            callback: Callback function for each packet.
            promisc: Enable promiscuous mode.

        Raises:
            RuntimeError: If scapy is not available or capture fails.
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available for packet capture")

        logger.info(f"Starting live capture on interface: {interface}")
        logger.info(f"BPF filter: {bpf_filter}")

        self.is_running = True
        self.packet_count = 0
        self.start_time = time.time()
        self._stop_event.clear()

        def packet_handler(packet):
            if self._stop_event.is_set():
                return

            self.packet_count += 1
            packet_info = self._extract_packet_info(packet)

            if packet_info:
                try:
                    callback(packet_info)
                except Exception as e:
                    logger.error(f"Error in packet callback: {e}")

        try:
            # Auto-select interface if needed
            if interface == "auto":
                from .utils import auto_select_interface

                interface = auto_select_interface()
                if not interface:
                    raise RuntimeError("Could not auto-select network interface")
                logger.info(f"Auto-selected interface: {interface}")

            # Start packet capture
            scapy.sniff(
                iface=interface,
                filter=bpf_filter,
                prn=packet_handler,
                store=False,
                stop_filter=lambda x: self._stop_event.is_set(),
                promisc=promisc,
            )

        except KeyboardInterrupt:
            logger.info("Capture interrupted by user")
        except Exception as e:
            logger.error(f"Capture error: {e}")
            raise
        finally:
            self.is_running = False
            duration = time.time() - self.start_time
            logger.info(
                f"Capture stopped. Processed {self.packet_count} packets "
                f"in {duration:.2f} seconds"
            )

    def start_offline_capture(
        self,
        pcap_file: str,
        callback: Callable[[PacketInfo], None],
        bpf_filter: str | None = None,
    ) -> None:
        """Start offline packet capture from PCAP file.

        Args:
            pcap_file: Path to PCAP file.
            callback: Callback function for each packet.
            bpf_filter: Optional BPF filter string.

        Raises:
            RuntimeError: If scapy is not available.
            FileNotFoundError: If PCAP file doesn't exist.
        """
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy not available for packet capture")

        pcap_path = Path(pcap_file)
        if not pcap_path.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

        logger.info(f"Starting offline capture from: {pcap_file}")
        if bpf_filter:
            logger.info(f"BPF filter: {bpf_filter}")

        self.is_running = True
        self.packet_count = 0
        self.start_time = time.time()

        try:
            # Read packets from PCAP file
            packets = scapy.rdpcap(str(pcap_path))
            logger.info(f"Loaded {len(packets)} packets from PCAP file")

            # Apply BPF filter if specified
            if bpf_filter:
                # Note: BPF filtering on offline packets is limited
                logger.warning("BPF filtering on offline PCAP files may be limited")

            # Process each packet
            for packet in packets:
                if self._stop_event.is_set():
                    break

                self.packet_count += 1
                packet_info = self._extract_packet_info(packet)

                if packet_info:
                    try:
                        callback(packet_info)
                    except Exception as e:
                        logger.error(f"Error in packet callback: {e}")

        except KeyboardInterrupt:
            logger.info("Offline capture interrupted by user")
        except Exception as e:
            logger.error(f"Offline capture error: {e}")
            raise
        finally:
            self.is_running = False
            duration = time.time() - self.start_time
            logger.info(
                f"Offline capture completed. Processed {self.packet_count} packets "
                f"in {duration:.2f} seconds"
            )

    def stop(self) -> None:
        """Stop packet capture."""
        if self.is_running:
            logger.info("Stopping packet capture...")
            self._stop_event.set()
            self.is_running = False

    def get_stats(self) -> dict[str, Any]:
        """Get capture statistics.

        Returns:
            Dictionary with capture statistics.
        """
        duration = time.time() - self.start_time if self.is_running else 0
        pps = self.packet_count / duration if duration > 0 else 0

        return {
            "is_running": self.is_running,
            "packet_count": self.packet_count,
            "duration_sec": duration,
            "packets_per_sec": pps,
        }
