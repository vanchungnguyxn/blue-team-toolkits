"""Command-line interface for Blue Team Toolkit."""

import logging
import signal
import time
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .alerts import AlertManager
from .analyze import ThreatAnalyzer
from .capture import PacketCapture
from .config import (
    Config,
    create_default_config,
    load_config,
    setup_logging,
    validate_config,
)
from .geoip import init_geoip
from .storage import Event, get_db_manager, init_db, query_events
from .utils import format_bytes, format_duration

# Initialize Typer app and Rich console
app = typer.Typer(
    name="bluetool",
    help="Blue Team Toolkit - Defensive Security Monitor",
    add_completion=False,
)
console = Console()

# Global variables for signal handling
capture = None
analyzer = None
alert_manager = None
running = False


def signal_handler(signum, frame):
    """Handle interrupt signals gracefully."""
    global running, capture
    console.print(
        "\n[yellow]Received interrupt signal. Shutting down gracefully...[/yellow]"
    )
    running = False
    if capture:
        capture.stop()


def version_callback(value: bool):
    """Show version information."""
    if value:
        console.print(f"Blue Team Toolkit v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool | None = typer.Option(
        None, "--version", "-v", callback=version_callback, help="Show version and exit"
    ),
):
    """Blue Team Toolkit - Defensive Security Monitor for Home/Lab Networks."""
    pass


@app.command()
def init(
    config_path: str = typer.Option(
        "config.yaml", "--config", "-c", help="Configuration file path"
    ),
    db_path: str = typer.Option(
        "bluetool.db", "--database", "-d", help="Database file path"
    ),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite existing files"),
):
    """Initialize configuration file and database schema."""
    console.print("[bold blue]Blue Team Toolkit Initialization[/bold blue]")

    config_file = Path(config_path)

    # Check if config already exists
    if config_file.exists() and not force:
        console.print(
            f"[yellow]Configuration file already exists: {config_path}[/yellow]"
        )
        console.print("Use --force to overwrite")
        raise typer.Exit(1)

    try:
        # Create default configuration
        console.print(f"Creating configuration file: {config_path}")
        config_file.parent.mkdir(parents=True, exist_ok=True)

        default_config = create_default_config()
        default_config["persistence"]["db_path"] = db_path

        with open(config_file, "w") as f:
            import yaml

            yaml.dump(default_config, f, default_flow_style=False, indent=2)

        console.print("[green]✓[/green] Configuration file created")

        # Initialize database
        console.print(f"Initializing database: {db_path}")
        init_db(db_path)
        console.print("[green]✓[/green] Database initialized")

        console.print("\n[bold green]Initialization complete![/bold green]")
        console.print(f"Edit {config_path} to customize your settings")
        console.print(
            f"Run 'bluetool start --config {config_path}' to begin monitoring"
        )

    except Exception as e:
        console.print(f"[red]Error during initialization: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def start(
    config_path: str = typer.Option(
        "config.yaml", "--config", "-c", help="Configuration file path"
    ),
    interface: str | None = typer.Option(
        None, "--interface", "-i", help="Network interface (overrides config)"
    ),
    offline: str | None = typer.Option(
        None, "--offline", "-o", help="Offline mode with PCAP file"
    ),
):
    """Start packet capture and threat detection."""
    global capture, analyzer, alert_manager, running

    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    try:
        # Load configuration
        console.print("[bold blue]Loading configuration...[/bold blue]")
        config = load_config(config_path)

        # Validate configuration
        errors = validate_config(config)
        if errors:
            console.print("[red]Configuration validation failed:[/red]")
            for error in errors:
                console.print(f"  • {error}")
            raise typer.Exit(1)

        # Setup logging
        setup_logging(config.logging)
        logger = logging.getLogger(__name__)

        # Override interface if provided
        if interface:
            config.interface = interface

        # Override offline mode if provided
        if offline:
            config.capture.offline = True
            offline_file = offline
        else:
            offline_file = None

        # Initialize components
        console.print("Initializing components...")

        # Database
        init_db(config.persistence.db_path)

        # GeoIP
        init_geoip()

        # Analyzer
        analyzer = ThreatAnalyzer(config.detection)

        # Alert manager
        alert_manager = AlertManager(config.alerts)

        # Packet capture
        capture = PacketCapture()

        console.print("[green]✓[/green] Components initialized")

        # Display configuration summary
        _display_config_summary(config, alert_manager)

        # Start monitoring
        running = True
        packet_count = 0
        event_count = 0
        start_time = time.time()

        def packet_callback(packet_info):
            nonlocal packet_count, event_count
            packet_count += 1

            # Analyze packet for threats
            events = analyzer.process_packet(packet_info)
            event_count += len(events)

            # Store and alert on events
            for event in events:
                try:
                    # Store in database
                    get_db_manager().insert_event(event)

                    # Send alerts
                    if alert_manager.is_enabled():
                        alert_manager.send_alert(event)

                    # Display event
                    _display_event(event)

                except Exception as e:
                    logger.error(f"Error processing event: {e}")

        # Create live display
        layout = Layout()
        layout.split_row(Layout(name="left", ratio=2), Layout(name="right", ratio=1))

        with Live(layout, console=console, refresh_per_second=1) as live:
            # Update display function
            def update_display():
                duration = time.time() - start_time
                pps = packet_count / duration if duration > 0 else 0

                # Left panel - Statistics
                stats_table = Table(title="Live Statistics")
                stats_table.add_column("Metric", style="cyan")
                stats_table.add_column("Value", style="green")

                stats_table.add_row("Runtime", format_duration(duration))
                stats_table.add_row("Packets", f"{packet_count:,}")
                stats_table.add_row("Events", f"{event_count:,}")
                stats_table.add_row("Rate", f"{pps:.1f} pps")

                layout["left"].update(Panel(stats_table, title="Monitor Status"))

                # Right panel - Recent events
                recent_events = query_events(limit=5)
                events_table = Table(title="Recent Events")
                events_table.add_column("Type", style="red")
                events_table.add_column("Source", style="yellow")
                events_table.add_column("Count", style="green")

                for event in recent_events:
                    events_table.add_row(event.type, event.src_ip, str(event.count))

                layout["right"].update(Panel(events_table, title="Events"))

            # Start capture
            try:
                if config.capture.offline and offline_file:
                    console.print(
                        f"[yellow]Starting offline analysis: {offline_file}[/yellow]"
                    )

                    # Update display periodically during offline processing
                    import threading

                    def display_updater():
                        while running:
                            update_display()
                            time.sleep(1)

                    display_thread = threading.Thread(
                        target=display_updater, daemon=True
                    )
                    display_thread.start()

                    capture.start_offline_capture(
                        offline_file, packet_callback, config.capture.bpf
                    )
                else:
                    console.print(
                        f"[yellow]Starting live capture on: {config.interface}[/yellow]"
                    )
                    console.print("Press Ctrl+C to stop")

                    # Update display periodically during live capture
                    import threading

                    def display_updater():
                        while running:
                            update_display()
                            time.sleep(1)

                    display_thread = threading.Thread(
                        target=display_updater, daemon=True
                    )
                    display_thread.start()

                    capture.start_live_capture(
                        config.interface,
                        config.capture.bpf,
                        packet_callback,
                        config.capture.promisc,
                    )

            except KeyboardInterrupt:
                pass
            except Exception as e:
                console.print(f"[red]Capture error: {e}[/red]")
                raise typer.Exit(1)

        # Display final summary
        duration = time.time() - start_time
        _display_summary(packet_count, event_count, duration)

    except FileNotFoundError as e:
        console.print(f"[red]Configuration file not found: {e}[/red]")
        console.print("Run 'bluetool init' to create a default configuration")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def show(
    what: str = typer.Argument(..., help="What to show: 'events'"),
    limit: int = typer.Option(50, "--limit", "-l", help="Maximum number of events"),
    event_type: list[str] | None = typer.Option(
        None, "--type", "-t", help="Filter by event type"
    ),
    src_ip: str | None = typer.Option(
        None, "--src-ip", "-s", help="Filter by source IP"
    ),
    config_path: str = typer.Option(
        "config.yaml", "--config", "-c", help="Configuration file path"
    ),
):
    """Show events or statistics."""
    if what.lower() != "events":
        console.print(f"[red]Unknown show target: {what}[/red]")
        console.print("Available targets: events")
        raise typer.Exit(1)

    try:
        # Load configuration to get database path
        config = load_config(config_path)
        init_db(config.persistence.db_path)

        # Query events
        events = query_events(event_types=event_type, src_ip=src_ip, limit=limit)

        if not events:
            console.print("[yellow]No events found[/yellow]")
            return

        # Display events in table
        table = Table(title=f"Security Events (showing {len(events)} of {limit} max)")
        table.add_column("Time", style="cyan")
        table.add_column("Type", style="red")
        table.add_column("Source IP", style="yellow")
        table.add_column("Dest IP", style="blue")
        table.add_column("Count", style="green")
        table.add_column("Details", style="white")

        for event in events:
            timestamp = datetime.fromtimestamp(event.timestamp)
            time_str = timestamp.strftime("%m-%d %H:%M:%S")

            table.add_row(
                time_str,
                event.type,
                event.src_ip,
                event.dst_ip or "-",
                str(event.count),
                (
                    event.details[:50] + "..."
                    if len(event.details) > 50
                    else event.details
                ),
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def status(
    config_path: str = typer.Option(
        "config.yaml", "--config", "-c", help="Configuration file path"
    ),
):
    """Show current system status and statistics."""
    try:
        # Load configuration
        config = load_config(config_path)
        init_db(config.persistence.db_path)

        # Get database info
        db_info = get_db_manager().get_database_info()

        # Get event statistics
        event_stats = get_db_manager().get_event_stats()

        # Display status
        console.print("[bold blue]Blue Team Toolkit Status[/bold blue]\n")

        # Database status
        db_table = Table(title="Database Status")
        db_table.add_column("Property", style="cyan")
        db_table.add_column("Value", style="green")

        db_table.add_row("Database Path", str(db_info["path"]))
        db_table.add_row("Database Size", format_bytes(db_info["size_bytes"]))
        db_table.add_row("Total Events", f"{db_info['total_events']:,}")
        db_table.add_row("Schema Version", db_info["schema_version"] or "Unknown")

        console.print(db_table)
        console.print()

        # Event statistics
        if event_stats:
            events_table = Table(title="Event Statistics")
            events_table.add_column("Event Type", style="red")
            events_table.add_column("Count", style="green")
            events_table.add_column("First Seen", style="cyan")
            events_table.add_column("Last Seen", style="cyan")

            for event_type, stats in event_stats.items():
                first_seen = datetime.fromtimestamp(stats["first_seen"])
                last_seen = datetime.fromtimestamp(stats["last_seen"])

                events_table.add_row(
                    event_type,
                    f"{stats['count']:,}",
                    first_seen.strftime("%Y-%m-%d %H:%M"),
                    last_seen.strftime("%Y-%m-%d %H:%M"),
                )

            console.print(events_table)
        else:
            console.print("[yellow]No events recorded yet[/yellow]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def config(
    action: str = typer.Argument(..., help="Action: 'validate'"),
    config_path: str = typer.Option(
        "config.yaml", "--config", "-c", help="Configuration file path"
    ),
):
    """Configuration management."""
    if action.lower() != "validate":
        console.print(f"[red]Unknown config action: {action}[/red]")
        console.print("Available actions: validate")
        raise typer.Exit(1)

    try:
        console.print(f"[bold blue]Validating configuration: {config_path}[/bold blue]")

        # Load and validate configuration
        config_obj = load_config(config_path)
        errors = validate_config(config_obj)

        if errors:
            console.print("[red]Configuration validation failed:[/red]")
            for error in errors:
                console.print(f"  • {error}")
            raise typer.Exit(1)
        else:
            console.print("[green]✓ Configuration is valid[/green]")

            # Display configuration summary
            console.print("\n[bold]Configuration Summary:[/bold]")
            console.print(f"Interface: {config_obj.interface}")
            console.print(f"BPF Filter: {config_obj.capture.bpf}")
            console.print(f"Database: {config_obj.persistence.db_path}")
            console.print(f"Log Level: {config_obj.logging.level}")

            # Alert channels
            alert_channels = []
            if config_obj.alerts.slack_webhook:
                alert_channels.append("Slack")
            if config_obj.alerts.telegram.bot_token:
                alert_channels.append("Telegram")

            if alert_channels:
                console.print(f"Alert Channels: {', '.join(alert_channels)}")
            else:
                console.print("Alert Channels: None configured")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def demo():
    """Run demo using sample PCAP file."""
    console.print("[bold blue]Blue Team Toolkit Demo[/bold blue]")

    # Check if demo PCAP exists
    demo_pcap = Path(__file__).parent / "demo" / "demo.pcap"

    if not demo_pcap.exists():
        console.print(
            "[yellow]Demo PCAP file not found. Creating synthetic demo...[/yellow]"
        )
        _create_demo_events()
        return

    try:
        # Create temporary config for demo
        demo_config = Config()
        demo_config.capture.offline = True
        demo_config.persistence.db_path = ":memory:"  # In-memory database

        # Initialize components
        init_db(":memory:")
        analyzer = ThreatAnalyzer(demo_config.detection)
        capture = PacketCapture()

        console.print(f"[yellow]Analyzing demo PCAP: {demo_pcap}[/yellow]")

        events_found = []

        def demo_callback(packet_info):
            events = analyzer.process_packet(packet_info)
            events_found.extend(events)

            for event in events:
                _display_event(event)

        # Process demo PCAP
        capture.start_offline_capture(str(demo_pcap), demo_callback)

        # Display summary
        console.print("\n[bold green]Demo completed![/bold green]")
        console.print(f"Found {len(events_found)} security events")

        if events_found:
            # Group by type
            event_types = {}
            for event in events_found:
                event_types[event.type] = event_types.get(event.type, 0) + 1

            for event_type, count in event_types.items():
                console.print(f"  {event_type}: {count}")

    except Exception as e:
        console.print(f"[red]Demo error: {e}[/red]")
        console.print("Creating synthetic demo instead...")
        _create_demo_events()


def _display_config_summary(config: Config, alert_manager: AlertManager):
    """Display configuration summary."""
    table = Table(title="Configuration Summary")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Interface", config.interface)
    table.add_row("BPF Filter", config.capture.bpf)
    table.add_row("Database", config.persistence.db_path)
    table.add_row("Mode", "Offline" if config.capture.offline else "Live")

    # Alert channels
    channels = alert_manager.get_enabled_channels()
    table.add_row("Alert Channels", ", ".join(channels) if channels else "None")

    console.print(table)
    console.print()


def _display_event(event: Event):
    """Display a security event."""
    timestamp = datetime.fromtimestamp(event.timestamp)
    time_str = timestamp.strftime("%H:%M:%S")

    # Choose color based on event type
    colors = {
        "PORTSCAN": "yellow",
        "BRUTEFORCE": "red",
        "DOS": "red",
    }
    color = colors.get(event.type, "white")

    console.print(
        f"[{color}]{time_str} {event.type}[/{color}] "
        f"from {event.src_ip} (count: {event.count}) - {event.details}"
    )


def _display_summary(packet_count: int, event_count: int, duration: float):
    """Display final summary."""
    console.print("\n[bold blue]Session Summary[/bold blue]")

    table = Table()
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("Duration", format_duration(duration))
    table.add_row("Packets Processed", f"{packet_count:,}")
    table.add_row("Events Detected", f"{event_count:,}")

    if duration > 0:
        table.add_row("Average Rate", f"{packet_count/duration:.1f} packets/sec")

    console.print(table)


def _create_demo_events():
    """Create synthetic demo events for demonstration."""
    console.print("[yellow]Creating synthetic demo events...[/yellow]")

    # Create some fake events
    demo_events = [
        Event.create(
            "PORTSCAN",
            "192.168.1.100",
            25,
            "Scanned ports: [22, 23, 80, 443, 3389] (and 20 more)",
        ),
        Event.create("BRUTEFORCE", "10.0.0.50", 15, "Service: ssh, Port: 22"),
        Event.create("DOS", "172.16.0.200", 750, "Protocol: TCP"),
    ]

    console.print("\n[bold]Demo Events:[/bold]")
    for event in demo_events:
        _display_event(event)

    console.print("\n[bold green]Demo completed![/bold green]")
    console.print("These are synthetic events for demonstration purposes.")
    console.print(
        "Run 'bluetool start' with real network traffic for actual monitoring."
    )


if __name__ == "__main__":
    app()
