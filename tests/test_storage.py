"""Tests for database storage and event management."""

import os
import tempfile
import time
import pytest
from pathlib import Path

from bluetool.storage import (
    Event,
    DatabaseManager,
    init_db,
    get_db_manager,
    insert_event,
    query_events,
    cleanup_old_events,
)


class TestEvent:
    """Test Event data class."""

    def test_event_creation(self):
        """Test creating an event."""
        event = Event.create(
            event_type="PORTSCAN",
            src_ip="192.168.1.100",
            count=25,
            details="Scanned ports: [22, 80, 443]",
            dst_ip="192.168.1.1",
        )

        assert event.type == "PORTSCAN"
        assert event.src_ip == "192.168.1.100"
        assert event.dst_ip == "192.168.1.1"
        assert event.count == 25
        assert event.details == "Scanned ports: [22, 80, 443]"
        assert event.id is not None
        assert len(event.id) > 0
        assert event.timestamp > 0

    def test_event_creation_defaults(self):
        """Test creating an event with defaults."""
        event = Event.create(event_type="DOS", src_ip="10.0.0.1", count=500)

        assert event.type == "DOS"
        assert event.src_ip == "10.0.0.1"
        assert event.dst_ip is None
        assert event.count == 500
        assert event.details == ""
        assert event.timestamp is not None

    def test_event_type_normalization(self):
        """Test that event types are normalized to uppercase."""
        event = Event.create("portscan", "192.168.1.1", 10)
        assert event.type == "PORTSCAN"

    def test_event_to_dict(self):
        """Test converting event to dictionary."""
        event = Event.create(
            "BRUTEFORCE", "10.0.0.50", 15, "Service: ssh", "192.168.1.10"
        )

        event_dict = event.to_dict()

        assert event_dict["type"] == "BRUTEFORCE"
        assert event_dict["src_ip"] == "10.0.0.50"
        assert event_dict["dst_ip"] == "192.168.1.10"
        assert event_dict["count"] == 15
        assert event_dict["details"] == "Service: ssh"
        assert "id" in event_dict
        assert "timestamp" in event_dict

    def test_event_from_dict(self):
        """Test creating event from dictionary."""
        event_data = {
            "id": "test-id-123",
            "type": "PORTSCAN",
            "src_ip": "192.168.1.100",
            "dst_ip": "192.168.1.1",
            "count": 20,
            "details": "Test details",
            "timestamp": 1234567890.0,
        }

        event = Event.from_dict(event_data)

        assert event.id == "test-id-123"
        assert event.type == "PORTSCAN"
        assert event.src_ip == "192.168.1.100"
        assert event.dst_ip == "192.168.1.1"
        assert event.count == 20
        assert event.details == "Test details"
        assert event.timestamp == 1234567890.0

    def test_event_custom_timestamp(self):
        """Test creating event with custom timestamp."""
        custom_timestamp = 1234567890.0
        event = Event.create("DOS", "10.0.0.1", 100, timestamp=custom_timestamp)

        assert event.timestamp == custom_timestamp


class TestDatabaseManager:
    """Test DatabaseManager functionality."""

    def test_database_initialization(self):
        """Test database initialization."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            db_manager = DatabaseManager(db_path)
            db_manager.init_db()

            # Check that database file was created
            assert Path(db_path).exists()

            # Check database info
            info = db_manager.get_database_info()
            assert info["exists"] is True
            assert info["total_events"] == 0
            assert info["schema_version"] == "1"

        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)

    def test_database_directory_creation(self):
        """Test that database directory is created if it doesn't exist."""
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "subdir" / "test.db"

            db_manager = DatabaseManager(str(db_path))
            db_manager.init_db()

            assert db_path.exists()

    def test_insert_and_query_events(self):
        """Test inserting and querying events."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            db_manager = DatabaseManager(db_path)
            db_manager.init_db()

            # Create and insert events
            event1 = Event.create("PORTSCAN", "192.168.1.100", 25, "Test scan")
            event2 = Event.create("BRUTEFORCE", "10.0.0.50", 15, "SSH brute force")
            event3 = Event.create("DOS", "172.16.0.200", 500, "High traffic")

            db_manager.insert_event(event1)
            db_manager.insert_event(event2)
            db_manager.insert_event(event3)

            # Query all events
            events = db_manager.query_events()
            assert len(events) == 3

            # Events should be returned in reverse chronological order
            assert events[0].id == event3.id  # Most recent first

            # Query by type
            portscan_events = db_manager.query_events(event_types=["PORTSCAN"])
            assert len(portscan_events) == 1
            assert portscan_events[0].type == "PORTSCAN"

            # Query by source IP
            ip_events = db_manager.query_events(src_ip="10.0.0.50")
            assert len(ip_events) == 1
            assert ip_events[0].src_ip == "10.0.0.50"

            # Query with limit
            limited_events = db_manager.query_events(limit=2)
            assert len(limited_events) == 2

        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)

    def test_query_events_time_range(self):
        """Test querying events within time range."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            db_manager = DatabaseManager(db_path)
            db_manager.init_db()

            # Create events with different timestamps
            now = time.time()
            event1 = Event.create(
                "PORTSCAN", "192.168.1.100", 25, timestamp=now - 3600
            )  # 1 hour ago
            event2 = Event.create(
                "BRUTEFORCE", "10.0.0.50", 15, timestamp=now - 1800
            )  # 30 min ago
            event3 = Event.create("DOS", "172.16.0.200", 500, timestamp=now)  # Now

            db_manager.insert_event(event1)
            db_manager.insert_event(event2)
            db_manager.insert_event(event3)

            # Query events from last 45 minutes
            start_time = now - 2700  # 45 minutes ago
            recent_events = db_manager.query_events(start_time=start_time)

            assert len(recent_events) == 2  # Should exclude event1
            event_ids = {event.id for event in recent_events}
            assert event2.id in event_ids
            assert event3.id in event_ids
            assert event1.id not in event_ids

        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)

    def test_get_event_stats(self):
        """Test getting event statistics."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            db_manager = DatabaseManager(db_path)
            db_manager.init_db()

            # Insert multiple events of different types
            events = [
                Event.create("PORTSCAN", "192.168.1.100", 25),
                Event.create("PORTSCAN", "192.168.1.101", 30),
                Event.create("BRUTEFORCE", "10.0.0.50", 15),
                Event.create("DOS", "172.16.0.200", 500),
            ]

            for event in events:
                db_manager.insert_event(event)

            stats = db_manager.get_event_stats()

            assert "PORTSCAN" in stats
            assert "BRUTEFORCE" in stats
            assert "DOS" in stats

            assert stats["PORTSCAN"]["count"] == 2
            assert stats["BRUTEFORCE"]["count"] == 1
            assert stats["DOS"]["count"] == 1

            # Check that timestamps are included
            assert "first_seen" in stats["PORTSCAN"]
            assert "last_seen" in stats["PORTSCAN"]

        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)

    def test_cleanup_old_events(self):
        """Test cleaning up old events."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            db_manager = DatabaseManager(db_path)
            db_manager.init_db()

            # Create events with different ages
            now = time.time()
            old_event = Event.create(
                "PORTSCAN", "192.168.1.100", 25, timestamp=now - 86400 * 35
            )  # 35 days ago
            recent_event = Event.create(
                "BRUTEFORCE", "10.0.0.50", 15, timestamp=now - 86400 * 5
            )  # 5 days ago

            db_manager.insert_event(old_event)
            db_manager.insert_event(recent_event)

            # Cleanup events older than 30 days
            deleted_count = db_manager.cleanup_old_events(days=30)

            assert deleted_count == 1

            # Verify only recent event remains
            remaining_events = db_manager.query_events()
            assert len(remaining_events) == 1
            assert remaining_events[0].id == recent_event.id

        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)

    def test_database_vacuum(self):
        """Test database vacuum operation."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            db_manager = DatabaseManager(db_path)
            db_manager.init_db()

            # Add some events
            event = Event.create("PORTSCAN", "192.168.1.100", 25)
            db_manager.insert_event(event)

            # Vacuum should not raise errors
            db_manager.vacuum_database()

            # Database should still be functional
            events = db_manager.query_events()
            assert len(events) == 1

        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)


class TestGlobalDatabaseFunctions:
    """Test global database functions."""

    def test_init_and_use_global_db(self):
        """Test initializing and using global database."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            # Initialize global database
            init_db(db_path)

            # Get database manager
            db_manager = get_db_manager()
            assert db_manager is not None

            # Test global insert and query functions
            event = Event.create("PORTSCAN", "192.168.1.100", 25)
            insert_event(event)

            events = query_events()
            assert len(events) == 1
            assert events[0].id == event.id

        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)

    def test_get_db_manager_not_initialized(self):
        """Test getting database manager when not initialized."""
        # Reset global database manager
        import bluetool.storage

        bluetool.storage._db_manager = None

        with pytest.raises(RuntimeError, match="Database not initialized"):
            get_db_manager()

    def test_global_cleanup_function(self):
        """Test global cleanup function."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            init_db(db_path)

            # Insert old and new events
            now = time.time()
            old_event = Event.create(
                "PORTSCAN", "192.168.1.100", 25, timestamp=now - 86400 * 35
            )
            new_event = Event.create("BRUTEFORCE", "10.0.0.50", 15, timestamp=now)

            insert_event(old_event)
            insert_event(new_event)

            # Cleanup old events
            deleted_count = cleanup_old_events(days=30)
            assert deleted_count == 1

            # Verify only new event remains
            events = query_events()
            assert len(events) == 1
            assert events[0].id == new_event.id

        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)

    def test_query_events_with_filters(self):
        """Test querying events with various filters."""
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            db_path = f.name

        try:
            init_db(db_path)

            # Insert test events
            events = [
                Event.create("PORTSCAN", "192.168.1.100", 25, "Scan details"),
                Event.create("PORTSCAN", "192.168.1.101", 30, "Another scan"),
                Event.create("BRUTEFORCE", "10.0.0.50", 15, "SSH attack"),
                Event.create("DOS", "172.16.0.200", 500, "High traffic"),
            ]

            for event in events:
                insert_event(event)

            # Test multiple event type filter
            portscan_events = query_events(event_types=["PORTSCAN", "DOS"])
            assert len(portscan_events) == 3  # 2 PORTSCAN + 1 DOS

            # Test source IP filter
            ip_events = query_events(src_ip="192.168.1.100")
            assert len(ip_events) == 1
            assert ip_events[0].src_ip == "192.168.1.100"

            # Test limit and offset
            limited_events = query_events(limit=2, offset=1)
            assert len(limited_events) == 2

        finally:
            if os.path.exists(db_path):
                os.unlink(db_path)
