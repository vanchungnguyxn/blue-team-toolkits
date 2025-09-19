"""Database storage and event management for Blue Team Toolkit."""

import logging
import sqlite3
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class Event:
    """Security event data structure."""

    id: str
    type: str  # PORTSCAN, BRUTEFORCE, DOS
    src_ip: str
    dst_ip: str | None
    count: int
    details: str
    timestamp: float

    @classmethod
    def create(
        cls,
        event_type: str,
        src_ip: str,
        count: int,
        details: str = "",
        dst_ip: str | None = None,
        timestamp: float | None = None,
    ) -> "Event":
        """Create a new event with auto-generated ID and timestamp.

        Args:
            event_type: Type of event (PORTSCAN, BRUTEFORCE, DOS).
            src_ip: Source IP address.
            count: Count of suspicious activity.
            details: Additional event details.
            dst_ip: Destination IP address (optional).
            timestamp: Event timestamp (default: current time).

        Returns:
            New Event instance.
        """
        return cls(
            id=str(uuid.uuid4()),
            type=event_type.upper(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            count=count,
            details=details,
            timestamp=timestamp or time.time(),
        )

    def to_dict(self) -> dict[str, Any]:
        """Convert event to dictionary.

        Returns:
            Event as dictionary.
        """
        return {
            "id": self.id,
            "type": self.type,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "count": self.count,
            "details": self.details,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Event":
        """Create event from dictionary.

        Args:
            data: Event data dictionary.

        Returns:
            Event instance.
        """
        return cls(
            id=data["id"],
            type=data["type"],
            src_ip=data["src_ip"],
            dst_ip=data.get("dst_ip"),
            count=data["count"],
            details=data["details"],
            timestamp=data["timestamp"],
        )


class DatabaseManager:
    """SQLite database manager for Blue Team Toolkit."""

    def __init__(self, db_path: str):
        """Initialize database manager.

        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = Path(db_path)
        self._ensure_db_dir()

    def _ensure_db_dir(self) -> None:
        """Ensure database directory exists."""
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    @contextmanager
    def get_connection(self):
        """Get database connection context manager.

        Yields:
            SQLite connection object.
        """
        conn = None
        try:
            conn = sqlite3.connect(
                self.db_path,
                timeout=30.0,
                isolation_level=None,  # Autocommit mode
            )
            conn.row_factory = sqlite3.Row  # Enable dict-like access
            yield conn
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                conn.close()

    def init_db(self) -> None:
        """Initialize database schema.

        Raises:
            sqlite3.Error: If database initialization fails.
        """
        logger.info(f"Initializing database: {self.db_path}")

        schema_sql = """
        -- Events table
        CREATE TABLE IF NOT EXISTS events (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT,
            count INTEGER NOT NULL DEFAULT 0,
            details TEXT DEFAULT '',
            ts INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Metadata table
        CREATE TABLE IF NOT EXISTS meta (
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        -- Indexes for better query performance
        CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
        CREATE INDEX IF NOT EXISTS idx_events_src_ip ON events(src_ip);
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_created_at ON events(created_at);

        -- Insert initial metadata
        INSERT OR IGNORE INTO meta (k, v) VALUES ('schema_version', '1');
        INSERT OR IGNORE INTO meta (k, v) VALUES ('created_at', datetime('now'));
        """

        with self.get_connection() as conn:
            conn.executescript(schema_sql)
            logger.info("Database schema initialized successfully")

    def insert_event(self, event: Event) -> None:
        """Insert event into database.

        Args:
            event: Event to insert.

        Raises:
            sqlite3.Error: If insertion fails.
        """
        sql = """
        INSERT INTO events (id, type, src_ip, dst_ip, count, details, ts)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """

        with self.get_connection() as conn:
            conn.execute(
                sql,
                (
                    event.id,
                    event.type,
                    event.src_ip,
                    event.dst_ip,
                    event.count,
                    event.details,
                    int(event.timestamp),
                ),
            )
            logger.debug(f"Inserted event: {event.id} ({event.type})")

    def query_events(
        self,
        event_types: list[str] | None = None,
        src_ip: str | None = None,
        limit: int = 100,
        offset: int = 0,
        start_time: float | None = None,
        end_time: float | None = None,
    ) -> list[Event]:
        """Query events from database.

        Args:
            event_types: Filter by event types.
            src_ip: Filter by source IP.
            limit: Maximum number of events to return.
            offset: Number of events to skip.
            start_time: Start timestamp filter.
            end_time: End timestamp filter.

        Returns:
            List of matching events.
        """
        conditions = []
        params = []

        if event_types:
            placeholders = ",".join("?" * len(event_types))
            conditions.append(f"type IN ({placeholders})")
            params.extend(event_types)

        if src_ip:
            conditions.append("src_ip = ?")
            params.append(src_ip)

        if start_time:
            conditions.append("ts >= ?")
            params.append(int(start_time))

        if end_time:
            conditions.append("ts <= ?")
            params.append(int(end_time))

        where_clause = " AND ".join(conditions) if conditions else "1=1"

        sql = f"""
        SELECT id, type, src_ip, dst_ip, count, details, ts
        FROM events
        WHERE {where_clause}
        ORDER BY ts DESC
        LIMIT ? OFFSET ?
        """

        params.extend([limit, offset])

        events = []
        with self.get_connection() as conn:
            cursor = conn.execute(sql, params)
            for row in cursor:
                events.append(
                    Event(
                        id=row["id"],
                        type=row["type"],
                        src_ip=row["src_ip"],
                        dst_ip=row["dst_ip"],
                        count=row["count"],
                        details=row["details"],
                        timestamp=float(row["ts"]),
                    )
                )

        logger.debug(f"Retrieved {len(events)} events")
        return events

    def get_event_stats(self) -> dict[str, int]:
        """Get event statistics.

        Returns:
            Dictionary with event statistics.
        """
        sql = """
        SELECT 
            type,
            COUNT(*) as count,
            MIN(ts) as first_seen,
            MAX(ts) as last_seen
        FROM events
        GROUP BY type
        """

        stats = {}
        with self.get_connection() as conn:
            cursor = conn.execute(sql)
            for row in cursor:
                stats[row["type"]] = {
                    "count": row["count"],
                    "first_seen": row["first_seen"],
                    "last_seen": row["last_seen"],
                }

        return stats

    def cleanup_old_events(self, days: int = 30) -> int:
        """Remove events older than specified days.

        Args:
            days: Number of days to retain events.

        Returns:
            Number of events deleted.
        """
        cutoff_time = int(time.time() - (days * 24 * 3600))

        sql = "DELETE FROM events WHERE ts < ?"

        with self.get_connection() as conn:
            cursor = conn.execute(sql, (cutoff_time,))
            deleted_count = cursor.rowcount

        logger.info(f"Cleaned up {deleted_count} old events (older than {days} days)")
        return deleted_count

    def vacuum_database(self) -> None:
        """Vacuum database to reclaim space.

        This should be called periodically after cleanup operations.
        """
        logger.info("Vacuuming database...")
        with self.get_connection() as conn:
            conn.execute("VACUUM")
        logger.info("Database vacuum completed")

    def get_database_info(self) -> dict[str, Any]:
        """Get database information and statistics.

        Returns:
            Dictionary with database information.
        """
        info = {
            "path": str(self.db_path),
            "exists": self.db_path.exists(),
            "size_bytes": 0,
            "total_events": 0,
            "schema_version": None,
        }

        if self.db_path.exists():
            info["size_bytes"] = self.db_path.stat().st_size

        try:
            with self.get_connection() as conn:
                # Get total events
                cursor = conn.execute("SELECT COUNT(*) FROM events")
                info["total_events"] = cursor.fetchone()[0]

                # Get schema version
                cursor = conn.execute("SELECT v FROM meta WHERE k = 'schema_version'")
                row = cursor.fetchone()
                if row:
                    info["schema_version"] = row[0]

        except sqlite3.Error as e:
            logger.warning(f"Failed to get database info: {e}")

        return info


# Global database manager instance
_db_manager: DatabaseManager | None = None


def init_db(db_path: str = "bluetool.db") -> None:
    """Initialize global database manager.

    Args:
        db_path: Path to SQLite database file.
    """
    global _db_manager
    _db_manager = DatabaseManager(db_path)
    _db_manager.init_db()


def get_db_manager() -> DatabaseManager:
    """Get global database manager instance.

    Returns:
        DatabaseManager instance.

    Raises:
        RuntimeError: If database not initialized.
    """
    if _db_manager is None:
        raise RuntimeError("Database not initialized. Call init_db() first.")
    return _db_manager


def insert_event(event: Event) -> None:
    """Insert event into database.

    Args:
        event: Event to insert.
    """
    get_db_manager().insert_event(event)


def query_events(
    event_types: list[str] | None = None,
    src_ip: str | None = None,
    limit: int = 100,
    offset: int = 0,
    start_time: float | None = None,
    end_time: float | None = None,
) -> list[Event]:
    """Query events from database.

    Args:
        event_types: Filter by event types.
        src_ip: Filter by source IP.
        limit: Maximum number of events to return.
        offset: Number of events to skip.
        start_time: Start timestamp filter.
        end_time: End timestamp filter.

    Returns:
        List of matching events.
    """
    return get_db_manager().query_events(
        event_types=event_types,
        src_ip=src_ip,
        limit=limit,
        offset=offset,
        start_time=start_time,
        end_time=end_time,
    )


def cleanup_old_events(days: int = 30) -> int:
    """Remove events older than specified days.

    Args:
        days: Number of days to retain events.

    Returns:
        Number of events deleted.
    """
    return get_db_manager().cleanup_old_events(days)
