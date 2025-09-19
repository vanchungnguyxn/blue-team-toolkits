"""GeoIP functionality for Blue Team Toolkit."""

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

try:
    import geoip2.database
    import geoip2.errors

    GEOIP2_AVAILABLE = True
except ImportError:
    logger.debug("GeoIP2 not available - geographic lookups disabled")
    GEOIP2_AVAILABLE = False


class GeoIPLookup:
    """GeoIP lookup functionality."""

    def __init__(self, db_path: str | None = None):
        """Initialize GeoIP lookup.

        Args:
            db_path: Path to MaxMind GeoLite2 database file.
                    If None, tries common locations.
        """
        self.db_path = db_path
        self.reader = None
        self._initialize_database()

    def _initialize_database(self) -> None:
        """Initialize GeoIP database reader."""
        if not GEOIP2_AVAILABLE:
            logger.debug("GeoIP2 library not available")
            return

        # Try provided path first
        if self.db_path:
            db_paths = [self.db_path]
        else:
            # Common GeoLite2 database locations
            db_paths = [
                "GeoLite2-City.mmdb",
                "GeoLite2-Country.mmdb",
                "/usr/share/GeoIP/GeoLite2-City.mmdb",
                "/usr/share/GeoIP/GeoLite2-Country.mmdb",
                "/var/lib/GeoIP/GeoLite2-City.mmdb",
                "/var/lib/GeoIP/GeoLite2-Country.mmdb",
                "/opt/GeoIP/GeoLite2-City.mmdb",
                "/opt/GeoIP/GeoLite2-Country.mmdb",
                "data/GeoLite2-City.mmdb",
                "data/GeoLite2-Country.mmdb",
            ]

        for db_path in db_paths:
            try:
                db_file = Path(db_path)
                if db_file.exists():
                    self.reader = geoip2.database.Reader(str(db_file))
                    logger.info(f"GeoIP database loaded: {db_path}")
                    return
            except Exception as e:
                logger.debug(f"Failed to load GeoIP database {db_path}: {e}")

        logger.info("No GeoIP database found - geographic lookups will return N/A")

    def get_country(self, ip_address: str) -> str:
        """Get country name for IP address.

        Args:
            ip_address: IP address to lookup.

        Returns:
            Country name or "N/A" if not found.
        """
        if not self.reader:
            return "N/A"

        try:
            response = self.reader.city(ip_address)
            country = response.country.name
            return country if country else "N/A"
        except geoip2.errors.AddressNotFoundError:
            return "N/A"
        except Exception as e:
            logger.debug(f"GeoIP lookup error for {ip_address}: {e}")
            return "N/A"

    def get_country_code(self, ip_address: str) -> str:
        """Get country code for IP address.

        Args:
            ip_address: IP address to lookup.

        Returns:
            Two-letter country code or "N/A" if not found.
        """
        if not self.reader:
            return "N/A"

        try:
            response = self.reader.city(ip_address)
            country_code = response.country.iso_code
            return country_code if country_code else "N/A"
        except geoip2.errors.AddressNotFoundError:
            return "N/A"
        except Exception as e:
            logger.debug(f"GeoIP lookup error for {ip_address}: {e}")
            return "N/A"

    def get_city(self, ip_address: str) -> str:
        """Get city name for IP address.

        Args:
            ip_address: IP address to lookup.

        Returns:
            City name or "N/A" if not found.
        """
        if not self.reader:
            return "N/A"

        try:
            response = self.reader.city(ip_address)
            city = response.city.name
            return city if city else "N/A"
        except geoip2.errors.AddressNotFoundError:
            return "N/A"
        except Exception as e:
            logger.debug(f"GeoIP lookup error for {ip_address}: {e}")
            return "N/A"

    def get_location_info(self, ip_address: str) -> dict[str, Any]:
        """Get comprehensive location information for IP address.

        Args:
            ip_address: IP address to lookup.

        Returns:
            Dictionary with location information.
        """
        if not self.reader:
            return {
                "country": "N/A",
                "country_code": "N/A",
                "city": "N/A",
                "latitude": None,
                "longitude": None,
                "timezone": "N/A",
            }

        try:
            response = self.reader.city(ip_address)

            return {
                "country": response.country.name or "N/A",
                "country_code": response.country.iso_code or "N/A",
                "city": response.city.name or "N/A",
                "latitude": (
                    float(response.location.latitude)
                    if response.location.latitude
                    else None
                ),
                "longitude": (
                    float(response.location.longitude)
                    if response.location.longitude
                    else None
                ),
                "timezone": response.location.time_zone or "N/A",
            }
        except geoip2.errors.AddressNotFoundError:
            return {
                "country": "N/A",
                "country_code": "N/A",
                "city": "N/A",
                "latitude": None,
                "longitude": None,
                "timezone": "N/A",
            }
        except Exception as e:
            logger.debug(f"GeoIP lookup error for {ip_address}: {e}")
            return {
                "country": "N/A",
                "country_code": "N/A",
                "city": "N/A",
                "latitude": None,
                "longitude": None,
                "timezone": "N/A",
            }

    def is_available(self) -> bool:
        """Check if GeoIP lookup is available.

        Returns:
            True if GeoIP database is loaded and ready.
        """
        return self.reader is not None

    def close(self) -> None:
        """Close GeoIP database reader."""
        if self.reader:
            self.reader.close()
            self.reader = None
            logger.debug("GeoIP database closed")

    def __enter__(self):
        """Context manager entry."""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.close()


# Global GeoIP lookup instance
_geoip_lookup: GeoIPLookup | None = None


def init_geoip(db_path: str | None = None) -> None:
    """Initialize global GeoIP lookup.

    Args:
        db_path: Path to GeoIP database file.
    """
    global _geoip_lookup
    _geoip_lookup = GeoIPLookup(db_path)


def get_geoip_lookup() -> GeoIPLookup:
    """Get global GeoIP lookup instance.

    Returns:
        GeoIPLookup instance.
    """
    global _geoip_lookup
    if _geoip_lookup is None:
        _geoip_lookup = GeoIPLookup()
    return _geoip_lookup


def get_country(ip_address: str) -> str:
    """Get country name for IP address using global lookup.

    Args:
        ip_address: IP address to lookup.

    Returns:
        Country name or "N/A" if not found.
    """
    return get_geoip_lookup().get_country(ip_address)


def get_country_code(ip_address: str) -> str:
    """Get country code for IP address using global lookup.

    Args:
        ip_address: IP address to lookup.

    Returns:
        Two-letter country code or "N/A" if not found.
    """
    return get_geoip_lookup().get_country_code(ip_address)


def get_location_info(ip_address: str) -> dict[str, Any]:
    """Get location information for IP address using global lookup.

    Args:
        ip_address: IP address to lookup.

    Returns:
        Dictionary with location information.
    """
    return get_geoip_lookup().get_location_info(ip_address)
