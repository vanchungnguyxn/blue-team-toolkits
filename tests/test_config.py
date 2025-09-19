"""Tests for configuration management."""

import os
import tempfile
import pytest
import yaml
from pathlib import Path

from bluetool.config import (
    Config,
    load_config,
    save_config,
    create_default_config,
    validate_config,
    CaptureConfig,
    DetectionConfig,
    AlertsConfig,
    PersistenceConfig,
    LoggingConfig,
)


class TestConfig:
    """Test configuration classes."""

    def test_default_config_creation(self):
        """Test creating default configuration."""
        config = Config()

        assert config.version == 1
        assert config.interface == "auto"
        assert isinstance(config.capture, CaptureConfig)
        assert isinstance(config.detection, DetectionConfig)
        assert isinstance(config.alerts, AlertsConfig)
        assert isinstance(config.persistence, PersistenceConfig)
        assert isinstance(config.logging, LoggingConfig)

    def test_capture_config_defaults(self):
        """Test capture configuration defaults."""
        config = CaptureConfig()

        assert config.bpf == "tcp or udp or icmp"
        assert config.snaplen == 65535
        assert config.promisc is True
        assert config.offline is False

    def test_detection_config_defaults(self):
        """Test detection configuration defaults."""
        config = DetectionConfig()

        assert config.portscan.window_sec == 5
        assert config.portscan.unique_ports_threshold == 20

        assert config.bruteforce.services == ["ssh", "http", "https"]
        assert config.bruteforce.window_sec == 60
        assert config.bruteforce.fail_threshold == 10

        assert config.dos.window_sec == 5
        assert config.dos.packet_threshold == 500

    def test_alerts_config_defaults(self):
        """Test alerts configuration defaults."""
        config = AlertsConfig()

        assert config.slack_webhook == ""
        assert config.telegram.bot_token == ""
        assert config.telegram.chat_id == ""

    def test_persistence_config_defaults(self):
        """Test persistence configuration defaults."""
        config = PersistenceConfig()
        assert config.db_path == "bluetool.db"

    def test_logging_config_defaults(self):
        """Test logging configuration defaults."""
        config = LoggingConfig()
        assert config.level == "info"
        assert config.console is True


class TestConfigValidation:
    """Test configuration validation."""

    def test_valid_config(self):
        """Test validation of valid configuration."""
        config = Config()
        errors = validate_config(config)
        assert errors == []

    def test_invalid_version(self):
        """Test validation with invalid version."""
        config = Config()
        config.version = 2
        errors = validate_config(config)
        assert any("Unsupported version" in error for error in errors)

    def test_empty_interface(self):
        """Test validation with empty interface."""
        config = Config()
        config.interface = ""
        errors = validate_config(config)
        assert any("Interface cannot be empty" in error for error in errors)

    def test_invalid_thresholds(self):
        """Test validation with invalid thresholds."""
        config = Config()
        config.detection.portscan.unique_ports_threshold = 0
        config.detection.bruteforce.fail_threshold = -1
        config.detection.dos.packet_threshold = 0

        errors = validate_config(config)
        assert any("Port scan threshold must be positive" in error for error in errors)
        assert any(
            "Brute force threshold must be positive" in error for error in errors
        )
        assert any("DoS packet threshold must be positive" in error for error in errors)

    def test_invalid_time_windows(self):
        """Test validation with invalid time windows."""
        config = Config()
        config.detection.portscan.window_sec = 0
        config.detection.bruteforce.window_sec = -1
        config.detection.dos.window_sec = 0

        errors = validate_config(config)
        assert any("Port scan window must be positive" in error for error in errors)
        assert any("Brute force window must be positive" in error for error in errors)
        assert any("DoS window must be positive" in error for error in errors)

    def test_invalid_service(self):
        """Test validation with invalid service."""
        config = Config()
        config.detection.bruteforce.services = ["invalid_service"]

        errors = validate_config(config)
        assert any("Unknown service: invalid_service" in error for error in errors)

    def test_invalid_logging_level(self):
        """Test validation with invalid logging level."""
        config = Config()
        config.logging.level = "invalid"

        errors = validate_config(config)
        assert any("Invalid logging level: invalid" in error for error in errors)


class TestConfigFileOperations:
    """Test configuration file operations."""

    def test_create_default_config_dict(self):
        """Test creating default configuration dictionary."""
        config_dict = create_default_config()

        assert config_dict["version"] == 1
        assert config_dict["interface"] == "auto"
        assert "capture" in config_dict
        assert "detection" in config_dict
        assert "alerts" in config_dict
        assert "persistence" in config_dict
        assert "logging" in config_dict

    def test_load_config_default(self):
        """Test loading default configuration."""
        config = load_config(None)
        assert isinstance(config, Config)
        assert config.version == 1

    def test_load_config_from_file(self):
        """Test loading configuration from file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            config_data = create_default_config()
            config_data["interface"] = "eth0"
            yaml.dump(config_data, f)
            temp_path = f.name

        try:
            config = load_config(temp_path)
            assert config.interface == "eth0"
        finally:
            os.unlink(temp_path)

    def test_load_config_file_not_found(self):
        """Test loading configuration from non-existent file."""
        with pytest.raises(FileNotFoundError):
            load_config("nonexistent.yaml")

    def test_load_config_invalid_yaml(self):
        """Test loading configuration from invalid YAML file."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("invalid: yaml: content: [")
            temp_path = f.name

        try:
            with pytest.raises(yaml.YAMLError):
                load_config(temp_path)
        finally:
            os.unlink(temp_path)

    def test_load_config_invalid_structure(self):
        """Test loading configuration with invalid structure."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump("not a dictionary", f)
            temp_path = f.name

        try:
            with pytest.raises(
                ValueError, match="Configuration must be a YAML dictionary"
            ):
                load_config(temp_path)
        finally:
            os.unlink(temp_path)

    def test_load_config_unsupported_version(self):
        """Test loading configuration with unsupported version."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            config_data = {"version": 99}
            yaml.dump(config_data, f)
            temp_path = f.name

        try:
            with pytest.raises(ValueError, match="Unsupported configuration version"):
                load_config(temp_path)
        finally:
            os.unlink(temp_path)

    def test_save_and_load_config(self):
        """Test saving and loading configuration."""
        config = Config()
        config.interface = "test0"
        config.capture.bpf = "tcp port 80"

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            temp_path = f.name

        try:
            save_config(config, temp_path)
            loaded_config = load_config(temp_path)

            assert loaded_config.interface == "test0"
            assert loaded_config.capture.bpf == "tcp port 80"
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)

    def test_save_config_creates_directory(self):
        """Test that save_config creates parent directories."""
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "subdir" / "config.yaml"
            config = Config()

            save_config(config, str(config_path))

            assert config_path.exists()
            loaded_config = load_config(str(config_path))
            assert isinstance(loaded_config, Config)
