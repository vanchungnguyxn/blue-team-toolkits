"""Alert functionality for Blue Team Toolkit."""

import logging
from datetime import datetime

import requests

from .config import AlertsConfig
from .geoip import get_country
from .storage import Event

logger = logging.getLogger(__name__)


class SlackAlerter:
    """Slack webhook alerting."""

    def __init__(self, webhook_url: str):
        """Initialize Slack alerter.

        Args:
            webhook_url: Slack webhook URL.
        """
        self.webhook_url = webhook_url
        self.enabled = bool(webhook_url.strip())

    def send_alert(self, event: Event) -> bool:
        """Send alert to Slack.

        Args:
            event: Event to alert on.

        Returns:
            True if alert sent successfully.
        """
        if not self.enabled:
            return False

        try:
            # Get country info for source IP
            country = get_country(event.src_ip)
            country_flag = self._get_country_emoji(country)

            # Format timestamp
            timestamp = datetime.fromtimestamp(event.timestamp)
            time_str = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

            # Choose emoji and color based on event type
            emoji, color, recommendation = self._get_event_style(event.type)

            # Build message
            message = {
                "attachments": [
                    {
                        "color": color,
                        "title": f"{emoji} {event.type} Alert",
                        "fields": [
                            {
                                "title": "Source IP",
                                "value": f"{country_flag} {event.src_ip} ({country})",
                                "short": True,
                            },
                            {
                                "title": "Count",
                                "value": str(event.count),
                                "short": True,
                            },
                            {
                                "title": "Timestamp",
                                "value": time_str,
                                "short": True,
                            },
                            {
                                "title": "Event ID",
                                "value": event.id[:8],
                                "short": True,
                            },
                        ],
                        "footer": "Blue Team Toolkit",
                        "ts": int(event.timestamp),
                    }
                ]
            }

            # Add destination IP if available
            if event.dst_ip:
                message["attachments"][0]["fields"].insert(
                    1,
                    {
                        "title": "Destination IP",
                        "value": event.dst_ip,
                        "short": True,
                    },
                )

            # Add details if available
            if event.details:
                message["attachments"][0]["fields"].append(
                    {
                        "title": "Details",
                        "value": event.details,
                        "short": False,
                    }
                )

            # Add recommendation
            message["attachments"][0]["fields"].append(
                {
                    "title": "Recommendation",
                    "value": recommendation,
                    "short": False,
                }
            )

            # Send to Slack
            response = requests.post(
                self.webhook_url,
                json=message,
                timeout=10,
                headers={"Content-Type": "application/json"},
            )

            if response.status_code == 200:
                logger.debug(f"Slack alert sent for event {event.id}")
                return True
            else:
                logger.error(
                    f"Slack alert failed: {response.status_code} - {response.text}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to send Slack alert: {e}")
            return False

    def _get_country_emoji(self, country: str) -> str:
        """Get emoji flag for country.

        Args:
            country: Country name.

        Returns:
            Flag emoji or default emoji.
        """
        # Simple mapping of some countries to flag emojis
        country_flags = {
            "United States": "🇺🇸",
            "United Kingdom": "🇬🇧",
            "Canada": "🇨🇦",
            "Germany": "🇩🇪",
            "France": "🇫🇷",
            "Japan": "🇯🇵",
            "China": "🇨🇳",
            "Russia": "🇷🇺",
            "Brazil": "🇧🇷",
            "India": "🇮🇳",
            "Australia": "🇦🇺",
        }
        return country_flags.get(country, "🌍")

    def _get_event_style(self, event_type: str) -> tuple[str, str, str]:
        """Get styling for event type.

        Args:
            event_type: Event type.

        Returns:
            Tuple of (emoji, color, recommendation).
        """
        styles = {
            "PORTSCAN": (
                "🔍",
                "warning",
                "Consider blocking IP if scan is aggressive or from suspicious location.",
            ),
            "BRUTEFORCE": (
                "🔨",
                "danger",
                "Block IP immediately and check for compromised accounts.",
            ),
            "DOS": (
                "💥",
                "danger",
                "Implement rate limiting or block IP to prevent service disruption.",
            ),
        }
        return styles.get(event_type, ("⚠️", "warning", "Investigate further."))


class TelegramAlerter:
    """Telegram bot alerting."""

    def __init__(self, bot_token: str, chat_id: str):
        """Initialize Telegram alerter.

        Args:
            bot_token: Telegram bot token.
            chat_id: Telegram chat ID.
        """
        self.bot_token = bot_token.strip()
        self.chat_id = chat_id.strip()
        self.enabled = bool(self.bot_token and self.chat_id)
        self.api_url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"

    def send_alert(self, event: Event) -> bool:
        """Send alert to Telegram.

        Args:
            event: Event to alert on.

        Returns:
            True if alert sent successfully.
        """
        if not self.enabled:
            return False

        try:
            # Get country info for source IP
            country = get_country(event.src_ip)

            # Format timestamp
            timestamp = datetime.fromtimestamp(event.timestamp)
            time_str = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

            # Choose emoji based on event type
            emoji = self._get_event_emoji(event.type)

            # Build message
            message_lines = [
                f"{emoji} *{event.type} ALERT*",
                "",
                f"*Source IP:* {event.src_ip} ({country})",
                f"*Count:* {event.count}",
                f"*Time:* {time_str}",
                f"*Event ID:* `{event.id[:8]}`",
            ]

            # Add destination IP if available
            if event.dst_ip:
                message_lines.insert(-2, f"*Destination IP:* {event.dst_ip}")

            # Add details if available
            if event.details:
                message_lines.append(f"*Details:* {event.details}")

            # Add recommendation
            recommendation = self._get_recommendation(event.type)
            message_lines.append(f"*Recommendation:* {recommendation}")

            message_text = "\n".join(message_lines)

            # Send to Telegram
            payload = {
                "chat_id": self.chat_id,
                "text": message_text,
                "parse_mode": "Markdown",
                "disable_web_page_preview": True,
            }

            response = requests.post(
                self.api_url,
                json=payload,
                timeout=10,
            )

            if response.status_code == 200:
                logger.debug(f"Telegram alert sent for event {event.id}")
                return True
            else:
                logger.error(
                    f"Telegram alert failed: {response.status_code} - {response.text}"
                )
                return False

        except Exception as e:
            logger.error(f"Failed to send Telegram alert: {e}")
            return False

    def _get_event_emoji(self, event_type: str) -> str:
        """Get emoji for event type.

        Args:
            event_type: Event type.

        Returns:
            Emoji string.
        """
        emojis = {
            "PORTSCAN": "🔍",
            "BRUTEFORCE": "🔨",
            "DOS": "💥",
        }
        return emojis.get(event_type, "⚠️")

    def _get_recommendation(self, event_type: str) -> str:
        """Get recommendation for event type.

        Args:
            event_type: Event type.

        Returns:
            Recommendation string.
        """
        recommendations = {
            "PORTSCAN": "Consider blocking IP if scan is aggressive.",
            "BRUTEFORCE": "Block IP and check for compromised accounts.",
            "DOS": "Implement rate limiting or block IP.",
        }
        return recommendations.get(event_type, "Investigate further.")


class AlertManager:
    """Manage all alert channels."""

    def __init__(self, config: AlertsConfig):
        """Initialize alert manager.

        Args:
            config: Alerts configuration.
        """
        self.config = config
        self.slack_alerter = None
        self.telegram_alerter = None

        # Initialize alerters
        if config.slack_webhook:
            self.slack_alerter = SlackAlerter(config.slack_webhook)
            logger.info("Slack alerting enabled")

        if config.telegram.bot_token and config.telegram.chat_id:
            self.telegram_alerter = TelegramAlerter(
                config.telegram.bot_token, config.telegram.chat_id
            )
            logger.info("Telegram alerting enabled")

        if not self.slack_alerter and not self.telegram_alerter:
            logger.info("No alert channels configured")

    def send_alert(self, event: Event) -> dict[str, bool]:
        """Send alert to all configured channels.

        Args:
            event: Event to alert on.

        Returns:
            Dictionary with success status for each channel.
        """
        results = {}

        # Send to Slack
        if self.slack_alerter:
            try:
                results["slack"] = self.slack_alerter.send_alert(event)
            except Exception as e:
                logger.error(f"Slack alert error: {e}")
                results["slack"] = False

        # Send to Telegram
        if self.telegram_alerter:
            try:
                results["telegram"] = self.telegram_alerter.send_alert(event)
            except Exception as e:
                logger.error(f"Telegram alert error: {e}")
                results["telegram"] = False

        # Log results
        successful_channels = [ch for ch, success in results.items() if success]
        if successful_channels:
            logger.info(f"Alert sent successfully to: {', '.join(successful_channels)}")
        else:
            logger.warning("Failed to send alert to any channels")

        return results

    def test_alerts(self) -> dict[str, bool]:
        """Test all configured alert channels.

        Returns:
            Dictionary with test results for each channel.
        """
        # Create test event
        test_event = Event.create(
            event_type="TEST",
            src_ip="127.0.0.1",
            count=1,
            details="This is a test alert from Blue Team Toolkit",
        )

        logger.info("Sending test alerts...")
        return self.send_alert(test_event)

    def get_enabled_channels(self) -> list[str]:
        """Get list of enabled alert channels.

        Returns:
            List of enabled channel names.
        """
        channels = []
        if self.slack_alerter and self.slack_alerter.enabled:
            channels.append("slack")
        if self.telegram_alerter and self.telegram_alerter.enabled:
            channels.append("telegram")
        return channels

    def is_enabled(self) -> bool:
        """Check if any alert channels are enabled.

        Returns:
            True if at least one channel is enabled.
        """
        return len(self.get_enabled_channels()) > 0
