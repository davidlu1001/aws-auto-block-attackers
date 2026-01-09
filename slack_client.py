import logging
import requests
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import json
import os
from typing import Optional, Dict, List, Any
from enum import Enum


class SlackSeverity(Enum):
    """Severity levels for Slack notifications with corresponding colors."""
    INFO = "#36a64f"       # Green - informational
    WARNING = "#f2c744"    # Yellow - warning
    LOW = "#ff9933"        # Orange - low threat
    MEDIUM = "#e07000"     # Dark orange - medium threat
    HIGH = "#cc0000"       # Red - high threat
    CRITICAL = "#8b0000"   # Dark red - critical threat
    SUCCESS = "#2eb886"    # Teal - success
    ERROR = "#ff0000"      # Bright red - error


# Mapping from threat tier names to severity
TIER_TO_SEVERITY = {
    "minimal": SlackSeverity.LOW,
    "low": SlackSeverity.LOW,
    "medium": SlackSeverity.MEDIUM,
    "high": SlackSeverity.HIGH,
    "critical": SlackSeverity.CRITICAL,
}


class SlackBlock(object):
    """Builder for Slack Block Kit messages."""

    def __init__(self):
        self.block = []

    def get(self):
        return {"blocks": self.block}

    def append(self, message_type="mrkdwn", message="", image_url=""):
        """
        appends a new section to the message
        """
        bl = {"type": "section", "text": {"type": message_type, "text": message}}

        if image_url != "":
            bl["accessory"] = {
                "type": "image",
                "image_url": image_url,
                "alt_text": "...",
            }

        self.block.append(bl)

    def add_divider(self):
        self.block.append({"type": "divider"})

    def add_image(self, image_url="", alt_text="", title="Example Image"):
        img = {
            "type": "image",
            "title": {"type": "plain_text", "text": title, "emoji": True},
            "image_url": image_url,
            "alt_text": alt_text,
        }

        self.block.append(img)

    def add_header(self, text: str):
        """Add a header block."""
        self.block.append({
            "type": "header",
            "text": {"type": "plain_text", "text": text, "emoji": True}
        })

    def add_context(self, elements: List[str]):
        """Add a context block with multiple text elements."""
        self.block.append({
            "type": "context",
            "elements": [
                {"type": "mrkdwn", "text": elem} for elem in elements
            ]
        })

    def add_fields(self, fields: List[tuple]):
        """Add a section with multiple fields (key-value pairs)."""
        field_elements = []
        for label, value in fields:
            field_elements.append({
                "type": "mrkdwn",
                "text": f"*{label}:*\n{value}"
            })
        self.block.append({
            "type": "section",
            "fields": field_elements
        })

    def add_actions(self, buttons: List[Dict[str, str]]):
        """
        Add an actions block with buttons.

        Args:
            buttons: List of button configs with keys:
                - text: Button label
                - action_id: Unique identifier for the action
                - style: Optional "primary" or "danger"
                - value: Optional value to pass with the action
        """
        elements = []
        for btn in buttons:
            button = {
                "type": "button",
                "text": {"type": "plain_text", "text": btn["text"], "emoji": True},
                "action_id": btn["action_id"],
            }
            if btn.get("style"):
                button["style"] = btn["style"]
            if btn.get("value"):
                button["value"] = btn["value"]
            if btn.get("url"):
                button["url"] = btn["url"]
            elements.append(button)

        self.block.append({
            "type": "actions",
            "elements": elements
        })

    def get_json(self):
        return json.dumps(self.block)


class SlackClient(object):
    """
    Enhanced Slack client with support for:
    - Rich formatted messages with Block Kit
    - Severity-based color coding via attachments
    - Message threading for incident grouping
    - Interactive action buttons
    """
    logger = logging.getLogger(__name__)

    def __init__(self, token="", webhook_url="", channel=""):
        self.token = token if token else None
        self.webhook_url = webhook_url
        self.channel = channel
        self.client = self.get_client() if self.token else None
        self.response = None
        # Thread tracking for incident threading
        self._active_threads: Dict[str, str] = {}  # incident_id -> thread_ts

    def get_client(self):
        return WebClient(token=self.token)

    def get_thread_ts(self, incident_id: str) -> Optional[str]:
        """Get the thread timestamp for an incident if it exists."""
        return self._active_threads.get(incident_id)

    def set_thread_ts(self, incident_id: str, thread_ts: str):
        """Store the thread timestamp for an incident."""
        self._active_threads[incident_id] = thread_ts

    def clear_thread(self, incident_id: str):
        """Clear the thread for an incident."""
        self._active_threads.pop(incident_id, None)

    def post_message(
        self,
        message: str = "",
        channel: str = "",
        thread_ts: Optional[str] = None,
        reply_broadcast: bool = False,
    ) -> bool:
        """
        Posts a text message to a Slack channel.

        Args:
            message: The text message to post
            channel: Optional channel override (uses self.channel if not provided)
            thread_ts: Optional thread timestamp to reply to
            reply_broadcast: If True and in a thread, also post to channel

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.client:
            self.logger.error("Slack client not initialized. Cannot post message.")
            return False

        if self.token == "test":
            self.logger.info("Using test token. Wont post anything to slack")
            return True

        try:
            target_channel = channel if channel else self.channel
            if not target_channel:
                self.logger.error("No channel specified for message posting")
                return False

            self.logger.info(
                "Notifying slack channel [%s] with message: %s"
                % (target_channel, message)
            )

            kwargs = {
                "channel": target_channel,
                "text": message,
            }
            if thread_ts:
                kwargs["thread_ts"] = thread_ts
                kwargs["reply_broadcast"] = reply_broadcast

            self.response = self.client.chat_postMessage(**kwargs)
            self.logger.info("Message posted successfully: %s" % self.response)
            return True
        except SlackApiError as err:
            self.logger.warning(
                "Slack API error when posting message: %s", err.response["error"]
            )
            return False
        except Exception as err:
            self.logger.warning("Whoops... could not post to slack: %s", err)
            return False

    def post_rich_message(
        self,
        text: str,
        blocks: Optional[List[Dict]] = None,
        attachments: Optional[List[Dict]] = None,
        severity: Optional[SlackSeverity] = None,
        channel: str = "",
        thread_ts: Optional[str] = None,
        reply_broadcast: bool = False,
    ) -> Optional[str]:
        """
        Posts a rich message with blocks, attachments, and optional color coding.

        Args:
            text: Fallback text for notifications
            blocks: Optional list of Block Kit blocks
            attachments: Optional list of attachments
            severity: Optional severity level for color coding
            channel: Optional channel override
            thread_ts: Optional thread to reply to
            reply_broadcast: If True and in a thread, also post to channel

        Returns:
            str: Thread timestamp if successful, None otherwise
        """
        if not self.client:
            self.logger.error("Slack client not initialized.")
            return None

        if self.token == "test":
            self.logger.info("Using test token. Wont post anything to slack")
            return "test_thread_ts"

        try:
            target_channel = channel if channel else self.channel
            if not target_channel:
                self.logger.error("No channel specified")
                return None

            kwargs: Dict[str, Any] = {
                "channel": target_channel,
                "text": text,
            }

            if blocks:
                kwargs["blocks"] = blocks

            # Create attachment with severity color if specified
            if severity:
                color_attachment = {
                    "color": severity.value,
                    "blocks": blocks or [],
                }
                kwargs["attachments"] = [color_attachment]
                # Remove blocks from top level when using attachments
                kwargs.pop("blocks", None)
            elif attachments:
                kwargs["attachments"] = attachments

            if thread_ts:
                kwargs["thread_ts"] = thread_ts
                kwargs["reply_broadcast"] = reply_broadcast

            self.response = self.client.chat_postMessage(**kwargs)

            # Return the thread_ts for threading
            if self.response and self.response.get("ok"):
                return self.response.get("ts")
            return None

        except SlackApiError as err:
            self.logger.warning(
                "Slack API error: %s", err.response["error"]
            )
            return None
        except Exception as err:
            self.logger.warning("Error posting rich message: %s", err)
            return None

    def post_incident_notification(
        self,
        title: str,
        description: str,
        fields: List[tuple],
        severity: SlackSeverity = SlackSeverity.INFO,
        incident_id: Optional[str] = None,
        action_buttons: Optional[List[Dict[str, str]]] = None,
        channel: str = "",
    ) -> Optional[str]:
        """
        Posts a formatted incident notification with threading support.

        Args:
            title: Incident title (header)
            description: Incident description
            fields: List of (label, value) tuples for fields
            severity: Severity level for color coding
            incident_id: Optional incident ID for threading
            action_buttons: Optional list of action button configs
            channel: Optional channel override

        Returns:
            str: Thread timestamp if successful, None otherwise
        """
        # Build blocks
        blocks = []

        # Header
        blocks.append({
            "type": "header",
            "text": {"type": "plain_text", "text": title, "emoji": True}
        })

        # Description
        if description:
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": description}
            })

        # Fields (in pairs)
        if fields:
            field_elements = []
            for label, value in fields:
                field_elements.append({
                    "type": "mrkdwn",
                    "text": f"*{label}:*\n{value}"
                })
            # Slack allows max 10 fields per section
            for i in range(0, len(field_elements), 10):
                blocks.append({
                    "type": "section",
                    "fields": field_elements[i:i+10]
                })

        # Divider before actions
        if action_buttons:
            blocks.append({"type": "divider"})
            elements = []
            for btn in action_buttons:
                button = {
                    "type": "button",
                    "text": {"type": "plain_text", "text": btn["text"], "emoji": True},
                    "action_id": btn.get("action_id", btn["text"].lower().replace(" ", "_")),
                }
                if btn.get("style"):
                    button["style"] = btn["style"]
                if btn.get("value"):
                    button["value"] = btn["value"]
                if btn.get("url"):
                    button["url"] = btn["url"]
                elements.append(button)

            blocks.append({
                "type": "actions",
                "elements": elements
            })

        # Get existing thread if this is a follow-up
        thread_ts = None
        if incident_id:
            thread_ts = self.get_thread_ts(incident_id)

        # Post the message
        result_ts = self.post_rich_message(
            text=f"{title}: {description}",
            blocks=blocks,
            severity=severity,
            channel=channel,
            thread_ts=thread_ts,
            reply_broadcast=thread_ts is not None,  # Broadcast follow-ups
        )

        # Store thread_ts for future messages in this incident
        if result_ts and incident_id and not thread_ts:
            self.set_thread_ts(incident_id, result_ts)

        return result_ts

    def post_blocks(self, blocks=[], channel=""):
        """
        Posts formatted blocks to a Slack channel.

        Args:
            blocks: List of Slack block objects
            channel: Optional channel override (uses self.channel if not provided)

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.client:
            self.logger.error("Slack client not initialized. Cannot post blocks.")
            return False

        if self.token == "test":
            self.logger.info("Using test token. Wont post anything to slack")
            return True

        try:
            target_channel = channel if channel else self.channel
            if not target_channel:
                self.logger.error("No channel specified for blocks posting")
                return False

            self.logger.info(
                "Notifying slack channel [%s] with blocks: %s"
                % (target_channel, blocks)
            )
            self.response = self.client.chat_postMessage(
                channel=target_channel, blocks=blocks
            )
            self.logger.info("Blocks posted successfully: %s" % self.response)
            return True
        except SlackApiError as err:
            self.logger.warning(
                "Slack API error when posting blocks: %s", err.response["error"]
            )
            return False
        except Exception as err:
            self.logger.warning("Whoops... could not post blocks to slack: %s", err)
            return False

    def post_payload(self, payload):
        """
        Posts a raw payload to a Slack webhook URL.

        Args:
            payload: Dictionary payload to send to webhook

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.webhook_url:
            self.logger.error("No webhook URL configured. Cannot post payload.")
            return False

        try:
            self.logger.info("slack payload: %s" % (payload))
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            self.logger.info("Payload posted successfully to webhook")
            return True
        except requests.exceptions.RequestException as err:
            self.logger.warning("Failed to post payload to webhook: %s", err)
            return False
        except Exception as err:
            self.logger.warning("Unexpected error posting to webhook: %s", err)
            return False

    def upload_file(self, file, channel="", filename=None, title=None):
        """
        Upload a file using the new files.getUploadURLExternal and files.completeUploadExternal APIs
        with slack-sdk

        Args:
            file: Path to the file to upload
            channel: Optional channel override (uses self.channel if not provided)
            filename: Optional filename override (uses basename if not provided)
            title: Optional title for the file in Slack

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.client:
            self.logger.error("Slack client not initialized. Cannot upload file.")
            return False

        if self.token == "test":
            self.logger.info("Using test token. Wont upload file to slack")
            return True

        try:
            # Validate file exists
            if not os.path.exists(file):
                self.logger.error(f"File does not exist: {file}")
                return False

            # Get the filename if not provided
            if filename is None:
                filename = os.path.basename(file)

            # Get file size
            file_size = os.path.getsize(file)

            # Determine the channel to use
            upload_channel = channel if channel else self.channel
            if not upload_channel:
                self.logger.error("No channel specified for file upload")
                return False

            self.logger.info(
                "Uploading file [%s] (size: %d bytes) to slack channel [%s]"
                % (file, file_size, upload_channel)
            )

            # Step 1: Get upload URL using slack-sdk
            upload_response = self.client.files_getUploadURLExternal(
                filename=filename, length=file_size
            )

            if not upload_response["ok"]:
                self.logger.error(
                    "Failed to get upload URL: %s"
                    % upload_response.get("error", "Unknown error")
                )
                return False

            upload_url = upload_response["upload_url"]
            file_id = upload_response["file_id"]

            # Step 2: Upload file to the URL
            with open(file, "rb") as f:
                upload_result = requests.post(upload_url, files={"file": f}, timeout=30)

            if upload_result.status_code != 200:
                self.logger.error(
                    "Failed to upload file to external URL: HTTP %d - %s"
                    % (upload_result.status_code, upload_result.text)
                )
                return False

            # Step 3: Complete the upload using slack-sdk
            complete_response = self.client.files_completeUploadExternal(
                files=[{"id": file_id, "title": title or filename}],
                channel_id=upload_channel,
            )

            if complete_response["ok"]:
                self.logger.info("File uploaded successfully: %s" % complete_response)
                self.response = complete_response
                return True
            else:
                self.logger.error(
                    "Failed to complete upload: %s"
                    % complete_response.get("error", "Unknown error")
                )
                return False

        except SlackApiError as err:
            self.logger.warning(
                "Slack API error during file upload: %s", err.response["error"]
            )
            return False
        except Exception as err:
            self.logger.warning("Whoops... could not upload file to slack: %s", err)
            return False
