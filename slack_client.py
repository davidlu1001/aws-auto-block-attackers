import logging
import requests
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
import json
import os


class SlackBlock(object):
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

    def get_json(self):
        return json.dumps(self.block)


class SlackClient(object):
    logger = logging.getLogger(__name__)
    # logger.setLevel(logging.DEBUG)

    def __init__(self, token="", webhook_url="", channel=""):
        self.token = token if token else None
        self.webhook_url = webhook_url
        self.channel = channel
        self.client = self.get_client() if self.token else None
        self.response = None

    def get_client(self):
        return WebClient(token=self.token)

    def post_message(self, message="", channel=""):
        """
        Posts a text message to a Slack channel.

        Args:
            message: The text message to post
            channel: Optional channel override (uses self.channel if not provided)

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
            self.response = self.client.chat_postMessage(
                channel=target_channel, text=message
            )
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
