import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open
import sys
import os

# Add the parent directory to sys.path to import slack_client
sys.path.insert(0, os.path.dirname(__file__))

from slack_client import SlackClient, SlackBlock


class TestSlackBlock(unittest.TestCase):
    """Tests for SlackBlock class"""

    def setUp(self):
        self.block = SlackBlock()

    def test_initialization(self):
        """Test that SlackBlock initializes with empty block list"""
        self.assertEqual(self.block.block, [])

    def test_get(self):
        """Test get method returns blocks dictionary"""
        result = self.block.get()
        self.assertEqual(result, {"blocks": []})

    def test_append_text_only(self):
        """Test appending a text-only section"""
        self.block.append(message_type="mrkdwn", message="Test message")
        expected = {
            "type": "section",
            "text": {"type": "mrkdwn", "text": "Test message"},
        }
        self.assertEqual(len(self.block.block), 1)
        self.assertEqual(self.block.block[0], expected)

    def test_append_with_image(self):
        """Test appending a section with an image"""
        self.block.append(
            message_type="mrkdwn",
            message="Test message",
            image_url="https://example.com/image.png",
        )
        self.assertEqual(len(self.block.block), 1)
        self.assertIn("accessory", self.block.block[0])
        self.assertEqual(
            self.block.block[0]["accessory"]["image_url"],
            "https://example.com/image.png",
        )

    def test_add_divider(self):
        """Test adding a divider"""
        self.block.add_divider()
        self.assertEqual(len(self.block.block), 1)
        self.assertEqual(self.block.block[0], {"type": "divider"})

    def test_add_image(self):
        """Test adding an image block"""
        self.block.add_image(
            image_url="https://example.com/test.png",
            alt_text="Test Alt",
            title="Test Title",
        )
        self.assertEqual(len(self.block.block), 1)
        self.assertEqual(self.block.block[0]["type"], "image")
        self.assertEqual(self.block.block[0]["image_url"], "https://example.com/test.png")
        self.assertEqual(self.block.block[0]["alt_text"], "Test Alt")

    def test_get_json(self):
        """Test JSON serialization of blocks"""
        self.block.append(message="Test")
        json_str = self.block.get_json()
        self.assertIsInstance(json_str, str)
        self.assertIn("Test", json_str)


class TestSlackClient(unittest.TestCase):
    """Tests for SlackClient class"""

    def setUp(self):
        """Set up test fixtures"""
        self.token = "xoxb-test-token"
        self.webhook_url = "https://hooks.slack.com/services/TEST"
        self.channel = "#test-channel"

    @patch("slack_client.WebClient")
    def test_initialization_with_token(self, mock_webclient):
        """Test SlackClient initializes correctly with token"""
        client = SlackClient(token=self.token, channel=self.channel)
        self.assertEqual(client.token, self.token)
        self.assertEqual(client.channel, self.channel)
        self.assertIsNotNone(client.client)
        mock_webclient.assert_called_once_with(token=self.token)

    def test_initialization_without_token(self):
        """Test SlackClient initializes correctly without token"""
        client = SlackClient(webhook_url=self.webhook_url, channel=self.channel)
        self.assertIsNone(client.token)
        self.assertIsNone(client.client)
        self.assertEqual(client.webhook_url, self.webhook_url)

    @patch("slack_client.WebClient")
    def test_post_message_success(self, mock_webclient):
        """Test successful message posting"""
        mock_client_instance = Mock()
        mock_webclient.return_value = mock_client_instance
        mock_client_instance.chat_postMessage.return_value = {"ok": True}

        client = SlackClient(token=self.token, channel=self.channel)
        result = client.post_message(message="Test message")

        self.assertTrue(result)
        mock_client_instance.chat_postMessage.assert_called_once_with(
            channel=self.channel, text="Test message"
        )

    @patch("slack_client.WebClient")
    def test_post_message_no_client(self, mock_webclient):
        """Test posting message without initialized client"""
        client = SlackClient(webhook_url=self.webhook_url)
        result = client.post_message(message="Test")
        self.assertFalse(result)

    @patch("slack_client.WebClient")
    def test_post_message_test_mode(self, mock_webclient):
        """Test posting message in test mode"""
        client = SlackClient(token="test", channel=self.channel)
        result = client.post_message(message="Test")
        self.assertTrue(result)
        # Should not actually call the API
        client.client.chat_postMessage.assert_not_called()

    @patch("slack_client.WebClient")
    def test_post_message_no_channel(self, mock_webclient):
        """Test posting message without channel specified"""
        client = SlackClient(token=self.token)
        result = client.post_message(message="Test")
        self.assertFalse(result)

    @patch("slack_client.WebClient")
    def test_post_message_with_channel_override(self, mock_webclient):
        """Test posting message with channel override"""
        mock_client_instance = Mock()
        mock_webclient.return_value = mock_client_instance
        mock_client_instance.chat_postMessage.return_value = {"ok": True}

        client = SlackClient(token=self.token, channel=self.channel)
        result = client.post_message(message="Test", channel="#other-channel")

        self.assertTrue(result)
        mock_client_instance.chat_postMessage.assert_called_once_with(
            channel="#other-channel", text="Test"
        )

    @patch("slack_client.WebClient")
    def test_post_blocks_success(self, mock_webclient):
        """Test successful blocks posting"""
        mock_client_instance = Mock()
        mock_webclient.return_value = mock_client_instance
        mock_client_instance.chat_postMessage.return_value = {"ok": True}

        client = SlackClient(token=self.token, channel=self.channel)
        blocks = [{"type": "section", "text": {"type": "mrkdwn", "text": "Test"}}]
        result = client.post_blocks(blocks=blocks)

        self.assertTrue(result)
        mock_client_instance.chat_postMessage.assert_called_once_with(
            channel=self.channel, blocks=blocks
        )

    @patch("slack_client.requests.post")
    def test_post_payload_success(self, mock_post):
        """Test successful webhook payload posting"""
        mock_response = Mock()
        mock_response.raise_for_status = Mock()
        mock_post.return_value = mock_response

        client = SlackClient(webhook_url=self.webhook_url)
        payload = {"text": "Test message"}
        result = client.post_payload(payload)

        self.assertTrue(result)
        mock_post.assert_called_once_with(
            self.webhook_url, json=payload, timeout=10
        )

    @patch("slack_client.requests.post")
    def test_post_payload_no_webhook_url(self, mock_post):
        """Test posting payload without webhook URL"""
        client = SlackClient(token=self.token)
        result = client.post_payload({"text": "Test"})
        self.assertFalse(result)
        mock_post.assert_not_called()

    @patch("slack_client.requests.post")
    def test_post_payload_request_exception(self, mock_post):
        """Test posting payload with request exception"""
        mock_post.side_effect = Exception("Connection error")

        client = SlackClient(webhook_url=self.webhook_url)
        result = client.post_payload({"text": "Test"})

        self.assertFalse(result)

    @patch("slack_client.WebClient")
    @patch("slack_client.requests.post")
    @patch("slack_client.os.path.exists")
    @patch("slack_client.os.path.getsize")
    @patch("builtins.open", new_callable=mock_open, read_data=b"file content")
    def test_upload_file_success(
        self, mock_file, mock_getsize, mock_exists, mock_requests_post, mock_webclient
    ):
        """Test successful file upload"""
        mock_exists.return_value = True
        mock_getsize.return_value = 1024

        mock_client_instance = Mock()
        mock_webclient.return_value = mock_client_instance

        # Mock the upload flow
        mock_client_instance.files_getUploadURLExternal.return_value = {
            "ok": True,
            "upload_url": "https://upload.url",
            "file_id": "F12345",
        }

        mock_upload_response = Mock()
        mock_upload_response.status_code = 200
        mock_requests_post.return_value = mock_upload_response

        mock_client_instance.files_completeUploadExternal.return_value = {"ok": True}

        client = SlackClient(token=self.token, channel=self.channel)
        result = client.upload_file(file="/path/to/test.txt")

        self.assertTrue(result)
        mock_client_instance.files_getUploadURLExternal.assert_called_once()
        mock_client_instance.files_completeUploadExternal.assert_called_once()

    @patch("slack_client.WebClient")
    @patch("slack_client.os.path.exists")
    def test_upload_file_not_exists(self, mock_exists, mock_webclient):
        """Test uploading non-existent file"""
        mock_exists.return_value = False

        client = SlackClient(token=self.token, channel=self.channel)
        result = client.upload_file(file="/path/to/missing.txt")

        self.assertFalse(result)

    @patch("slack_client.WebClient")
    def test_upload_file_no_channel(self, mock_webclient):
        """Test uploading file without channel specified"""
        client = SlackClient(token=self.token)
        result = client.upload_file(file="/path/to/test.txt")
        self.assertFalse(result)

    @patch("slack_client.WebClient")
    def test_upload_file_test_mode(self, mock_webclient):
        """Test file upload in test mode"""
        client = SlackClient(token="test", channel=self.channel)
        result = client.upload_file(file="/path/to/test.txt")
        self.assertTrue(result)


if __name__ == "__main__":
    unittest.main()
