#!/usr/bin/env python3
"""
Test suite for auto_block_attackers.py
Tests all critical logic paths and fixes
"""

import unittest
from unittest.mock import Mock, patch, MagicMock, mock_open
from datetime import timedelta, datetime, timezone
from collections import Counter
import sys
import os

# Add parent directory to path to import the module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auto_block_attackers import NaclAutoBlocker, is_valid_public_ipv4, ATTACK_PATTERNS


class TestHelperFunctions(unittest.TestCase):
    """Test standalone helper functions"""

    def test_is_valid_public_ipv4_valid(self):
        """Test valid public IPv4 addresses"""
        self.assertTrue(is_valid_public_ipv4("8.8.8.8"))
        self.assertTrue(is_valid_public_ipv4("1.1.1.1"))
        self.assertTrue(is_valid_public_ipv4("123.45.67.89"))

    def test_is_valid_public_ipv4_private(self):
        """Test private IPv4 addresses are rejected"""
        self.assertFalse(is_valid_public_ipv4("192.168.1.1"))
        self.assertFalse(is_valid_public_ipv4("10.0.0.1"))
        self.assertFalse(is_valid_public_ipv4("172.16.0.1"))
        self.assertFalse(is_valid_public_ipv4("127.0.0.1"))

    def test_is_valid_public_ipv4_invalid(self):
        """Test invalid IP formats are rejected"""
        self.assertFalse(is_valid_public_ipv4("not_an_ip"))
        self.assertFalse(is_valid_public_ipv4("256.1.1.1"))
        self.assertFalse(is_valid_public_ipv4("2001:db8::1"))  # IPv6

    def test_attack_patterns_detection(self):
        """Test that attack patterns detect malicious requests"""
        malicious_samples = [
            "GET /../../etc/passwd HTTP/1.1",
            "POST /login?user=admin' OR '1'='1 HTTP/1.1",
            "<script>alert(1)</script>",
            "GET /.env HTTP/1.1",
            "GET /wp-login.php HTTP/1.1",
            "GET /path?cmd=whoami HTTP/1.1",
        ]
        for sample in malicious_samples:
            self.assertIsNotNone(
                ATTACK_PATTERNS.search(sample),
                f"Pattern should match: {sample}"
            )

    def test_attack_patterns_benign(self):
        """Test that benign requests are not flagged"""
        benign_samples = [
            "GET / HTTP/1.1",
            "GET /api/users/123 HTTP/1.1",
            "POST /login HTTP/1.1",
        ]
        for sample in benign_samples:
            self.assertIsNone(
                ATTACK_PATTERNS.search(sample),
                f"Pattern should not match: {sample}"
            )


class TestNaclAutoBlocker(unittest.TestCase):
    """Test NaclAutoBlocker class methods"""

    def setUp(self):
        """Set up test fixtures"""
        # Mock AWS clients to avoid actual API calls
        with patch('auto_block_attackers.boto3.client'):
            self.blocker = NaclAutoBlocker(
                lb_name_pattern="test-lb-*",
                region="us-east-1",
                lookback_str="1h",
                threshold=10,
                start_rule=80,
                limit=20,
                whitelist_file=None,
                aws_ip_ranges_file=None,
                dry_run=True,
                debug=False
            )

    def test_parse_lookback_period_minutes(self):
        """Test parsing minutes lookback period"""
        result = self.blocker._parse_lookback_period("30m")
        self.assertEqual(result, timedelta(minutes=30))

    def test_parse_lookback_period_hours(self):
        """Test parsing hours lookback period"""
        result = self.blocker._parse_lookback_period("2h")
        self.assertEqual(result, timedelta(hours=2))

    def test_parse_lookback_period_days(self):
        """Test parsing days lookback period - THIS WAS THE BUG!"""
        result = self.blocker._parse_lookback_period("1d")
        self.assertEqual(result, timedelta(days=1))
        # Verify it's not None
        self.assertIsNotNone(result)

    def test_parse_lookback_period_invalid(self):
        """Test invalid lookback period raises error"""
        with self.assertRaises(ValueError):
            self.blocker._parse_lookback_period("invalid")
        with self.assertRaises(ValueError):
            self.blocker._parse_lookback_period("10x")

    def test_load_whitelist_no_file(self):
        """Test whitelist loading with no file"""
        result = self.blocker._load_whitelist(None)
        self.assertEqual(result, set())

    def test_load_whitelist_with_content(self):
        """Test whitelist loading with valid content"""
        mock_content = "1.2.3.4\n5.6.7.8\n# comment\n\n9.10.11.12\n"
        with patch('builtins.open', mock_open(read_data=mock_content)):
            result = self.blocker._load_whitelist("test.txt")
            self.assertEqual(result, {"1.2.3.4", "5.6.7.8", "9.10.11.12"})

    def test_load_whitelist_file_not_found(self):
        """Test whitelist loading with missing file"""
        with patch('builtins.open', side_effect=FileNotFoundError):
            result = self.blocker._load_whitelist("missing.txt")
            self.assertEqual(result, set())

    def test_deny_rule_range_calculation(self):
        """Test that deny_rule_range is calculated correctly with limit"""
        # start_rule=80, limit=20 should give range(80, 100)
        self.assertEqual(self.blocker.deny_rule_range, range(80, 100))

        # Test with different parameters
        with patch('auto_block_attackers.boto3.client'):
            blocker2 = NaclAutoBlocker(
                lb_name_pattern="test",
                region="us-east-1",
                lookback_str="1h",
                threshold=10,
                start_rule=50,
                limit=30,
                whitelist_file=None,
                aws_ip_ranges_file=None,
                dry_run=True,
                debug=False
            )
            self.assertEqual(blocker2.deny_rule_range, range(50, 80))

    def test_deny_rule_range_exceeds_100(self):
        """Test that deny_rule_range caps at 100"""
        with patch('auto_block_attackers.boto3.client'):
            blocker = NaclAutoBlocker(
                lb_name_pattern="test",
                region="us-east-1",
                lookback_str="1h",
                threshold=10,
                start_rule=90,
                limit=50,  # Would go to 140, but should cap at 100
                whitelist_file=None,
                aws_ip_ranges_file=None,
                dry_run=True,
                debug=False
            )
            self.assertEqual(blocker.deny_rule_range, range(90, 100))

    def test_generate_report_no_ips(self):
        """Test report generation with no IPs detected"""
        # This should not crash even with empty data
        try:
            self.blocker._generate_report(Counter(), set(), set())
        except Exception as e:
            self.fail(f"Report generation crashed with empty data: {e}")

    def test_generate_report_with_whitelisted_ips(self):
        """Test report generation with whitelisted IPs"""
        self.blocker.whitelist = {"1.2.3.4"}
        ip_counts = Counter({"1.2.3.4": 100, "5.6.7.8": 50})
        offenders = {"1.2.3.4", "5.6.7.8"}
        final_blocked = {"5.6.7.8"}

        # Should not crash
        try:
            self.blocker._generate_report(ip_counts, offenders, final_blocked)
        except Exception as e:
            self.fail(f"Report generation crashed: {e}")

    def test_generate_report_below_threshold_check(self):
        """Test the undefined variable fix in _generate_report"""
        # Testing the line that previously referenced undefined 'all_malicious_ips'
        ip_counts = Counter({"1.2.3.4": 5})  # Below threshold of 10

        # This should use ip_counts, not all_malicious_ips
        try:
            self.blocker._generate_report(ip_counts, set(), set())
        except NameError as e:
            self.fail(f"NameError in report: {e} - undefined variable still referenced")


class TestNACLFilterFix(unittest.TestCase):
    """Test the NACL filter fix for finding default NACL"""

    @patch('auto_block_attackers.boto3.client')
    def test_find_nacl_default_vpc_filters(self, mock_boto_client):
        """Test that NACL lookup uses correct filter format (Values not Value)"""
        mock_ec2 = MagicMock()
        mock_boto_client.return_value = mock_ec2

        # Setup: No explicit association, should fall back to default NACL
        mock_ec2.describe_network_acls.side_effect = [
            {"NetworkAcls": []},  # No explicit association
            {"NetworkAcls": [{"NetworkAclId": "acl-default123"}]}  # Default NACL
        ]

        blocker = NaclAutoBlocker(
            lb_name_pattern="test",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False
        )

        target_lbs = {
            "arn1": {
                "Name": "test-lb",
                "VpcId": "vpc-123",
                "SubnetIds": ["subnet-1"]
            }
        }

        result = blocker._find_nacl_for_subnets(target_lbs)

        # Verify the second call (default NACL lookup) uses correct format
        calls = mock_ec2.describe_network_acls.call_args_list
        self.assertEqual(len(calls), 2)

        # Check the second call (default NACL)
        second_call_kwargs = calls[1][1]
        filters = second_call_kwargs['Filters']

        # Both filters should use "Values" (list), not "Value" (string)
        for filter_dict in filters:
            self.assertIn("Values", filter_dict,
                         f"Filter should use 'Values' key: {filter_dict}")
            self.assertNotIn("Value", filter_dict,
                           f"Filter should NOT use 'Value' key: {filter_dict}")
            self.assertIsInstance(filter_dict["Values"], list,
                                f"Values should be a list: {filter_dict}")


class TestSlackIntegration(unittest.TestCase):
    """Test Slack notification integration"""

    @patch('auto_block_attackers.SlackClient')
    @patch('auto_block_attackers.boto3.client')
    def test_slack_initialization_with_credentials(self, mock_boto_client, mock_slack_client):
        """Test that Slack client is initialized when credentials provided"""
        blocker = NaclAutoBlocker(
            lb_name_pattern="test",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False,
            slack_token="xoxb-test-token",
            slack_channel="#security-alerts"
        )

        self.assertIsNotNone(blocker.slack_client)
        mock_slack_client.assert_called_once_with(token="xoxb-test-token", channel="#security-alerts")

    @patch('auto_block_attackers.boto3.client')
    def test_slack_initialization_without_credentials(self, mock_boto_client):
        """Test that Slack client is not initialized without credentials"""
        blocker = NaclAutoBlocker(
            lb_name_pattern="test",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False
        )

        self.assertIsNone(blocker.slack_client)

    @patch('auto_block_attackers.SlackClient')
    @patch('auto_block_attackers.boto3.client')
    def test_send_slack_notification_critical(self, mock_boto_client, mock_slack_client):
        """Test sending critical Slack notification"""
        mock_client_instance = MagicMock()
        mock_slack_client.return_value = mock_client_instance
        mock_client_instance.post_message.return_value = True

        blocker = NaclAutoBlocker(
            lb_name_pattern="test",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False,
            slack_token="xoxb-test",
            slack_channel="#alerts"
        )

        blocker._send_slack_notification("Test alert", is_critical=True)

        # Check that post_message was called with warning emoji
        mock_client_instance.post_message.assert_called_once()
        call_args = mock_client_instance.post_message.call_args
        self.assertIn(":warning:", call_args[1]["message"])

    @patch('auto_block_attackers.SlackClient')
    @patch('auto_block_attackers.boto3.client')
    def test_send_slack_notification_normal(self, mock_boto_client, mock_slack_client):
        """Test sending normal Slack notification"""
        mock_client_instance = MagicMock()
        mock_slack_client.return_value = mock_client_instance
        mock_client_instance.post_message.return_value = True

        blocker = NaclAutoBlocker(
            lb_name_pattern="test",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False,
            slack_token="xoxb-test",
            slack_channel="#alerts"
        )

        blocker._send_slack_notification("Test info", is_critical=False)

        # Check that post_message was called without warning emoji
        mock_client_instance.post_message.assert_called_once()
        call_args = mock_client_instance.post_message.call_args
        self.assertNotIn(":warning:", call_args[1]["message"])

    @patch('auto_block_attackers.boto3.client')
    def test_send_slack_notification_no_client(self, mock_boto_client):
        """Test sending notification when no Slack client configured"""
        blocker = NaclAutoBlocker(
            lb_name_pattern="test",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False
        )

        # Should not raise an error
        blocker._send_slack_notification("Test", is_critical=True)


class TestLogParsing(unittest.TestCase):
    """Test log parsing logic"""

    @patch('auto_block_attackers.boto3.client')
    def test_download_and_parse_log(self, mock_boto_client):
        """Test parsing ALB log format"""
        import gzip
        import io

        # Sample ALB log line with attack pattern
        log_content = (
            "http 2025-01-15T10:30:00.000Z app/test-lb/abc123 "
            "1.2.3.4:12345 10.0.0.1:80 0.001 0.002 0.003 200 200 100 200 "
            '"GET http://example.com:80/../../etc/passwd HTTP/1.1" '
            '"Mozilla/5.0" - - arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/test/xyz '
            '"Root=1-abc-123" "-" "-" 0 2025-01-15T10:30:00.000Z "forward" "-" "-" "-" "-" "-" "-" "-"\n'
        )

        # Compress the log content
        compressed = io.BytesIO()
        with gzip.open(compressed, 'wt') as f:
            f.write(log_content)
        compressed.seek(0)

        mock_s3 = MagicMock()
        mock_s3.get_object.return_value = {"Body": compressed}
        mock_boto_client.return_value = mock_s3

        blocker = NaclAutoBlocker(
            lb_name_pattern="test",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False
        )
        blocker.s3 = mock_s3

        result = blocker._download_and_parse_log("test-bucket", "test-key")

        # Should extract the IP address
        self.assertEqual(result, ["1.2.3.4"])


def run_tests():
    """Run all tests and return results"""
    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestHelperFunctions))
    suite.addTests(loader.loadTestsFromTestCase(TestNaclAutoBlocker))
    suite.addTests(loader.loadTestsFromTestCase(TestNACLFilterFix))
    suite.addTests(loader.loadTestsFromTestCase(TestSlackIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestLogParsing))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
