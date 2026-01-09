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
import logging

# Add parent directory to path to import the module
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auto_block_attackers import NaclAutoBlocker, is_valid_public_ipv4, is_valid_public_ip, ATTACK_PATTERNS


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

    def test_is_valid_public_ip_ipv4(self):
        """Test is_valid_public_ip with valid IPv4 addresses"""
        is_valid, version = is_valid_public_ip("8.8.8.8")
        self.assertTrue(is_valid)
        self.assertEqual(version, 4)

        is_valid, version = is_valid_public_ip("1.1.1.1")
        self.assertTrue(is_valid)
        self.assertEqual(version, 4)

    def test_is_valid_public_ip_ipv6(self):
        """Test is_valid_public_ip with valid IPv6 addresses"""
        # Google's public IPv6 DNS
        is_valid, version = is_valid_public_ip("2001:4860:4860::8888")
        self.assertTrue(is_valid)
        self.assertEqual(version, 6)

    def test_is_valid_public_ip_private_ipv4(self):
        """Test is_valid_public_ip rejects private IPv4"""
        is_valid, version = is_valid_public_ip("192.168.1.1")
        self.assertFalse(is_valid)
        self.assertEqual(version, 4)

        is_valid, version = is_valid_public_ip("10.0.0.1")
        self.assertFalse(is_valid)
        self.assertEqual(version, 4)

    def test_is_valid_public_ip_private_ipv6(self):
        """Test is_valid_public_ip rejects private/local IPv6"""
        # Link-local address
        is_valid, version = is_valid_public_ip("fe80::1")
        self.assertFalse(is_valid)
        self.assertEqual(version, 6)

        # Loopback
        is_valid, version = is_valid_public_ip("::1")
        self.assertFalse(is_valid)
        self.assertEqual(version, 6)

        # Unique local (fc00::/7)
        is_valid, version = is_valid_public_ip("fd00::1")
        self.assertFalse(is_valid)
        self.assertEqual(version, 6)

    def test_is_valid_public_ip_invalid(self):
        """Test is_valid_public_ip with invalid addresses"""
        is_valid, version = is_valid_public_ip("not_an_ip")
        self.assertFalse(is_valid)
        self.assertEqual(version, 0)

        is_valid, version = is_valid_public_ip("256.1.1.1")
        self.assertFalse(is_valid)
        self.assertEqual(version, 0)

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

        # Should extract the IP address with version (now returns tuples)
        self.assertEqual(result, [("1.2.3.4", 4)])


class TestWAFIntegration(unittest.TestCase):
    """Test AWS WAF IP Set integration"""

    @patch("boto3.client")
    def test_waf_disabled_by_default(self, mock_boto_client):
        """Test that WAF is disabled when no IP set name/ID is provided"""
        mock_ec2 = MagicMock()
        mock_elbv2 = MagicMock()
        mock_s3 = MagicMock()
        mock_sts = MagicMock()

        def client_factory(service, **kwargs):
            clients = {
                "ec2": mock_ec2,
                "elbv2": mock_elbv2,
                "s3": mock_s3,
                "sts": mock_sts,
            }
            return clients.get(service, MagicMock())

        mock_boto_client.side_effect = client_factory

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

        self.assertFalse(blocker._waf_enabled)
        self.assertIsNone(blocker.wafv2)

    @patch("boto3.client")
    def test_waf_enabled_with_ip_set_name(self, mock_boto_client):
        """Test that WAF is enabled when IP set name is provided"""
        mock_ec2 = MagicMock()
        mock_elbv2 = MagicMock()
        mock_s3 = MagicMock()
        mock_sts = MagicMock()
        mock_wafv2 = MagicMock()

        # Mock WAF IP set search (not found, and not creating)
        mock_wafv2.get_paginator.return_value.paginate.return_value = [{"IPSets": []}]

        def client_factory(service, **kwargs):
            clients = {
                "ec2": mock_ec2,
                "elbv2": mock_elbv2,
                "s3": mock_s3,
                "sts": mock_sts,
                "wafv2": mock_wafv2,
            }
            return clients.get(service, MagicMock())

        mock_boto_client.side_effect = client_factory

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
            waf_ip_set_name="test-blocklist",
        )

        # WAF will be disabled because the IP set wasn't found and create_waf_ip_set=False
        self.assertFalse(blocker._waf_enabled)

    @patch("boto3.client")
    def test_waf_find_existing_ip_set(self, mock_boto_client):
        """Test finding an existing WAF IP set by name"""
        mock_ec2 = MagicMock()
        mock_elbv2 = MagicMock()
        mock_s3 = MagicMock()
        mock_sts = MagicMock()
        mock_wafv2 = MagicMock()

        # Mock WAF IP set search (found)
        mock_wafv2.get_paginator.return_value.paginate.return_value = [
            {"IPSets": [{"Name": "test-blocklist", "Id": "abc-123"}]}
        ]
        mock_wafv2.get_ip_set.return_value = {
            "IPSet": {"Name": "test-blocklist", "Addresses": []},
            "LockToken": "lock-token-123"
        }

        def client_factory(service, **kwargs):
            clients = {
                "ec2": mock_ec2,
                "elbv2": mock_elbv2,
                "s3": mock_s3,
                "sts": mock_sts,
                "wafv2": mock_wafv2,
            }
            return clients.get(service, MagicMock())

        mock_boto_client.side_effect = client_factory

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
            waf_ip_set_name="test-blocklist",
        )

        self.assertTrue(blocker._waf_enabled)
        self.assertEqual(blocker._waf_ip_set_id, "abc-123")

    @patch("boto3.client")
    def test_waf_get_statistics(self, mock_boto_client):
        """Test WAF statistics when disabled"""
        mock_ec2 = MagicMock()
        mock_elbv2 = MagicMock()
        mock_s3 = MagicMock()
        mock_sts = MagicMock()

        def client_factory(service, **kwargs):
            clients = {
                "ec2": mock_ec2,
                "elbv2": mock_elbv2,
                "s3": mock_s3,
                "sts": mock_sts,
            }
            return clients.get(service, MagicMock())

        mock_boto_client.side_effect = client_factory

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

        stats = blocker._get_waf_statistics()
        self.assertFalse(stats["enabled"])

    @patch("boto3.client")
    def test_waf_cloudfront_uses_us_east_1(self, mock_boto_client):
        """Test that CloudFront scope WAF uses us-east-1 region"""
        mock_ec2 = MagicMock()
        mock_elbv2 = MagicMock()
        mock_s3 = MagicMock()
        mock_sts = MagicMock()
        mock_wafv2 = MagicMock()

        # Mock WAF IP set search (not found)
        mock_wafv2.get_paginator.return_value.paginate.return_value = [{"IPSets": []}]

        regions_used = []

        def client_factory(service, **kwargs):
            if service == "wafv2":
                regions_used.append(kwargs.get("region_name"))
            clients = {
                "ec2": mock_ec2,
                "elbv2": mock_elbv2,
                "s3": mock_s3,
                "sts": mock_sts,
                "wafv2": mock_wafv2,
            }
            return clients.get(service, MagicMock())

        mock_boto_client.side_effect = client_factory

        blocker = NaclAutoBlocker(
            lb_name_pattern="test",
            region="ap-southeast-2",  # Non-US region
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False,
            waf_ip_set_name="test-blocklist",
            waf_ip_set_scope="CLOUDFRONT",
        )

        # WAF client should have been created with us-east-1 for CloudFront
        self.assertIn("us-east-1", regions_used)


class TestLoggingAndMetrics(unittest.TestCase):
    """Test structured logging and CloudWatch metrics"""

    def test_json_formatter(self):
        """Test JsonFormatter produces valid JSON"""
        from auto_block_attackers import JsonFormatter
        import json as json_mod

        formatter = JsonFormatter()

        # Create a mock log record
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=10,
            msg="Test message",
            args=(),
            exc_info=None,
        )

        output = formatter.format(record)

        # Should be valid JSON
        parsed = json_mod.loads(output)
        self.assertEqual(parsed["level"], "INFO")
        self.assertEqual(parsed["message"], "Test message")
        self.assertIn("timestamp", parsed)

    def test_cloudwatch_metrics_disabled_by_default(self):
        """Test CloudWatch metrics are disabled when not requested"""
        from auto_block_attackers import CloudWatchMetrics

        metrics = CloudWatchMetrics(enabled=False)
        self.assertFalse(metrics.enabled)

        # Should not raise when putting metrics while disabled
        metrics.put_count("TestMetric", 1)
        metrics.put_timing("TestTiming", 1.0)
        metrics.flush()  # Should be a no-op

    def test_cloudwatch_metrics_dry_run(self):
        """Test CloudWatch metrics in dry run mode"""
        from auto_block_attackers import CloudWatchMetrics

        metrics = CloudWatchMetrics(enabled=True, dry_run=True)

        # Put some metrics
        metrics.put_count("TestMetric", 5, {"Region": "us-east-1"})
        metrics.put_timing("TestTiming", 1.5)

        # Flush should not raise in dry run mode
        metrics.flush()

        # Buffer should be cleared after flush
        self.assertEqual(len(metrics._metric_buffer), 0)

    @patch("boto3.client")
    def test_nacl_blocker_with_json_logging(self, mock_boto_client):
        """Test NaclAutoBlocker initializes with JSON logging"""
        mock_ec2 = MagicMock()
        mock_elbv2 = MagicMock()
        mock_s3 = MagicMock()
        mock_sts = MagicMock()

        def client_factory(service, **kwargs):
            clients = {
                "ec2": mock_ec2,
                "elbv2": mock_elbv2,
                "s3": mock_s3,
                "sts": mock_sts,
            }
            return clients.get(service, MagicMock())

        mock_boto_client.side_effect = client_factory

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
            json_logging=True,
        )

        # Verify metrics object is created
        self.assertIsNotNone(blocker._metrics)
        self.assertFalse(blocker._metrics.enabled)  # Not enabled by default

    @patch("boto3.client")
    def test_nacl_blocker_with_metrics_enabled(self, mock_boto_client):
        """Test NaclAutoBlocker initializes with CloudWatch metrics enabled"""
        mock_ec2 = MagicMock()
        mock_elbv2 = MagicMock()
        mock_s3 = MagicMock()
        mock_sts = MagicMock()
        mock_cloudwatch = MagicMock()

        def client_factory(service, **kwargs):
            clients = {
                "ec2": mock_ec2,
                "elbv2": mock_elbv2,
                "s3": mock_s3,
                "sts": mock_sts,
                "cloudwatch": mock_cloudwatch,
            }
            return clients.get(service, MagicMock())

        mock_boto_client.side_effect = client_factory

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
            enable_cloudwatch_metrics=True,
            cloudwatch_namespace="TestNamespace",
        )

        # Verify metrics object is created and enabled (though in dry_run)
        self.assertIsNotNone(blocker._metrics)


class TestMultiSignalDetection(unittest.TestCase):
    """Test multi-signal threat detection"""

    def test_threat_signals_initialization(self):
        """Test ThreatSignals class initialization"""
        from auto_block_attackers import ThreatSignals

        signals = ThreatSignals()
        self.assertEqual(signals.attack_pattern_hits, 0)
        self.assertEqual(signals.scanner_ua_hits, 0)
        self.assertEqual(signals.error_responses, 0)
        self.assertEqual(signals.total_requests, 0)
        self.assertEqual(len(signals.unique_paths), 0)

    def test_threat_signals_add_request(self):
        """Test adding requests to ThreatSignals"""
        from auto_block_attackers import ThreatSignals

        signals = ThreatSignals()
        signals.add_request(
            has_attack_pattern=True,
            has_scanner_ua=True,
            status_code=404,
            path="/admin.php",
        )

        self.assertEqual(signals.attack_pattern_hits, 1)
        self.assertEqual(signals.scanner_ua_hits, 1)
        self.assertEqual(signals.error_responses, 1)
        self.assertEqual(signals.total_requests, 1)
        self.assertIn("/admin.php", signals.unique_paths)

    def test_threat_signals_score_calculation(self):
        """Test threat score calculation"""
        from auto_block_attackers import ThreatSignals, DEFAULT_THREAT_SIGNALS_CONFIG

        signals = ThreatSignals()

        # Add 10 requests, all with attack patterns and from scanner
        for i in range(10):
            signals.add_request(
                has_attack_pattern=True,
                has_scanner_ua=True,
                status_code=404,
                path=f"/path{i}",
            )

        score, breakdown = signals.calculate_threat_score(DEFAULT_THREAT_SIGNALS_CONFIG)

        # Should have high score
        self.assertGreater(score, 60)
        self.assertIn("attack_pattern", breakdown)
        self.assertIn("scanner_ua", breakdown)

    def test_threat_signals_benign_traffic(self):
        """Test that benign traffic gets low threat score"""
        from auto_block_attackers import ThreatSignals, DEFAULT_THREAT_SIGNALS_CONFIG

        signals = ThreatSignals()

        # Add 100 normal requests (no attack patterns, no scanner UA)
        for i in range(100):
            signals.add_request(
                has_attack_pattern=False,
                has_scanner_ua=False,
                status_code=200,
                path="/",
            )

        is_malicious, score, _ = signals.is_malicious(DEFAULT_THREAT_SIGNALS_CONFIG)

        # Should NOT be considered malicious
        self.assertFalse(is_malicious)
        self.assertLess(score, DEFAULT_THREAT_SIGNALS_CONFIG["min_threat_score"])

    def test_scanner_user_agent_pattern(self):
        """Test SCANNER_USER_AGENTS pattern matching"""
        from auto_block_attackers import SCANNER_USER_AGENTS

        # Known scanner user agents
        scanner_agents = [
            "Mozilla/5.0 zgrab/0.x",
            "Nmap Scripting Engine",
            "sqlmap/1.5",
            "python-requests/2.25",
            "Go-http-client/1.1",
            "Nikto/2.1.6",
            "curl/7.68.0",
            "wget/1.20.3",
        ]

        for ua in scanner_agents:
            self.assertTrue(
                bool(SCANNER_USER_AGENTS.search(ua)),
                f"Should detect scanner UA: {ua}",
            )

        # Normal user agents
        normal_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
        ]

        for ua in normal_agents:
            self.assertFalse(
                bool(SCANNER_USER_AGENTS.search(ua)),
                f"Should not flag normal UA: {ua}",
            )

    @patch("boto3.client")
    def test_blocker_with_multi_signal_disabled(self, mock_boto_client):
        """Test NaclAutoBlocker with multi-signal detection disabled"""
        mock_ec2 = MagicMock()
        mock_elbv2 = MagicMock()
        mock_s3 = MagicMock()
        mock_sts = MagicMock()

        def client_factory(service, **kwargs):
            clients = {
                "ec2": mock_ec2,
                "elbv2": mock_elbv2,
                "s3": mock_s3,
                "sts": mock_sts,
            }
            return clients.get(service, MagicMock())

        mock_boto_client.side_effect = client_factory

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
            enable_multi_signal=False,
        )

        self.assertFalse(blocker._enable_multi_signal)


class TestEnhancedSlackNotifications(unittest.TestCase):
    """Test enhanced Slack notification functionality"""

    @patch('auto_block_attackers.boto3.client')
    def test_enhanced_slack_disabled_by_default(self, mock_boto_client):
        """Test that enhanced Slack is disabled by default"""
        blocker = NaclAutoBlocker(
            lb_name_pattern="test-*",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False,
        )

        self.assertFalse(blocker._enhanced_slack)

    @patch('auto_block_attackers.boto3.client')
    def test_enhanced_slack_enabled(self, mock_boto_client):
        """Test that enhanced Slack can be enabled"""
        blocker = NaclAutoBlocker(
            lb_name_pattern="test-*",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False,
            enhanced_slack=True,
        )

        self.assertTrue(blocker._enhanced_slack)

    @patch('auto_block_attackers.boto3.client')
    def test_tier_emoji_mapping(self, mock_boto_client):
        """Test tier to emoji mapping"""
        blocker = NaclAutoBlocker(
            lb_name_pattern="test-*",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False,
        )

        self.assertEqual(blocker._get_tier_emoji("critical"), ":rotating_light:")
        self.assertEqual(blocker._get_tier_emoji("high"), ":red_circle:")
        self.assertEqual(blocker._get_tier_emoji("medium"), ":large_orange_circle:")
        self.assertEqual(blocker._get_tier_emoji("low"), ":large_yellow_circle:")
        self.assertEqual(blocker._get_tier_emoji("minimal"), ":white_circle:")
        self.assertEqual(blocker._get_tier_emoji("unknown"), ":question:")

    @patch('auto_block_attackers.boto3.client')
    def test_format_duration(self, mock_boto_client):
        """Test duration formatting"""
        blocker = NaclAutoBlocker(
            lb_name_pattern="test-*",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False,
        )

        self.assertEqual(blocker._format_duration(72), "3d")
        self.assertEqual(blocker._format_duration(24), "1d")
        self.assertEqual(blocker._format_duration(12), "12h")
        self.assertEqual(blocker._format_duration(1), "1h")
        self.assertEqual(blocker._format_duration(0.5), "30m")

    @patch('auto_block_attackers.boto3.client')
    def test_enhanced_notification_skips_dry_run(self, mock_boto_client):
        """Test that enhanced notification skips in dry run mode"""
        blocker = NaclAutoBlocker(
            lb_name_pattern="test-*",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False,
            enhanced_slack=True,
            slack_token="test-token",
            slack_channel="test-channel",
        )

        # Should not raise any errors
        blocker._send_enhanced_slack_notification(
            new_offenders={"1.2.3.4"},
            final_blocked_ips={"1.2.3.4"},
            ip_counts=Counter({"1.2.3.4": 100}),
            initially_blocked_ips=set(),
            active_blocks={"1.2.3.4": {"tier": "high", "block_duration_hours": 72}},
        )

    @patch('auto_block_attackers.boto3.client')
    def test_enhanced_notification_skips_no_changes(self, mock_boto_client):
        """Test that enhanced notification skips when no changes"""
        blocker = NaclAutoBlocker(
            lb_name_pattern="test-*",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=False,
            debug=False,
            enhanced_slack=True,
            slack_token="test-token",
            slack_channel="test-channel",
        )

        # Mock the Slack client
        blocker.slack_client = MagicMock()
        blocker.slack_client.post_incident_notification = MagicMock(return_value="test_ts")

        # Call with no changes (same blocked IPs)
        blocker._send_enhanced_slack_notification(
            new_offenders=set(),
            final_blocked_ips={"1.2.3.4"},
            ip_counts=Counter({"1.2.3.4": 100}),
            initially_blocked_ips={"1.2.3.4"},  # Same as final
            active_blocks={"1.2.3.4": {"tier": "high", "block_duration_hours": 72}},
        )

        # Should not have called post_incident_notification
        blocker.slack_client.post_incident_notification.assert_not_called()


class TestAthenaIntegration(unittest.TestCase):
    """Test Athena integration for large-scale log analysis"""

    @patch('auto_block_attackers.boto3.client')
    def test_athena_disabled_by_default(self, mock_boto_client):
        """Test that Athena is disabled by default"""
        blocker = NaclAutoBlocker(
            lb_name_pattern="test-*",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False,
        )

        self.assertFalse(blocker._athena_enabled)

    @patch('auto_block_attackers.boto3.client')
    def test_athena_enabled_without_output_location(self, mock_boto_client):
        """Test that Athena is disabled if no output location provided"""
        blocker = NaclAutoBlocker(
            lb_name_pattern="test-*",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False,
            athena_enabled=True,
            athena_output_location=None,  # Missing!
        )

        # Should be disabled due to missing output location
        self.assertFalse(blocker._athena_enabled)

    @patch('auto_block_attackers.boto3.client')
    def test_athena_enabled_with_output_location(self, mock_boto_client):
        """Test that Athena is enabled when output location provided"""
        blocker = NaclAutoBlocker(
            lb_name_pattern="test-*",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False,
            athena_enabled=True,
            athena_output_location="s3://my-bucket/athena-results/",
        )

        self.assertTrue(blocker._athena_enabled)
        self.assertEqual(blocker._athena_database, "alb_logs")
        self.assertEqual(blocker._athena_output_location, "s3://my-bucket/athena-results/")

    @patch('auto_block_attackers.boto3.client')
    def test_athena_custom_database(self, mock_boto_client):
        """Test custom Athena database name"""
        blocker = NaclAutoBlocker(
            lb_name_pattern="test-*",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False,
            athena_enabled=True,
            athena_database="custom_logs_db",
            athena_output_location="s3://my-bucket/athena-results/",
        )

        self.assertEqual(blocker._athena_database, "custom_logs_db")

    @patch('auto_block_attackers.boto3.client')
    def test_athena_init_lazy(self, mock_boto_client):
        """Test that Athena client is lazily initialized"""
        blocker = NaclAutoBlocker(
            lb_name_pattern="test-*",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False,
            athena_enabled=True,
            athena_output_location="s3://my-bucket/athena-results/",
        )

        # Athena client should not be initialized yet
        self.assertIsNone(blocker._athena)

        # Initialize it
        blocker._init_athena()

        # Should now be initialized (the mock)
        mock_boto_client.assert_any_call("athena", region_name="us-east-1")

    @patch('auto_block_attackers.boto3.client')
    def test_process_logs_via_athena_disabled(self, mock_boto_client):
        """Test that _process_logs_via_athena returns None when disabled"""
        blocker = NaclAutoBlocker(
            lb_name_pattern="test-*",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False,
            athena_enabled=False,
        )

        result = blocker._process_logs_via_athena(
            "s3://bucket/logs/",
            lookback_hours=1.0,
        )

        self.assertIsNone(result)


class TestSlackClientEnhanced(unittest.TestCase):
    """Test enhanced SlackClient functionality"""

    def test_slack_severity_colors(self):
        """Test SlackSeverity enum has correct colors"""
        from slack_client import SlackSeverity

        self.assertEqual(SlackSeverity.INFO.value, "#36a64f")
        self.assertEqual(SlackSeverity.WARNING.value, "#f2c744")
        self.assertEqual(SlackSeverity.LOW.value, "#ff9933")
        self.assertEqual(SlackSeverity.MEDIUM.value, "#e07000")
        self.assertEqual(SlackSeverity.HIGH.value, "#cc0000")
        self.assertEqual(SlackSeverity.CRITICAL.value, "#8b0000")

    def test_tier_to_severity_mapping(self):
        """Test TIER_TO_SEVERITY mapping"""
        from slack_client import TIER_TO_SEVERITY, SlackSeverity

        self.assertEqual(TIER_TO_SEVERITY["minimal"], SlackSeverity.LOW)
        self.assertEqual(TIER_TO_SEVERITY["low"], SlackSeverity.LOW)
        self.assertEqual(TIER_TO_SEVERITY["medium"], SlackSeverity.MEDIUM)
        self.assertEqual(TIER_TO_SEVERITY["high"], SlackSeverity.HIGH)
        self.assertEqual(TIER_TO_SEVERITY["critical"], SlackSeverity.CRITICAL)

    def test_slack_block_add_header(self):
        """Test SlackBlock add_header method"""
        from slack_client import SlackBlock

        block = SlackBlock()
        block.add_header("Test Header")

        blocks = block.block
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["type"], "header")
        self.assertEqual(blocks[0]["text"]["text"], "Test Header")

    def test_slack_block_add_fields(self):
        """Test SlackBlock add_fields method"""
        from slack_client import SlackBlock

        block = SlackBlock()
        block.add_fields([("Label1", "Value1"), ("Label2", "Value2")])

        blocks = block.block
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["type"], "section")
        self.assertEqual(len(blocks[0]["fields"]), 2)

    def test_slack_block_add_actions(self):
        """Test SlackBlock add_actions method"""
        from slack_client import SlackBlock

        block = SlackBlock()
        block.add_actions([
            {"text": "Button 1", "action_id": "action1"},
            {"text": "Button 2", "action_id": "action2", "style": "danger"},
        ])

        blocks = block.block
        self.assertEqual(len(blocks), 1)
        self.assertEqual(blocks[0]["type"], "actions")
        self.assertEqual(len(blocks[0]["elements"]), 2)

    def test_slack_client_thread_tracking(self):
        """Test SlackClient thread tracking"""
        from slack_client import SlackClient

        client = SlackClient(token="test", channel="test-channel")

        # Initially no threads
        self.assertIsNone(client.get_thread_ts("incident_1"))

        # Set a thread
        client.set_thread_ts("incident_1", "1234567890.123456")
        self.assertEqual(client.get_thread_ts("incident_1"), "1234567890.123456")

        # Clear the thread
        client.clear_thread("incident_1")
        self.assertIsNone(client.get_thread_ts("incident_1"))


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
    suite.addTests(loader.loadTestsFromTestCase(TestWAFIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestLoggingAndMetrics))
    suite.addTests(loader.loadTestsFromTestCase(TestMultiSignalDetection))
    suite.addTests(loader.loadTestsFromTestCase(TestEnhancedSlackNotifications))
    suite.addTests(loader.loadTestsFromTestCase(TestAthenaIntegration))
    suite.addTests(loader.loadTestsFromTestCase(TestSlackClientEnhanced))

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
