#!/usr/bin/env python3
"""
Final validation tests for auto_block_attackers.py
Tests all critical paths, edge cases, and the AWS IP filtering feature
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import ipaddress
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auto_block_attackers import (
    NaclAutoBlocker,
    is_valid_public_ipv4,
    load_aws_ip_ranges,
    is_aws_ip,
    ATTACK_PATTERNS
)


class TestAWSIPFiltering(unittest.TestCase):
    """Test AWS IP range filtering functionality"""

    def test_load_aws_ip_ranges_none(self):
        """Test with no file path"""
        ipv4_result, ipv6_result = load_aws_ip_ranges(None)
        self.assertEqual(ipv4_result, set())
        self.assertEqual(ipv6_result, set())

    def test_load_aws_ip_ranges_missing_file(self):
        """Test with non-existent file"""
        ipv4_result, ipv6_result = load_aws_ip_ranges("/nonexistent/file.json")
        self.assertEqual(ipv4_result, set())
        self.assertEqual(ipv6_result, set())

    def test_load_aws_ip_ranges_valid(self):
        """Test loading valid AWS IP ranges"""
        import tempfile
        import json

        test_data = {
            "syncToken": "test",
            "createDate": "2025-01-01",
            "prefixes": [
                {"ip_prefix": "3.0.0.0/8", "region": "us-east-1", "service": "AMAZON"},
                {"ip_prefix": "52.0.0.0/8", "region": "us-west-1", "service": "AMAZON"},
                {"ip_prefix": "54.0.0.0/8", "region": "ap-southeast-2", "service": "AMAZON"},
            ]
        }

        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(test_data, f)
            temp_file = f.name

        try:
            ipv4_result, ipv6_result = load_aws_ip_ranges(temp_file)
            self.assertEqual(len(ipv4_result), 3)
            self.assertIsInstance(list(ipv4_result)[0], ipaddress.IPv4Network)
            # No IPv6 prefixes in test data
            self.assertEqual(len(ipv6_result), 0)
        finally:
            os.unlink(temp_file)

    def test_is_aws_ip_empty_networks(self):
        """Test AWS IP check with no networks loaded"""
        result = is_aws_ip("1.2.3.4", set())
        self.assertFalse(result)

    def test_is_aws_ip_match(self):
        """Test AWS IP check with matching IP"""
        networks = {ipaddress.ip_network("54.0.0.0/8")}
        # 54.252.193.112 is in 54.0.0.0/8
        result = is_aws_ip("54.252.193.112", networks)
        self.assertTrue(result)

    def test_is_aws_ip_no_match(self):
        """Test AWS IP check with non-matching IP"""
        networks = {ipaddress.ip_network("54.0.0.0/8")}
        # 203.0.113.1 is NOT in 54.0.0.0/8
        result = is_aws_ip("203.0.113.1", networks)
        self.assertFalse(result)

    def test_is_aws_ip_invalid_ip(self):
        """Test AWS IP check with invalid IP"""
        networks = {ipaddress.ip_network("54.0.0.0/8")}
        result = is_aws_ip("not_an_ip", networks)
        self.assertFalse(result)


class TestNACLRuleManagement(unittest.TestCase):
    """Test NACL rule management logic"""

    @patch('auto_block_attackers.boto3.client')
    def test_deny_rule_range_calculation(self, mock_boto_client):
        """Test that deny_rule_range is calculated correctly"""
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

        # Should be range(80, 100) - capped at 100
        self.assertEqual(list(blocker.deny_rule_range), list(range(80, 100)))

    @patch('auto_block_attackers.boto3.client')
    def test_deny_rule_range_exceeds_100(self, mock_boto_client):
        """Test that deny_rule_range caps at 100"""
        blocker = NaclAutoBlocker(
            lb_name_pattern="test",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=90,
            limit=50,  # Would go to 140
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False
        )

        # Should be capped at 100
        self.assertEqual(list(blocker.deny_rule_range), list(range(90, 100)))

    @patch('auto_block_attackers.boto3.client')
    def test_filtering_order(self, mock_boto_client):
        """Test that filtering applies whitelist, AWS IPs, and threshold correctly"""
        import tempfile
        import json

        # Create AWS IP ranges file
        aws_data = {
            "prefixes": [
                {"ip_prefix": "54.0.0.0/8", "region": "ap-southeast-2", "service": "AMAZON"}
            ]
        }
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(aws_data, f)
            aws_file = f.name

        # Create whitelist file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("1.2.3.4\n")
            whitelist_file = f.name

        try:
            blocker = NaclAutoBlocker(
                lb_name_pattern="test",
                region="us-east-1",
                lookback_str="1h",
                threshold=10,
                start_rule=80,
                limit=20,
                whitelist_file=whitelist_file,
                aws_ip_ranges_file=aws_file,
                dry_run=True,
                debug=False
            )

            # Simulate IP counts
            ip_counts = Counter({
                "1.2.3.4": 100,      # Whitelisted
                "54.252.193.112": 50,  # AWS IP
                "203.0.113.42": 30,  # Real attacker
                "198.51.100.17": 5,  # Below threshold
            })

            # Apply filtering logic (from run() method)
            offenders = {
                ip
                for ip, count in ip_counts.items()
                if count >= blocker.threshold
                and ip not in blocker.whitelist
                and not is_aws_ip(ip, blocker.aws_networks)
            }

            # Only 203.0.113.42 should be in offenders
            self.assertEqual(offenders, {"203.0.113.42"})
            self.assertNotIn("1.2.3.4", offenders)  # Whitelisted
            self.assertNotIn("54.252.193.112", offenders)  # AWS IP
            self.assertNotIn("198.51.100.17", offenders)  # Below threshold

        finally:
            os.unlink(aws_file)
            os.unlink(whitelist_file)


class TestInputValidation(unittest.TestCase):
    """Test input validation and edge cases"""

    def test_is_valid_public_ipv4_private_ips(self):
        """Test that private IPs are rejected"""
        private_ips = [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
        ]
        for ip in private_ips:
            self.assertFalse(is_valid_public_ipv4(ip), f"{ip} should be rejected as private")

    def test_is_valid_public_ipv4_public_ips(self):
        """Test that public IPs are accepted"""
        public_ips = [
            "8.8.8.8",           # Google DNS
            "1.1.1.1",           # Cloudflare DNS
            "54.252.193.112",    # AWS IP
            "151.101.1.140",     # Fastly CDN
        ]
        for ip in public_ips:
            self.assertTrue(is_valid_public_ipv4(ip), f"{ip} should be accepted as public")

    def test_is_valid_public_ipv4_reserved_ips(self):
        """Test that reserved IPs are rejected"""
        reserved_ips = [
            "203.0.113.1",    # TEST-NET-3 (RFC 5737)
            "198.51.100.1",   # TEST-NET-2 (RFC 5737)
            "192.0.2.1",      # TEST-NET-1 (RFC 5737)
            "224.0.0.1",      # Multicast
            "169.254.1.1",    # Link-local
        ]
        for ip in reserved_ips:
            self.assertFalse(is_valid_public_ipv4(ip), f"{ip} should be rejected as reserved")

    def test_attack_patterns_match(self):
        """Test that attack patterns match expected strings"""
        malicious_samples = [
            "GET /../../etc/passwd HTTP/1.1",
            "POST /.env HTTP/1.1",
            "GET /.git/config HTTP/1.1",
            "GET /wp-login.php HTTP/1.1",
            "<script>alert(1)</script>",
        ]
        for sample in malicious_samples:
            self.assertIsNotNone(
                ATTACK_PATTERNS.search(sample),
                f"Pattern should match: {sample}"
            )

    def test_attack_patterns_no_false_positives(self):
        """Test that benign requests don't match"""
        benign_samples = [
            "GET / HTTP/1.1",
            "GET /api/users HTTP/1.1",
            "POST /login HTTP/1.1",
            "GET /health HTTP/1.1",
        ]
        for sample in benign_samples:
            self.assertIsNone(
                ATTACK_PATTERNS.search(sample),
                f"Pattern should NOT match: {sample}"
            )


class TestLookbackParsing(unittest.TestCase):
    """Test lookback period parsing"""

    @patch('auto_block_attackers.boto3.client')
    def test_parse_lookback_minutes(self, mock_boto_client):
        """Test parsing minutes"""
        from datetime import timedelta
        blocker = NaclAutoBlocker(
            lb_name_pattern="test",
            region="us-east-1",
            lookback_str="30m",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False
        )
        self.assertEqual(blocker.lookback_delta, timedelta(minutes=30))

    @patch('auto_block_attackers.boto3.client')
    def test_parse_lookback_hours(self, mock_boto_client):
        """Test parsing hours"""
        from datetime import timedelta
        blocker = NaclAutoBlocker(
            lb_name_pattern="test",
            region="us-east-1",
            lookback_str="2h",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False
        )
        self.assertEqual(blocker.lookback_delta, timedelta(hours=2))

    @patch('auto_block_attackers.boto3.client')
    def test_parse_lookback_days(self, mock_boto_client):
        """Test parsing days"""
        from datetime import timedelta
        blocker = NaclAutoBlocker(
            lb_name_pattern="test",
            region="us-east-1",
            lookback_str="1d",
            threshold=10,
            start_rule=80,
            limit=20,
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False
        )
        self.assertEqual(blocker.lookback_delta, timedelta(days=1))
        # Verify it's not None (the original bug!)
        self.assertIsNotNone(blocker.lookback_delta)


def run_all_tests():
    """Run all validation tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestAWSIPFiltering))
    suite.addTests(loader.loadTestsFromTestCase(TestNACLRuleManagement))
    suite.addTests(loader.loadTestsFromTestCase(TestInputValidation))
    suite.addTests(loader.loadTestsFromTestCase(TestLookbackParsing))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
