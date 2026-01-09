#!/usr/bin/env python3
"""
Integration tests for auto_block_attackers.py
Tests complete workflows and edge cases
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timezone, timedelta
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auto_block_attackers import NaclAutoBlocker


class TestIntegrationScenarios(unittest.TestCase):
    """Test complete end-to-end scenarios"""

    @patch('auto_block_attackers.boto3.client')
    def test_scenario_no_load_balancers_found(self, mock_boto_client):
        """Test handling when no LBs match the pattern"""
        mock_elbv2 = MagicMock()
        mock_ec2 = MagicMock()

        def get_client(service, **kwargs):
            if service == 'elbv2':
                return mock_elbv2
            return mock_ec2

        mock_boto_client.side_effect = get_client

        # Return empty list of load balancers
        mock_elbv2.get_paginator.return_value.paginate.return_value = [
            {"LoadBalancers": []}
        ]

        blocker = NaclAutoBlocker(
            lb_name_pattern="nonexistent-*",
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

        # Should handle gracefully without crashing
        try:
            blocker.run()
        except Exception as e:
            self.fail(f"Script crashed with no LBs: {e}")

    @patch('auto_block_attackers.boto3.client')
    def test_scenario_lb_without_logging(self, mock_boto_client):
        """Test handling when LB has logging disabled"""
        mock_elbv2 = MagicMock()

        def get_client(service, **kwargs):
            if service == 'elbv2':
                return mock_elbv2
            return MagicMock()

        mock_boto_client.side_effect = get_client

        # Return LB without logging enabled
        mock_elbv2.get_paginator.return_value.paginate.return_value = [
            {
                "LoadBalancers": [{
                    "LoadBalancerName": "test-lb",
                    "LoadBalancerArn": "arn:aws:elasticloadbalancing:us-east-1:123:loadbalancer/app/test/abc",
                    "VpcId": "vpc-123",
                    "AvailabilityZones": [{"SubnetId": "subnet-1"}]
                }]
            }
        ]

        mock_elbv2.describe_load_balancer_attributes.return_value = {
            "Attributes": [
                {"Key": "access_logs.s3.enabled", "Value": "false"}
            ]
        }

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
            debug=False
        )

        # Should handle gracefully
        try:
            blocker.run()
        except Exception as e:
            self.fail(f"Script crashed with LB without logging: {e}")

    @patch('auto_block_attackers.boto3.client')
    def test_scenario_multiple_vpcs_error(self, mock_boto_client):
        """Test that script errors when LBs span multiple VPCs"""
        mock_elbv2 = MagicMock()

        def get_client(service, **kwargs):
            if service == 'elbv2':
                return mock_elbv2
            return MagicMock()

        mock_boto_client.side_effect = get_client

        # Return LBs in different VPCs
        mock_elbv2.get_paginator.return_value.paginate.return_value = [
            {
                "LoadBalancers": [
                    {
                        "LoadBalancerName": "test-lb-1",
                        "LoadBalancerArn": "arn1",
                        "VpcId": "vpc-111",
                        "AvailabilityZones": [{"SubnetId": "subnet-1"}]
                    },
                    {
                        "LoadBalancerName": "test-lb-2",
                        "LoadBalancerArn": "arn2",
                        "VpcId": "vpc-222",  # Different VPC!
                        "AvailabilityZones": [{"SubnetId": "subnet-2"}]
                    }
                ]
            }
        ]

        # Both have logging enabled
        mock_elbv2.describe_load_balancer_attributes.return_value = {
            "Attributes": [
                {"Key": "access_logs.s3.enabled", "Value": "true"},
                {"Key": "access_logs.s3.bucket", "Value": "test-bucket"},
                {"Key": "access_logs.s3.prefix", "Value": "logs"}
            ]
        }

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
            debug=False
        )

        # Should detect and handle the multi-VPC scenario
        try:
            blocker.run()
        except Exception as e:
            self.fail(f"Script crashed unexpectedly: {e}")

    @patch('auto_block_attackers.boto3.client')
    def test_scenario_all_ips_whitelisted(self, mock_boto_client):
        """Test scenario where all detected IPs are whitelisted"""
        import tempfile

        # Create temporary whitelist file
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
            f.write("1.2.3.4\n5.6.7.8\n")
            whitelist_path = f.name

        try:
            blocker = NaclAutoBlocker(
                lb_name_pattern="test-*",
                region="us-east-1",
                lookback_str="1h",
                threshold=10,
                start_rule=80,
                limit=20,
                whitelist_file=whitelist_path,
                aws_ip_ranges_file=None,
                dry_run=True,
                debug=False
            )

            # Simulate detection where all IPs are whitelisted
            from collections import Counter
            ip_counts = Counter({"1.2.3.4": 100, "5.6.7.8": 200})
            offenders = set()  # Empty because all are whitelisted

            # Should generate report without crashing
            blocker._generate_report(ip_counts, offenders, set())

        finally:
            os.unlink(whitelist_path)

    @patch('auto_block_attackers.boto3.client')
    def test_rule_range_boundary_conditions(self, mock_boto_client):
        """Test rule range calculation at boundaries"""
        # Test case 1: Normal range
        blocker1 = NaclAutoBlocker(
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
        self.assertEqual(list(blocker1.deny_rule_range), list(range(80, 100)))

        # Test case 2: Exactly at boundary (100)
        blocker2 = NaclAutoBlocker(
            lb_name_pattern="test",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=99,
            limit=10,  # Should cap at 100
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False
        )
        self.assertEqual(list(blocker2.deny_rule_range), list(range(99, 100)))

        # Test case 3: Would exceed 100
        blocker3 = NaclAutoBlocker(
            lb_name_pattern="test",
            region="us-east-1",
            lookback_str="1h",
            threshold=10,
            start_rule=85,
            limit=50,  # Would go to 135, but capped
            whitelist_file=None,
            aws_ip_ranges_file=None,
            dry_run=True,
            debug=False
        )
        self.assertEqual(list(blocker3.deny_rule_range), list(range(85, 100)))

    @patch('auto_block_attackers.boto3.client')
    def test_lookback_period_edge_cases(self, mock_boto_client):
        """Test various lookback period formats"""
        test_cases = [
            ("1m", timedelta(minutes=1)),
            ("60m", timedelta(minutes=60)),
            ("1h", timedelta(hours=1)),
            ("24h", timedelta(hours=24)),
            ("1d", timedelta(days=1)),
            ("7d", timedelta(days=7)),
            ("365d", timedelta(days=365)),
        ]

        for lookback_str, expected_delta in test_cases:
            blocker = NaclAutoBlocker(
                lb_name_pattern="test",
                region="us-east-1",
                lookback_str=lookback_str,
                threshold=10,
                start_rule=80,
                limit=20,
                whitelist_file=None,
            aws_ip_ranges_file=None,
                dry_run=True,
                debug=False
            )
            self.assertEqual(
                blocker.lookback_delta,
                expected_delta,
                f"Failed for lookback_str: {lookback_str}"
            )

    @patch('auto_block_attackers.boto3.client')
    def test_manage_rule_limit_empty_slots(self, mock_boto_client):
        """Test adding rules when slots are available"""
        mock_ec2 = MagicMock()

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
        blocker.ec2 = mock_ec2

        # Mock empty NACL (all slots available)
        mock_ec2.describe_network_acls.return_value = {
            "NetworkAcls": [{
                "NetworkAclId": "acl-123",
                "Entries": []
            }]
        }

        from collections import Counter
        ips_to_add = {"1.2.3.4", "5.6.7.8", "9.10.11.12"}
        ip_counts = Counter({"1.2.3.4": 100, "5.6.7.8": 80, "9.10.11.12": 60})

        # Should add all IPs without error
        try:
            blocker._manage_rule_limit_and_add("acl-123", ips_to_add, ip_counts)
        except Exception as e:
            self.fail(f"Failed to add rules to empty NACL: {e}")


def run_integration_tests():
    """Run all integration tests"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestIntegrationScenarios)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_integration_tests()
    sys.exit(0 if success else 1)
