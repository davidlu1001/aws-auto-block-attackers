#!/usr/bin/env python3
"""
Test the timestamp filtering fix
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta, timezone
import gzip
import io
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from auto_block_attackers import NaclAutoBlocker


class TestTimestampFiltering(unittest.TestCase):
    """Test that requests are filtered by their actual timestamp"""

    @patch('auto_block_attackers.boto3.client')
    def test_log_file_entries_are_all_processed(self, mock_boto_client):
        """Test that all entries in a log file are processed.

        Note: The lookback window filtering happens at the S3 file level
        (via ListObjectsV2), not at the individual log entry level. All
        entries within a fetched log file are processed regardless of
        their individual timestamps.
        """

        # Create a log with requests from different times
        now = datetime.now(timezone.utc)
        old_time = now - timedelta(hours=2)  # 2 hours ago
        recent_time = now - timedelta(minutes=30)  # 30 mins ago

        log_content = f"""http {old_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')} app/test-lb/abc123 1.2.3.4:12345 10.0.0.1:80 0.001 0.002 0.003 200 200 100 200 "GET http://example.com:80/../../etc/passwd HTTP/1.1" "Mozilla/5.0" - - arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/test/xyz "Root=1-abc-123" "-" "-" 0 {old_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')} "forward" "-" "-" "-" "-" "-" "-" "-"
http {recent_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')} app/test-lb/abc123 5.6.7.8:12345 10.0.0.1:80 0.001 0.002 0.003 200 200 100 200 "GET http://example.com:80/../../etc/passwd HTTP/1.1" "Mozilla/5.0" - - arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/test/xyz "Root=1-abc-123" "-" "-" 0 {recent_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')} "forward" "-" "-" "-" "-" "-" "-" "-"
"""

        # Compress the log
        compressed = io.BytesIO()
        with gzip.open(compressed, 'wt') as f:
            f.write(log_content)
        compressed.seek(0)

        mock_s3 = MagicMock()
        mock_s3.get_object.return_value = {"Body": compressed}

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

        # Extract just the IPs from the tuples (ip, ip_version)
        result_ips = [ip for ip, _ in result]

        # Both IPs should be processed (filtering happens at file level, not entry level)
        self.assertEqual(len(result_ips), 2, f"Expected 2 IPs, got: {result_ips}")
        self.assertIn("1.2.3.4", result_ips)
        self.assertIn("5.6.7.8", result_ips)

    @patch('auto_block_attackers.boto3.client')
    def test_processes_all_requests_if_within_window(self, mock_boto_client):
        """Test that all requests within window are processed"""

        now = datetime.now(timezone.utc)
        time1 = now - timedelta(minutes=10)
        time2 = now - timedelta(minutes=20)
        time3 = now - timedelta(minutes=30)

        log_content = f"""http {time1.strftime('%Y-%m-%dT%H:%M:%S.%fZ')} app/test-lb/abc123 1.1.1.1:12345 10.0.0.1:80 0.001 0.002 0.003 200 200 100 200 "GET http://example.com:80/../../etc/passwd HTTP/1.1" "Mozilla/5.0" - - arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/test/xyz "Root=1-abc-123" "-" "-" 0 {time1.strftime('%Y-%m-%dT%H:%M:%S.%fZ')} "forward" "-" "-" "-" "-" "-" "-" "-"
http {time2.strftime('%Y-%m-%dT%H:%M:%S.%fZ')} app/test-lb/abc123 2.2.2.2:12345 10.0.0.1:80 0.001 0.002 0.003 200 200 100 200 "GET http://example.com:80/../../etc/passwd HTTP/1.1" "Mozilla/5.0" - - arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/test/xyz "Root=1-abc-123" "-" "-" 0 {time2.strftime('%Y-%m-%dT%H:%M:%S.%fZ')} "forward" "-" "-" "-" "-" "-" "-" "-"
http {time3.strftime('%Y-%m-%dT%H:%M:%S.%fZ')} app/test-lb/abc123 3.3.3.3:12345 10.0.0.1:80 0.001 0.002 0.003 200 200 100 200 "GET http://example.com:80/../../etc/passwd HTTP/1.1" "Mozilla/5.0" - - arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/test/xyz "Root=1-abc-123" "-" "-" 0 {time3.strftime('%Y-%m-%dT%H:%M:%S.%fZ')} "forward" "-" "-" "-" "-" "-" "-" "-"
"""

        compressed = io.BytesIO()
        with gzip.open(compressed, 'wt') as f:
            f.write(log_content)
        compressed.seek(0)

        mock_s3 = MagicMock()
        mock_s3.get_object.return_value = {"Body": compressed}

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

        # Extract just the IPs from the tuples (ip, ip_version)
        result_ips = [ip for ip, _ in result]

        # All three should be included
        self.assertEqual(len(result_ips), 3, f"Expected 3 IPs, got {len(result_ips)}: {result_ips}")
        self.assertIn("1.1.1.1", result_ips)
        self.assertIn("2.2.2.2", result_ips)
        self.assertIn("3.3.3.3", result_ips)

    @patch('auto_block_attackers.boto3.client')
    def test_handles_malformed_timestamps_gracefully(self, mock_boto_client):
        """Test that lines with bad timestamps are still processed"""

        now = datetime.now(timezone.utc)
        recent_time = now - timedelta(minutes=30)

        log_content = f"""http MALFORMED_TIMESTAMP app/test-lb/abc123 1.2.3.4:12345 10.0.0.1:80 0.001 0.002 0.003 200 200 100 200 "GET http://example.com:80/../../etc/passwd HTTP/1.1" "Mozilla/5.0" - - arn:aws:elasticloadbalancing:us-east-1:123:targetgroup/test/xyz "Root=1-abc-123" "-" "-" 0 {recent_time.strftime('%Y-%m-%dT%H:%M:%S.%fZ')} "forward" "-" "-" "-" "-" "-" "-" "-"
"""

        compressed = io.BytesIO()
        with gzip.open(compressed, 'wt') as f:
            f.write(log_content)
        compressed.seek(0)

        mock_s3 = MagicMock()
        mock_s3.get_object.return_value = {"Body": compressed}

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

        # Should not crash, should process the line anyway
        try:
            result = blocker._download_and_parse_log("test-bucket", "test-key")
            # Extract just the IPs from the tuples (ip, ip_version)
            result_ips = [ip for ip, _ in result]
            # Should still detect the malicious pattern
            self.assertIn("1.2.3.4", result_ips,
                         "Should process lines with malformed timestamps")
        except Exception as e:
            self.fail(f"Should handle malformed timestamps gracefully: {e}")


def run_tests():
    """Run timestamp filtering tests"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestTimestampFiltering)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
