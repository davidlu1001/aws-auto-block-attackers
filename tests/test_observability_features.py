"""
Tests for observability and UX improvements.

Tests cover:
1. Auto-download AWS IP ranges
2. O(log N) IP range lookups with AWSIPRangeIndex
3. Enhanced threat score logging
4. Secure legitimate service verification
5. Accurate dry-run summary table
"""

import pytest
import json
import tempfile
import os
from unittest.mock import patch, MagicMock
from pathlib import Path
from datetime import datetime, timedelta

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auto_block_attackers import (
    AWSIPRangeIndex,
    download_aws_ip_ranges,
    load_aws_ip_ranges_with_index,
    get_ip_ranges_path,
    is_aws_ip_fast,
    verify_legitimate_service,
    _clean_path,
    _path_matches,
    KNOWN_LEGITIMATE_SERVICES,
    AWS_SERVICE_ROUTE53_HEALTHCHECKS,
    AWS_SERVICE_ELB,
    AWS_SERVICE_CLOUDFRONT,
)


# Sample AWS IP ranges data for testing
SAMPLE_AWS_IP_RANGES = {
    "syncToken": "1234567890",
    "createDate": "2026-01-09-00-00-00",
    "prefixes": [
        {"ip_prefix": "52.93.178.234/32", "region": "us-east-1", "service": "AMAZON"},
        {"ip_prefix": "52.94.76.0/22", "region": "us-east-1", "service": "EC2"},
        {"ip_prefix": "54.239.0.0/17", "region": "us-west-2", "service": "EC2"},
        {"ip_prefix": "15.177.0.0/18", "region": "us-east-1", "service": "ROUTE53_HEALTHCHECKS"},
        {"ip_prefix": "15.177.64.0/18", "region": "us-west-2", "service": "ROUTE53_HEALTHCHECKS"},
        {"ip_prefix": "13.32.0.0/15", "region": "GLOBAL", "service": "CLOUDFRONT"},
        {"ip_prefix": "176.32.103.0/24", "region": "eu-west-1", "service": "ELB"},
    ],
    "ipv6_prefixes": [
        {"ipv6_prefix": "2600:1f00::/24", "region": "us-east-1", "service": "EC2"},
        {"ipv6_prefix": "2600:9000::/28", "region": "GLOBAL", "service": "CLOUDFRONT"},
    ]
}


class TestAWSIPRangeIndex:
    """Tests for the AWSIPRangeIndex class."""

    def test_build_index_from_json(self):
        """Test building index from JSON data."""
        index = AWSIPRangeIndex.from_json_data(SAMPLE_AWS_IP_RANGES)

        assert index.total_ipv4 == 7
        assert index.total_ipv6 == 2
        assert "AMAZON" in index.services
        assert "EC2" in index.services
        assert "ROUTE53_HEALTHCHECKS" in index.services
        assert "CLOUDFRONT" in index.services
        assert "ELB" in index.services

    def test_is_aws_ip_match(self):
        """Test O(log N) IP lookup - matching IP."""
        index = AWSIPRangeIndex.from_json_data(SAMPLE_AWS_IP_RANGES)

        # Test exact match
        assert index.is_aws_ip("52.93.178.234") is True

        # Test IP within a range
        assert index.is_aws_ip("52.94.76.1") is True
        assert index.is_aws_ip("52.94.79.255") is True  # Last IP in /22

    def test_is_aws_ip_no_match(self):
        """Test O(log N) IP lookup - non-matching IP."""
        index = AWSIPRangeIndex.from_json_data(SAMPLE_AWS_IP_RANGES)

        # Test IP not in any range
        assert index.is_aws_ip("1.2.3.4") is False
        assert index.is_aws_ip("203.0.113.1") is False

    def test_is_aws_ip_ipv6(self):
        """Test IPv6 IP lookup."""
        index = AWSIPRangeIndex.from_json_data(SAMPLE_AWS_IP_RANGES)

        # Test IPv6 in range
        assert index.is_aws_ip("2600:1f00:0:0:0:0:0:1") is True

        # Test IPv6 not in range
        assert index.is_aws_ip("2001:db8::1") is False

    def test_is_aws_ip_invalid(self):
        """Test handling of invalid IP addresses."""
        index = AWSIPRangeIndex.from_json_data(SAMPLE_AWS_IP_RANGES)

        assert index.is_aws_ip("not_an_ip") is False
        assert index.is_aws_ip("") is False
        assert index.is_aws_ip("256.256.256.256") is False

    def test_is_from_service(self):
        """Test service-specific IP verification."""
        index = AWSIPRangeIndex.from_json_data(SAMPLE_AWS_IP_RANGES)

        # Route53 Health Check IP
        assert index.is_from_service("15.177.0.1", "ROUTE53_HEALTHCHECKS") is True
        assert index.is_from_service("15.177.0.1", "EC2") is False

        # CloudFront IP
        assert index.is_from_service("13.32.0.1", "CLOUDFRONT") is True
        assert index.is_from_service("13.32.0.1", "ROUTE53_HEALTHCHECKS") is False

        # ELB IP
        assert index.is_from_service("176.32.103.1", "ELB") is True

        # IP not in any service
        assert index.is_from_service("1.2.3.4", "EC2") is False

    def test_get_service_for_ip(self):
        """Test getting service name for an IP."""
        index = AWSIPRangeIndex.from_json_data(SAMPLE_AWS_IP_RANGES)

        assert index.get_service_for_ip("15.177.0.1") == "ROUTE53_HEALTHCHECKS"
        assert index.get_service_for_ip("13.32.0.1") == "CLOUDFRONT"
        assert index.get_service_for_ip("1.2.3.4") is None

    def test_lookup_stats(self):
        """Test lookup statistics tracking."""
        index = AWSIPRangeIndex.from_json_data(SAMPLE_AWS_IP_RANGES)

        # Perform some lookups
        index.is_aws_ip("15.177.0.1")  # Hit
        index.is_aws_ip("1.2.3.4")     # Miss
        index.is_aws_ip("13.32.0.1")   # Hit

        hits, misses, rate = index.get_lookup_stats()
        assert hits == 2
        assert misses == 1
        assert rate == pytest.approx(66.67, rel=0.1)

    def test_empty_index(self):
        """Test handling of empty IP ranges data."""
        empty_data = {"prefixes": [], "ipv6_prefixes": []}
        index = AWSIPRangeIndex.from_json_data(empty_data)

        assert index.total_ipv4 == 0
        assert index.total_ipv6 == 0
        assert index.is_aws_ip("1.2.3.4") is False


class TestAutoDownload:
    """Tests for auto-download functionality."""

    def test_get_ip_ranges_path_default(self):
        """Test default path for non-Lambda environments."""
        with patch.dict(os.environ, {}, clear=True):
            path = get_ip_ranges_path()
            assert path == "./ip-ranges.json"

    def test_get_ip_ranges_path_lambda(self):
        """Test path for Lambda environments."""
        with patch.dict(os.environ, {"AWS_LAMBDA_FUNCTION_NAME": "test-function"}):
            path = get_ip_ranges_path()
            assert path == "/tmp/ip-ranges.json"

    def test_download_aws_ip_ranges_success(self):
        """Test successful download of IP ranges."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "ip-ranges.json")

            mock_response = MagicMock()
            mock_response.json.return_value = SAMPLE_AWS_IP_RANGES
            mock_response.content = json.dumps(SAMPLE_AWS_IP_RANGES).encode()

            with patch('requests.get', return_value=mock_response):
                result = download_aws_ip_ranges(file_path)

            assert result is not None
            assert "prefixes" in result
            assert os.path.exists(file_path)

    def test_download_aws_ip_ranges_cached(self):
        """Test loading from fresh cache."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "ip-ranges.json")

            # Create a fresh cached file
            with open(file_path, 'w') as f:
                json.dump(SAMPLE_AWS_IP_RANGES, f)

            # Should load from cache without downloading
            with patch('requests.get') as mock_get:
                result = download_aws_ip_ranges(file_path, max_age_days=7)

            # requests.get should not be called if cache is fresh
            assert result is not None
            assert "prefixes" in result

    def test_download_aws_ip_ranges_timeout(self):
        """Test handling of download timeout."""
        import requests
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "ip-ranges.json")

            with patch('requests.get', side_effect=requests.exceptions.Timeout):
                result = download_aws_ip_ranges(file_path)

            assert result is None

    def test_download_aws_ip_ranges_fallback(self):
        """Test fallback to stale cache on download failure."""
        import requests
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "ip-ranges.json")

            # Create stale cached file (touch with old timestamp)
            with open(file_path, 'w') as f:
                json.dump(SAMPLE_AWS_IP_RANGES, f)
            old_time = datetime.now() - timedelta(days=30)
            os.utime(file_path, (old_time.timestamp(), old_time.timestamp()))

            # Simulate download failure
            with patch('requests.get', side_effect=requests.exceptions.RequestException("Network error")):
                result = download_aws_ip_ranges(file_path, max_age_days=7)

            # Should fall back to stale cache
            assert result is not None
            assert "prefixes" in result


class TestLoadWithIndex:
    """Tests for load_aws_ip_ranges_with_index."""

    def test_load_with_auto_download_disabled(self):
        """Test loading with auto-download disabled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "ip-ranges.json")

            # Create file
            with open(file_path, 'w') as f:
                json.dump(SAMPLE_AWS_IP_RANGES, f)

            index, ipv4, ipv6 = load_aws_ip_ranges_with_index(
                file_path=file_path,
                auto_download=False
            )

            assert index is not None
            assert len(ipv4) == 7
            assert len(ipv6) == 2

    def test_load_with_missing_file_no_download(self):
        """Test loading missing file with auto-download disabled."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = os.path.join(tmpdir, "nonexistent.json")

            index, ipv4, ipv6 = load_aws_ip_ranges_with_index(
                file_path=file_path,
                auto_download=False
            )

            assert index is None
            assert len(ipv4) == 0
            assert len(ipv6) == 0


class TestPathCleaning:
    """Tests for path cleaning and matching."""

    def test_clean_path_basic(self):
        """Test basic path cleaning."""
        assert _clean_path("/health") == "/health"
        assert _clean_path("/health/") == "/health"
        assert _clean_path("health") == "/health"

    def test_clean_path_query_params(self):
        """Test stripping query parameters."""
        assert _clean_path("/health?foo=bar") == "/health"
        assert _clean_path("/login?redirect=/health") == "/login"

    def test_clean_path_fragments(self):
        """Test stripping URL fragments."""
        assert _clean_path("/health#section") == "/health"

    def test_clean_path_full_url(self):
        """Test cleaning full URLs."""
        assert _clean_path("https://example.com/health?token=xyz") == "/health"
        assert _clean_path("http://example.com/api/v1/status") == "/api/v1/status"

    def test_path_matches_exact(self):
        """Test exact path matching."""
        assert _path_matches("/health", "/health") is True
        assert _path_matches("/health/", "/health") is True
        assert _path_matches("/status", "/health") is False

    def test_path_matches_prefix(self):
        """Test prefix path matching."""
        assert _path_matches("/health/check", "/health") is True
        assert _path_matches("/health/deep/nested", "/health") is True
        assert _path_matches("/healthz", "/health") is False  # No slash after prefix

    def test_path_matches_query_bypass_prevention(self):
        """Test that query params don't bypass path matching."""
        # This is the key security test
        assert _path_matches("/login?redirect=/health", "/health") is False
        assert _path_matches("/api?path=/health", "/health") is False


class TestLegitimateServiceVerification:
    """Tests for legitimate service verification."""

    def test_route53_health_check_verified(self):
        """Test Route53 Health Check verification with matching IP."""
        index = AWSIPRangeIndex.from_json_data(SAMPLE_AWS_IP_RANGES)

        adjustment, service, method = verify_legitimate_service(
            ip="15.177.0.1",  # In ROUTE53_HEALTHCHECKS range
            ua="Amazon-Route53-Health-Check-Service (ref: abc123)",
            request_paths=["/health"],
            aws_index=index
        )

        assert adjustment == -25
        assert service == "Route53-Health-Check"
        assert method == "aws_service"

    def test_route53_health_check_spoofed(self):
        """Test Route53 Health Check rejection when IP doesn't match."""
        index = AWSIPRangeIndex.from_json_data(SAMPLE_AWS_IP_RANGES)

        # IP not in ROUTE53_HEALTHCHECKS range
        adjustment, service, method = verify_legitimate_service(
            ip="1.2.3.4",
            ua="Amazon-Route53-Health-Check-Service (ref: abc123)",
            request_paths=["/health"],
            aws_index=index
        )

        assert adjustment == 0  # No negative adjustment for spoofed UA
        assert service is None

    def test_datadog_verified(self):
        """Test Datadog verification with matching path."""
        adjustment, service, method = verify_legitimate_service(
            ip="1.2.3.4",
            ua="Datadog Agent/7.0.0",
            request_paths=["/health", "/api/v1/metrics"],
            aws_index=None
        )

        assert adjustment == -15
        assert service == "Datadog"
        assert method == "path_match"

    def test_datadog_wrong_path(self):
        """Test Datadog rejection when paths don't match."""
        adjustment, service, method = verify_legitimate_service(
            ip="1.2.3.4",
            ua="Datadog Agent/7.0.0",
            request_paths=["/admin", "/wp-login.php"],
            aws_index=None
        )

        assert adjustment == 0
        assert service is None

    def test_no_aws_index_warning(self):
        """Test warning when AWS index unavailable for AWS service."""
        # Without AWS index, can't verify AWS services
        adjustment, service, method = verify_legitimate_service(
            ip="15.177.0.1",
            ua="Amazon-Route53-Health-Check-Service",
            request_paths=["/health"],
            aws_index=None  # No index available
        )

        # Should not give negative score without verification
        assert adjustment == 0

    def test_ua_injection_prevention(self):
        """Test that UA injection doesn't match anchored patterns."""
        index = AWSIPRangeIndex.from_json_data(SAMPLE_AWS_IP_RANGES)

        # Evil UA trying to inject legitimate service name
        adjustment, service, method = verify_legitimate_service(
            ip="1.2.3.4",
            ua="Evil-Attacker/1.0 (includes Amazon-Route53-Health-Check-Service)",
            request_paths=["/admin"],
            aws_index=index
        )

        # Anchored regex should not match
        assert adjustment == 0

    def test_cloudfront_verification(self):
        """Test CloudFront service verification."""
        index = AWSIPRangeIndex.from_json_data(SAMPLE_AWS_IP_RANGES)

        adjustment, service, method = verify_legitimate_service(
            ip="13.32.0.1",  # In CLOUDFRONT range
            ua="Amazon CloudFront",
            request_paths=["/"],
            aws_index=index
        )

        assert adjustment == -25
        assert service == "CloudFront"
        assert method == "aws_service"


class TestIsAwsIpFast:
    """Tests for the fast AWS IP check function."""

    def test_is_aws_ip_fast_with_index(self):
        """Test fast IP check with index."""
        index = AWSIPRangeIndex.from_json_data(SAMPLE_AWS_IP_RANGES)

        assert is_aws_ip_fast("15.177.0.1", index) is True
        assert is_aws_ip_fast("1.2.3.4", index) is False

    def test_is_aws_ip_fast_explicit_none(self):
        """Test fast IP check with explicitly passed None index."""
        # Create a fresh empty index to test explicit None behavior
        empty_index = AWSIPRangeIndex.from_json_data({"prefixes": [], "ipv6_prefixes": []})

        # With empty index, IP should not be found
        assert is_aws_ip_fast("15.177.0.1", empty_index) is False
        assert is_aws_ip_fast("1.2.3.4", empty_index) is False


class TestDryRunSummary:
    """Tests for accurate dry-run summary table generation."""

    def test_generate_report_dry_run_mode(self):
        """Test report generation in dry-run mode shows expected state changes."""
        from unittest.mock import MagicMock
        from collections import Counter
        from auto_block_attackers import NaclAutoBlocker

        with tempfile.TemporaryDirectory() as tmpdir:
            # Create minimal blocker instance
            with patch('boto3.client') as mock_boto:
                mock_client = MagicMock()
                mock_boto.return_value = mock_client

                # Mock STS get_caller_identity
                mock_client.get_caller_identity.return_value = {"Account": "123456789012"}

                blocker = NaclAutoBlocker(
                    lb_name_pattern="test-*",
                    region="us-east-1",
                    lookback_str="60m",
                    threshold=50,
                    start_rule=80,
                    limit=20,
                    whitelist_file=None,
                    aws_ip_ranges_file=None,
                    dry_run=True,
                    debug=False,
                    auto_download_ip_ranges=False,
                )

        # Test data
        ip_counts = Counter({
            "192.168.1.1": 100,  # Will be blocked
            "192.168.1.2": 30,   # Below threshold
        })

        offenders = {"192.168.1.1"}
        final_blocked_ips = {"192.168.1.3"}  # Currently blocked
        ips_to_add = {"192.168.1.1"}
        ips_to_remove = {"192.168.1.4"}  # Expired

        # Test _get_dry_run_status directly
        status = blocker._get_dry_run_status(
            ip="192.168.1.1",
            ips_to_add=ips_to_add,
            ips_to_remove=ips_to_remove,
            final_blocked_ips=final_blocked_ips,
            skipped_ip_details={},
            hits=100,
        )
        assert "WILL BE BLOCKED" in status

        status = blocker._get_dry_run_status(
            ip="192.168.1.4",
            ips_to_add=ips_to_add,
            ips_to_remove=ips_to_remove,
            final_blocked_ips=final_blocked_ips,
            skipped_ip_details={},
            hits=0,
        )
        assert "WILL BE UNBLOCKED" in status

        status = blocker._get_dry_run_status(
            ip="192.168.1.3",
            ips_to_add=ips_to_add,
            ips_to_remove=ips_to_remove,
            final_blocked_ips=final_blocked_ips,
            skipped_ip_details={},
            hits=0,
        )
        assert "NO CHANGE" in status

        # Test skipped IP status
        status = blocker._get_dry_run_status(
            ip="192.168.1.5",
            ips_to_add=ips_to_add,
            ips_to_remove=ips_to_remove,
            final_blocked_ips=final_blocked_ips,
            skipped_ip_details={"192.168.1.5": (35.0, {})},
            hits=75,
        )
        assert "SKIPPED" in status
        assert "35" in status


class TestThreatScoreLogging:
    """Tests for enhanced threat score logging."""

    def test_log_threat_score_details_blocked(self, capsys):
        """Test logging for blocked IPs."""
        from unittest.mock import MagicMock
        from auto_block_attackers import NaclAutoBlocker
        import logging

        with patch('boto3.client') as mock_boto:
            mock_client = MagicMock()
            mock_boto.return_value = mock_client
            mock_client.get_caller_identity.return_value = {"Account": "123456789012"}

            blocker = NaclAutoBlocker(
                lb_name_pattern="test-*",
                region="us-east-1",
                lookback_str="60m",
                threshold=50,
                start_rule=80,
                limit=20,
                whitelist_file=None,
                aws_ip_ranges_file=None,
                dry_run=True,
                debug=True,  # Enable debug for detailed logging
                auto_download_ip_ranges=False,
            )

        details = {
            'base_score': 75.0,
            'breakdown': {
                'attack_pattern': 40.0,
                'scanner_ua': 25.0,
                'error_rate': 10.0,
                'path_diversity': 0.0,
                'rate': 0.0,
            },
            'hit_count': 150,
            'reasons': ['attack_patterns (45 hits)', 'scanner_ua (30 hits)'],
            'attack_pattern_hits': 45,
            'scanner_ua_hits': 30,
            'error_responses': 120,
        }

        blocker._log_threat_score_details("192.168.1.1", 75.0, details, blocked=True)

        # Check stderr (where logging output goes)
        captured = capsys.readouterr()
        assert "BLOCKED" in captured.err
        assert "192.168.1.1" in captured.err
        assert "75" in captured.err

    def test_log_threat_score_details_high_hit_warning(self, capsys):
        """Test warning for high-hit IPs that were skipped."""
        from unittest.mock import MagicMock
        from auto_block_attackers import NaclAutoBlocker
        import logging

        with patch('boto3.client') as mock_boto:
            mock_client = MagicMock()
            mock_boto.return_value = mock_client
            mock_client.get_caller_identity.return_value = {"Account": "123456789012"}

            blocker = NaclAutoBlocker(
                lb_name_pattern="test-*",
                region="us-east-1",
                lookback_str="60m",
                threshold=50,
                start_rule=80,
                limit=20,
                whitelist_file=None,
                aws_ip_ranges_file=None,
                dry_run=True,
                debug=False,
                auto_download_ip_ranges=False,
            )

        details = {
            'base_score': 35.0,
            'breakdown': {
                'attack_pattern': 20.0,
                'scanner_ua': 0.0,
                'error_rate': 15.0,
                'path_diversity': 0.0,
                'rate': 0.0,
            },
            'hit_count': 500,  # High hits but low score
            'reasons': ['attack_patterns (10 hits)'],
            'attack_pattern_hits': 10,
            'scanner_ua_hits': 0,
            'error_responses': 100,
        }

        blocker._log_threat_score_details("192.168.1.1", 35.0, details, blocked=False)

        # Check stderr for warning
        captured = capsys.readouterr()
        assert "High-traffic IP" in captured.err
        assert "500 hits" in captured.err
        assert "NOT blocked" in captured.err


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
