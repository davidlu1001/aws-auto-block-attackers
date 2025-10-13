#!/usr/bin/env python3
"""
Test script to validate ipinfo integration in auto_block_attackers.py
This tests the new IP geolocation functionality.
"""

import sys
import os
from unittest.mock import Mock, patch, MagicMock

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_ipinfo_initialization():
    """Test that ipinfo handler is initialized correctly"""
    print("Test 1: Testing ipinfo handler initialization...")

    with patch('auto_block_attackers.boto3.client'):
        with patch('auto_block_attackers.ipinfo.getHandler') as mock_ipinfo:
            mock_handler = MagicMock()
            mock_ipinfo.return_value = mock_handler

            from auto_block_attackers import NaclAutoBlocker

            # Test with ipinfo token
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
                ipinfo_token="test_token"
            )

            assert blocker.ipinfo_handler is not None, "IPInfo handler should be initialized"
            mock_ipinfo.assert_called_once_with("test_token")
            print("✓ IPInfo handler initialized correctly with token")

    print()

def test_ipinfo_disabled():
    """Test that ipinfo is disabled when no token provided"""
    print("Test 2: Testing ipinfo disabled without token...")

    with patch('auto_block_attackers.boto3.client'):
        from auto_block_attackers import NaclAutoBlocker

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

        assert blocker.ipinfo_handler is None, "IPInfo handler should be None without token"
        print("✓ IPInfo correctly disabled when no token provided")

    print()

def test_get_ip_info_without_handler():
    """Test _get_ip_info returns None when handler is not configured"""
    print("Test 3: Testing _get_ip_info without handler...")

    with patch('auto_block_attackers.boto3.client'):
        from auto_block_attackers import NaclAutoBlocker

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

        result = blocker._get_ip_info("1.2.3.4")
        assert result is None, "Should return None when handler is not configured"
        print("✓ _get_ip_info correctly returns None without handler")

    print()

def test_get_ip_info_with_handler():
    """Test _get_ip_info fetches data correctly"""
    print("Test 4: Testing _get_ip_info with mock handler...")

    with patch('auto_block_attackers.boto3.client'):
        with patch('auto_block_attackers.ipinfo.getHandler') as mock_ipinfo:
            from auto_block_attackers import NaclAutoBlocker

            # Create mock handler and details
            mock_handler = MagicMock()
            mock_ipinfo.return_value = mock_handler

            mock_details = MagicMock()
            mock_details.city = "Sydney"
            mock_details.region = "New South Wales"
            mock_details.country_name = "Australia"
            mock_details.country = "AU"
            mock_details.loc = "-33.8688,151.2093"
            mock_details.org = "AS1221 Telstra Corporation Ltd"
            mock_details.postal = "2000"
            mock_details.timezone = "Australia/Sydney"
            mock_details.hostname = "test.example.com"

            mock_handler.getDetails.return_value = mock_details

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
                ipinfo_token="test_token"
            )

            result = blocker._get_ip_info("1.2.3.4")

            assert result is not None, "Should return IP info"
            assert result["city"] == "Sydney", "City should be Sydney"
            assert result["country"] == "Australia", "Country should be Australia"
            assert result["location"] == "-33.8688,151.2093", "Location should match"
            assert result["hostname"] == "test.example.com", "Hostname should match"
            print("✓ _get_ip_info correctly fetches and parses IP details")
            print(f"  Sample data: {result['city']}, {result['country']} ({result['location']})")

    print()

def test_format_ip_info():
    """Test IP info formatting"""
    print("Test 5: Testing IP info formatting...")

    with patch('auto_block_attackers.boto3.client'):
        from auto_block_attackers import NaclAutoBlocker

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

        # Test with full info
        ip_info = {
            "ip": "1.2.3.4",
            "city": "Sydney",
            "region": "New South Wales",
            "country": "Australia",
            "location": "-33.8688,151.2093",
            "org": "AS1221 Telstra Corporation",
            "hostname": "test.example.com"
        }

        formatted = blocker._format_ip_info(ip_info)
        assert "Sydney" in formatted, "Should contain city"
        assert "Australia" in formatted, "Should contain country"
        assert "-33.8688,151.2093" in formatted, "Should contain coordinates"
        assert "Telstra" in formatted, "Should contain org"
        print("✓ IP info formatted correctly")
        print(f"  Formatted output: {formatted}")

        # Test with None
        formatted_none = blocker._format_ip_info(None)
        assert formatted_none == "IP info not available", "Should handle None gracefully"
        print("✓ Handles None input correctly")

    print()

def test_create_deny_rule_integration():
    """Test that _create_deny_rule calls IP info methods"""
    print("Test 6: Testing _create_deny_rule IP info integration...")

    with patch('auto_block_attackers.boto3.client'):
        with patch('auto_block_attackers.ipinfo.getHandler') as mock_ipinfo:
            from auto_block_attackers import NaclAutoBlocker

            mock_handler = MagicMock()
            mock_ipinfo.return_value = mock_handler

            mock_details = MagicMock()
            mock_details.city = "London"
            mock_details.region = "England"
            mock_details.country_name = "United Kingdom"
            mock_details.country = "GB"
            mock_details.loc = "51.5074,-0.1278"
            mock_details.org = "AS12345 Example Hosting"
            mock_details.postal = "EC1A"
            mock_details.timezone = "Europe/London"

            mock_handler.getDetails.return_value = mock_details

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
                ipinfo_token="test_token"
            )

            # Mock EC2 client
            blocker.ec2 = MagicMock()

            # Call _create_deny_rule
            blocker._create_deny_rule("acl-123", "1.2.3.4", 80)

            # Verify IP info was fetched
            mock_handler.getDetails.assert_called_once_with("1.2.3.4")
            print("✓ _create_deny_rule fetches IP info for blocked IPs")

    print()

def test_error_handling():
    """Test error handling in IP info lookup"""
    print("Test 7: Testing error handling for failed IP lookups...")

    with patch('auto_block_attackers.boto3.client'):
        with patch('auto_block_attackers.ipinfo.getHandler') as mock_ipinfo:
            from auto_block_attackers import NaclAutoBlocker

            mock_handler = MagicMock()
            mock_ipinfo.return_value = mock_handler

            # Simulate API error
            mock_handler.getDetails.side_effect = Exception("API Error")

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
                ipinfo_token="test_token"
            )

            # Should not crash, should return None
            result = blocker._get_ip_info("1.2.3.4")
            assert result is None, "Should return None on error"
            print("✓ Error handling works correctly - returns None on API failure")

    print()

def run_all_tests():
    """Run all tests"""
    print("="*60)
    print("IPInfo Integration Tests for auto_block_attackers.py")
    print("="*60)
    print()

    try:
        test_ipinfo_initialization()
        test_ipinfo_disabled()
        test_get_ip_info_without_handler()
        test_get_ip_info_with_handler()
        test_format_ip_info()
        test_create_deny_rule_integration()
        test_error_handling()

        print("="*60)
        print("✓ All tests passed successfully!")
        print("="*60)
        return True
    except AssertionError as e:
        print(f"✗ Test failed: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
