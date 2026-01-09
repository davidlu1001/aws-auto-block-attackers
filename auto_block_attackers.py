#!/usr/bin/env python3
"""
AWS Auto Block Attackers - Automated Network ACL Management System

This module provides an automated solution for analyzing AWS Application Load Balancer (ALB)
access logs, detecting malicious traffic patterns, and implementing tiered time-based IP
blocking through Network ACLs (NACLs).

Key Features:
    - Tiered Blocking System: Categorizes attackers into 5 severity tiers (Critical, High,
      Medium, Low, Minimal) with corresponding block durations from 1 hour to 7 days
    - Attack Pattern Detection: Identifies common attack vectors including LFI, XSS, SQL
      injection, command injection, SSTI, and scanner activity
    - Time-Based Persistence: Maintains a JSON registry of blocked IPs with expiration
      tracking and automatic cleanup
    - Priority-Based Management: Higher-priority threats won't be displaced when NACL slots
      are full
    - AWS IP Exclusion: Automatically excludes AWS service IPs from blocking
    - Slack Integration: Real-time notifications with detailed attack context
    - IP Geolocation: Optional IPInfo integration for attacker intelligence
    - Dry-Run Mode: Test blocking logic without making actual changes

Architecture:
    The script operates in 7 main steps:
    1. Discover target ALBs matching the specified pattern
    2. Extract S3 log locations from ALB configurations
    3. Find and validate Network ACLs for the VPC
    4. Check for expired blocks and remove them
    5. Scan S3 for ALB logs within the lookback window
    6. Process logs in parallel to detect attack patterns
    7. Update NACL rules based on tiered blocking strategy

Tier System:
    - Critical (Priority 4): 2000+ hits → 7 days block
    - High (Priority 3): 1000-1999 hits → 3 days block
    - Medium (Priority 2): 500-999 hits → 2 days block
    - Low (Priority 1): 100-499 hits → 1 day block
    - Minimal (Priority 0): <100 hits → 1 hour block (rolling)

Usage:
    Basic dry-run (no changes made):
        $ python3 auto_block_attackers.py --lb-name-pattern "alb-*" --threshold 50

    Production deployment with live blocking:
        $ python3 auto_block_attackers.py \\
            --lb-name-pattern "alb-prod-*" \\
            --region ap-southeast-2 \\
            --threshold 75 \\
            --lookback 90m \\
            --live-run

    With Slack notifications and IP geolocation:
        $ export SLACK_BOT_TOKEN="xoxb-your-token"
        $ export SLACK_CHANNEL="C04ABCDEFG"
        $ export IPINFO_TOKEN="your-ipinfo-token"
        $ python3 auto_block_attackers.py --live-run

Configuration:
    Required AWS IAM Permissions:
        - elasticloadbalancing:DescribeLoadBalancers
        - elasticloadbalancing:DescribeLoadBalancerAttributes
        - ec2:DescribeNetworkAcls
        - ec2:CreateNetworkAclEntry
        - ec2:DeleteNetworkAclEntry
        - s3:GetObject
        - s3:ListBucket
        - sts:GetCallerIdentity

    Environment Variables:
        SLACK_BOT_TOKEN: Slack bot token for notifications
        SLACK_CHANNEL: Slack channel ID or name
        IPINFO_TOKEN: IPInfo API token for geolocation

    Files:
        whitelist.txt: Trusted IPs (one per line, # for comments)
        ip-ranges.json: AWS IP ranges (download from AWS)
        block_registry.json: Persistent block state (auto-managed)

Security Considerations:
    - Always test with --dry-run before deploying to production
    - Maintain a whitelist of trusted IPs (office, monitoring, etc.)
    - Review blocked IPs regularly to identify false positives
    - Use separate NACL rule ranges for manual vs. automated blocks
    - Enable CloudTrail for audit logging of NACL changes
    - Protect the block_registry.json file with appropriate permissions

Performance:
    - Parallel log processing with ThreadPoolExecutor (10 workers)
    - Date-based S3 prefix filtering for efficient log scanning
    - IPInfo API caching to reduce rate limit concerns (1-hour TTL)
    - Atomic registry file updates to prevent corruption

Error Handling:
    - Gracefully handles corrupted registry files
    - Recovers from transient AWS API failures with retries
    - Validates IP addresses before blocking
    - Logs errors without exposing sensitive information

Author:
    AWS Auto Block Attackers Contributors

License:
    MIT License - See LICENSE file for details

Version:
    1.0.0

Repository:
    https://github.com/davidlu1001/aws-auto-block-attackers

Documentation:
    See README.md for detailed documentation and examples
"""

__version__ = "2.0.0"
__author__ = "AWS Auto Block Attackers Contributors"
__license__ = "MIT"

import boto3
import gzip
import re
import json
from collections import Counter
from pathlib import Path
import logging
import argparse
from datetime import datetime, timedelta, timezone
from botocore.config import Config
from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import fnmatch
from typing import Set, List, Dict, Tuple, Optional, Any
from collections import defaultdict
from dataclasses import dataclass, field
from urllib.parse import urlparse
import bisect
import os
import sys
import ipinfo
import requests

# Import SlackClient from the same directory
try:
    from slack_client import SlackClient, SlackSeverity, TIER_TO_SEVERITY
except ImportError:
    # If running from a different directory
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from slack_client import SlackClient, SlackSeverity, TIER_TO_SEVERITY

# Import storage backends
try:
    from storage_backends import (
        StorageBackend,
        LocalFileBackend,
        DynamoDBBackend,
        S3Backend,
        create_storage_backend,
        StorageError,
    )
except ImportError:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from storage_backends import (
        StorageBackend,
        LocalFileBackend,
        DynamoDBBackend,
        S3Backend,
        create_storage_backend,
        StorageError,
    )

# --- ENHANCED REGULAR EXPRESSIONS TO DETECT COMMON ATTACK PATTERNS ---
# FIX: All patterns are now combined into a single string separated by '|'
ATTACK_PATTERNS = re.compile(
    # LFI/Path Traversal
    r"(\.\./|%2e%2e[/|%5c])|etc/passwd|win.ini|/proc/self|"
    # XSS
    r"<script|alert\(|document\.cookie|onfocus=|onerror=|"
    # SQL Injection
    r"UNION\sSELECT|SELECT\s.*\sFROM|' OR '1'='1|sleep\(|BENCHMARK\(|"
    # Command Injection
    r"eval\(|base64_decode|whoami|uname|wget|curl|/bin/bash|"
    # Sensitive File/Dir Probing
    r"\.env|\.git/config|credentials|/solr/|/v2/_catalog|"
    # Common Scanners & Exploits
    r"wp-login|phpmyadmin|jndi:ldap|log4j|nmap|zgrab|nikto|"
    # SSTI (Server-Side Template Injection)
    r"\{\{.*\}\}|\{%",
    re.IGNORECASE,
)

# --- KNOWN MALICIOUS USER AGENTS ---
SCANNER_USER_AGENTS = re.compile(
    r"(zgrab|nmap|nikto|sqlmap|dirbuster|gobuster|nuclei|wpscan|"
    r"masscan|shodan|censys|zmap|httpx|feroxbuster|ffuf|"
    r"python-requests|go-http-client|curl/|wget/|"
    r"scanner|crawler|spider|bot|scraper|"
    r"java/\d|libwww-perl|lwp-trivial)",
    re.IGNORECASE,
)

# --- SUSPICIOUS USER AGENT PATTERNS (lower confidence than scanners) ---
SUSPICIOUS_UA_PATTERNS = re.compile(
    r"(python|java|php|ruby|perl|curl|wget|libwww|"
    r"httpclient|okhttp|apache-http|axios|node-fetch)",
    re.IGNORECASE,
)

# --- AWS IP RANGES CONFIGURATION ---
AWS_IP_RANGES_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
IP_RANGES_MAX_AGE_DAYS = 7  # Re-download if older than 7 days

# AWS service names from ip-ranges.json
# See: https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html
AWS_SERVICE_ROUTE53_HEALTHCHECKS = 'ROUTE53_HEALTHCHECKS'
AWS_SERVICE_CLOUDFRONT = 'CLOUDFRONT'
AWS_SERVICE_ELB = 'ELB'
AWS_SERVICE_EC2 = 'EC2'
AWS_SERVICE_AMAZON = 'AMAZON'

# --- KNOWN LEGITIMATE SERVICES CONFIGURATION ---
# SECURITY NOTE: No hardcoded IPs! AWS services verified via ip-ranges.json service tags.
KNOWN_LEGITIMATE_SERVICES = {
    'Route53-Health-Check': {
        'ua_pattern': re.compile(r'^Amazon-Route53-Health-Check', re.IGNORECASE),
        # Verify IP is from ROUTE53_HEALTHCHECKS service in ip-ranges.json
        'aws_service': AWS_SERVICE_ROUTE53_HEALTHCHECKS,
        'require_service_match': True,
    },
    'ELB-HealthChecker': {
        'ua_pattern': re.compile(r'^ELB-HealthChecker', re.IGNORECASE),
        'aws_service': AWS_SERVICE_ELB,
        'require_service_match': True,
    },
    'CloudFront': {
        'ua_pattern': re.compile(r'^Amazon CloudFront', re.IGNORECASE),
        'aws_service': AWS_SERVICE_CLOUDFRONT,
        'require_service_match': True,
    },
    # Non-AWS services: require path matching since we can't verify IPs
    # These only get -15 (vs -25 for AWS), so even if spoofed, won't bypass threshold alone
    'Datadog': {
        'ua_pattern': re.compile(r'Datadog', re.IGNORECASE),
        'expected_paths': ['/health', '/metrics', '/status', '/api/v1', '/info'],
        'require_path_match': True,
    },
    'NewRelic': {
        'ua_pattern': re.compile(r'NewRelic', re.IGNORECASE),
        'expected_paths': ['/health', '/status', '/ping'],
        'require_path_match': True,
    },
    'Pingdom': {
        'ua_pattern': re.compile(r'Pingdom', re.IGNORECASE),
        'expected_paths': ['/health', '/status', '/ping', '/'],
        'require_path_match': True,
    },
    'UptimeRobot': {
        'ua_pattern': re.compile(r'UptimeRobot', re.IGNORECASE),
        'expected_paths': ['/health', '/status', '/'],
        'require_path_match': True,
    },
}


def get_ip_ranges_path() -> str:
    """
    Get appropriate path for ip-ranges.json based on environment.

    - Lambda: /tmp (re-download on cold start, ~500ms, acceptable)
    - ECS with EFS: /mnt/efs (persistent)
    - EC2/VM: ./ip-ranges.json (persistent)

    Note: We intentionally skip S3 caching to avoid IAM complexity.
    The ~500ms download time on Lambda cold start is acceptable.
    """
    # Lambda environment
    if os.environ.get('AWS_LAMBDA_FUNCTION_NAME'):
        return '/tmp/ip-ranges.json'

    # ECS with EFS mount
    if os.path.exists('/mnt/efs') and os.access('/mnt/efs', os.W_OK):
        return '/mnt/efs/cache/ip-ranges.json'

    # Default: current directory
    return './ip-ranges.json'


def download_aws_ip_ranges(
    file_path: str,
    max_age_days: int = IP_RANGES_MAX_AGE_DAYS
) -> Optional[Dict]:
    """
    Download AWS IP ranges if missing or stale.

    Args:
        file_path: Path to save the ip-ranges.json file
        max_age_days: Re-download if file is older than this many days

    Returns:
        Parsed JSON data if successful, None otherwise
    """
    path = Path(file_path)
    is_lambda = os.environ.get('AWS_LAMBDA_FUNCTION_NAME') is not None

    # Check freshness (Lambda always re-downloads on cold start)
    if path.exists() and not is_lambda:
        file_age = datetime.now() - datetime.fromtimestamp(path.stat().st_mtime)
        if file_age < timedelta(days=max_age_days):
            logging.debug(f"AWS IP ranges fresh ({file_age.days}d old), loading from cache")
            try:
                with open(path) as f:
                    return json.load(f)
            except json.JSONDecodeError:
                logging.warning("Cached IP ranges corrupted, re-downloading")

    # Download using requests
    logging.info(f"Downloading AWS IP ranges from {AWS_IP_RANGES_URL}...")
    try:
        response = requests.get(
            AWS_IP_RANGES_URL,
            timeout=30,
            headers={'User-Agent': 'aws-auto-block-attackers/2.0'}
        )
        response.raise_for_status()
        data = response.json()

        # Save for future use (skip on Lambda - /tmp is ephemeral anyway)
        if not is_lambda:
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, 'w') as f:
                json.dump(data, f)
            logging.info(
                f"Successfully downloaded AWS IP ranges ({len(response.content) / 1024:.1f} KB) "
                f"to {file_path}"
            )
        else:
            logging.info(
                f"Downloaded AWS IP ranges ({len(response.content) / 1024:.1f} KB) "
                f"(Lambda env, not caching)"
            )

        return data

    except requests.exceptions.Timeout:
        logging.warning("Timeout downloading AWS IP ranges (30s)")
    except requests.exceptions.RequestException as e:
        logging.warning(f"Failed to download AWS IP ranges: {e}")
    except json.JSONDecodeError as e:
        logging.warning(f"Downloaded AWS IP ranges file is invalid JSON: {e}")
    except Exception as e:
        logging.warning(f"Unexpected error downloading AWS IP ranges: {e}")

    # Fallback: try loading stale cache
    if path.exists():
        logging.info("Using stale cached IP ranges as fallback")
        try:
            with open(path) as f:
                return json.load(f)
        except Exception:
            pass

    logging.warning(
        "No AWS IP ranges available. AWS IPs will not be excluded. "
        "Some legitimate AWS service traffic may be blocked."
    )
    return None


@dataclass
class AWSIPRangeIndex:
    """
    Sorted index for O(log N) AWS IP lookups with service mapping.

    Features:
    - Binary search for fast IP-in-range checks
    - Service-based verification (e.g., is IP from ROUTE53_HEALTHCHECKS?)
    - No hardcoded IPs - all data from ip-ranges.json

    Performance: O(log N) per lookup, where N ≈ 10,000 ranges
    """
    # For general "is AWS IP" checks: List of (start_int, end_int, cidr_str)
    ipv4_ranges: List[Tuple[int, int, str]] = field(default_factory=list)
    ipv6_ranges: List[Tuple[int, int, str]] = field(default_factory=list)

    # For service-specific checks: service_name -> List of (start_int, end_int)
    service_ranges_v4: Dict[str, List[Tuple[int, int]]] = field(default_factory=lambda: defaultdict(list))
    service_ranges_v6: Dict[str, List[Tuple[int, int]]] = field(default_factory=lambda: defaultdict(list))

    # Statistics
    total_ipv4: int = 0
    total_ipv6: int = 0
    services: Set[str] = field(default_factory=set)

    # Lookup statistics
    _lookup_hits: int = 0
    _lookup_misses: int = 0

    @classmethod
    def from_json_data(cls, data: Dict) -> 'AWSIPRangeIndex':
        """Build index from ip-ranges.json data."""
        index = cls()

        # Process IPv4 prefixes
        for prefix in data.get('prefixes', []):
            ip_prefix = prefix.get('ip_prefix')
            service = prefix.get('service', 'UNKNOWN')

            if not ip_prefix:
                continue

            try:
                network = ipaddress.ip_network(ip_prefix, strict=False)
                start_int = int(network.network_address)
                end_int = int(network.broadcast_address)

                index.ipv4_ranges.append((start_int, end_int, ip_prefix))
                index.service_ranges_v4[service].append((start_int, end_int))
                index.services.add(service)
            except ValueError:
                continue

        # Process IPv6 prefixes
        for prefix in data.get('ipv6_prefixes', []):
            ip_prefix = prefix.get('ipv6_prefix')
            service = prefix.get('service', 'UNKNOWN')

            if not ip_prefix:
                continue

            try:
                network = ipaddress.ip_network(ip_prefix, strict=False)
                start_int = int(network.network_address)
                end_int = int(network.broadcast_address)

                index.ipv6_ranges.append((start_int, end_int, ip_prefix))
                index.service_ranges_v6[service].append((start_int, end_int))
                index.services.add(service)
            except ValueError:
                continue

        # Sort all ranges for binary search
        index.ipv4_ranges.sort(key=lambda x: x[0])
        index.ipv6_ranges.sort(key=lambda x: x[0])

        for service in index.service_ranges_v4:
            index.service_ranges_v4[service].sort(key=lambda x: x[0])
        for service in index.service_ranges_v6:
            index.service_ranges_v6[service].sort(key=lambda x: x[0])

        index.total_ipv4 = len(index.ipv4_ranges)
        index.total_ipv6 = len(index.ipv6_ranges)

        # Log summary of services
        top_services = sorted(index.services)[:5]
        logging.info(
            f"Built AWS IP index: {index.total_ipv4} IPv4, {index.total_ipv6} IPv6 ranges, "
            f"{len(index.services)} services ({', '.join(top_services)}...)"
        )

        return index

    def is_aws_ip(self, ip_str: str) -> bool:
        """
        O(log N) check if IP belongs to any AWS range.

        Args:
            ip_str: IP address string (IPv4 or IPv6)

        Returns:
            True if IP is from AWS
        """
        result = self._bisect_lookup(ip_str) is not None
        if result:
            self._lookup_hits += 1
        else:
            self._lookup_misses += 1
        return result

    def is_from_service(self, ip_str: str, service_name: str) -> bool:
        """
        Check if IP belongs to a specific AWS service.

        This enables dynamic verification without hardcoded IPs.
        Service names come from ip-ranges.json (e.g., 'ROUTE53_HEALTHCHECKS', 'CLOUDFRONT').

        Args:
            ip_str: IP address to check
            service_name: AWS service name from ip-ranges.json

        Returns:
            True if IP belongs to the specified service
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            ip_int = int(ip)

            if ip.version == 4:
                ranges = self.service_ranges_v4.get(service_name, [])
            else:
                ranges = self.service_ranges_v6.get(service_name, [])

            if not ranges:
                return False

            # Binary search in service-specific ranges
            starts = [r[0] for r in ranges]
            idx = bisect.bisect_right(starts, ip_int) - 1

            if idx < 0:
                return False

            start_int, end_int = ranges[idx]
            return start_int <= ip_int <= end_int

        except ValueError:
            return False

    def get_service_for_ip(self, ip_str: str) -> Optional[str]:
        """
        Get the AWS service name for an IP address.

        Args:
            ip_str: IP address to check

        Returns:
            Service name if found, None otherwise
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            ip_int = int(ip)

            service_ranges = self.service_ranges_v4 if ip.version == 4 else self.service_ranges_v6

            for service_name, ranges in service_ranges.items():
                if not ranges:
                    continue

                starts = [r[0] for r in ranges]
                idx = bisect.bisect_right(starts, ip_int) - 1

                if idx < 0:
                    continue

                start_int, end_int = ranges[idx]
                if start_int <= ip_int <= end_int:
                    return service_name

            return None

        except ValueError:
            return None

    def _bisect_lookup(self, ip_str: str) -> Optional[str]:
        """
        Binary search for IP in all ranges.

        Returns matching CIDR or None.
        """
        try:
            ip = ipaddress.ip_address(ip_str)
            ip_int = int(ip)

            ranges = self.ipv4_ranges if ip.version == 4 else self.ipv6_ranges

            if not ranges:
                return None

            # Binary search: find rightmost range where start <= ip_int
            starts = [r[0] for r in ranges]
            idx = bisect.bisect_right(starts, ip_int) - 1

            if idx < 0:
                return None

            start_int, end_int, cidr = ranges[idx]

            if start_int <= ip_int <= end_int:
                return cidr

            return None

        except ValueError:
            return None

    def get_lookup_stats(self) -> Tuple[int, int, float]:
        """
        Get lookup statistics.

        Returns:
            Tuple of (hits, misses, hit_rate_percent)
        """
        total = self._lookup_hits + self._lookup_misses
        hit_rate = (self._lookup_hits / total * 100) if total > 0 else 0.0
        return self._lookup_hits, self._lookup_misses, hit_rate


# Module-level index (singleton)
_aws_ip_index: Optional[AWSIPRangeIndex] = None


def _clean_path(url_or_path: str) -> str:
    """
    Extract and clean the path component from a URL or path string.

    Removes query parameters and fragments to prevent bypass attempts like:
    /login?redirect=/health  (would incorrectly match '/health' if not cleaned)

    Args:
        url_or_path: Full URL or path string

    Returns:
        Clean path without query params or fragments
    """
    # Handle full URLs
    if '://' in url_or_path:
        parsed = urlparse(url_or_path)
        path = parsed.path
    else:
        # Just a path - split off query string
        path = url_or_path.split('?')[0].split('#')[0]

    # Normalize: ensure leading slash, remove trailing slash (except for root)
    if not path.startswith('/'):
        path = '/' + path
    if path != '/' and path.endswith('/'):
        path = path.rstrip('/')

    return path


def _path_matches(req_path: str, expected_path: str) -> bool:
    """
    Check if request path matches expected path (prefix match).

    More secure than simple 'in' check:
    - /health matches /health, /health/check, /healthz
    - /health does NOT match /login?ref=/health

    Args:
        req_path: Actual request path (will be cleaned)
        expected_path: Expected path pattern

    Returns:
        True if path matches
    """
    clean_req = _clean_path(req_path)
    clean_expected = expected_path.rstrip('/')

    # Exact match
    if clean_req == clean_expected:
        return True

    # Prefix match (e.g., /health matches /health/check)
    if clean_expected and clean_req.startswith(clean_expected + '/'):
        return True

    # Root path special case
    if clean_expected == '/' and clean_req == '/':
        return True

    return False


def verify_legitimate_service(
    ip: str,
    ua: str,
    request_paths: List[str],
    aws_index: Optional[AWSIPRangeIndex] = None
) -> Tuple[int, Optional[str], Optional[str]]:
    """
    Verify if traffic is from a known legitimate service.

    SECURITY: NEVER trusts UA alone. Requires secondary verification:
    - AWS services: IP must belong to correct AWS service (dynamic lookup via ip-ranges.json)
    - Non-AWS services: Request paths must match expected patterns (cleaned, no query params)

    FAIL-CLOSED: If aws_index is unavailable, AWS services cannot be verified.
    This may cause false positives but maintains security.

    Args:
        ip: Client IP address
        ua: User-Agent string
        request_paths: List of request paths/URLs from this IP
        aws_index: AWSIPRangeIndex for service verification (built from ip-ranges.json)

    Returns:
        (score_adjustment, service_name, verification_method)
        - score_adjustment: Negative value to reduce threat score (-25 for AWS, -15 for path match)
        - service_name: Name of verified service, or None
        - verification_method: How it was verified ('aws_service', 'path_match', None)
    """
    if not ua:
        return 0, None, None

    for service_name, config in KNOWN_LEGITIMATE_SERVICES.items():
        # Step 1: Check UA pattern (anchored patterns prevent injection like "Evil-Amazon-Route53...")
        if not config['ua_pattern'].search(ua):
            continue

        # UA matched - now REQUIRE secondary verification (don't trust UA alone!)

        # Step 2a: AWS service verification (dynamic, no hardcoded IPs)
        if config.get('require_service_match'):
            aws_service = config.get('aws_service')

            if aws_index is None:
                # FAIL-CLOSED: Can't verify without index - don't give negative score
                # This is intentional: security over availability
                logging.warning(
                    f"UA matches {service_name} but AWS IP index unavailable. "
                    f"Cannot verify IP {ip}. This may cause false positive. "
                    f"Check if ip-ranges.json download failed."
                )
                continue

            if aws_service and aws_index.is_from_service(ip, aws_service):
                # VERIFIED: UA + IP matches AWS service
                logging.debug(
                    f"Verified legitimate AWS service: {service_name} "
                    f"(IP {ip} confirmed in {aws_service} range)"
                )
                return -25, service_name, 'aws_service'
            else:
                # SUSPICIOUS: UA claims to be AWS service but IP doesn't match!
                logging.warning(
                    f"SPOOFING ALERT: UA claims to be {service_name} but IP {ip} "
                    f"is NOT in {aws_service} range. Possible attack vector."
                )
                # Don't give negative score - likely spoofing attempt
                continue

        # Step 2b: Path-based verification (for non-AWS services like Datadog)
        # Uses cleaned paths to prevent bypass via query params
        if config.get('require_path_match'):
            expected_paths = config.get('expected_paths', [])

            # Check if any request path matches expected patterns
            path_matched = False
            matched_path = None
            for req_path in request_paths:
                for expected in expected_paths:
                    if _path_matches(req_path, expected):
                        path_matched = True
                        matched_path = expected
                        break
                if path_matched:
                    break

            if path_matched:
                logging.debug(
                    f"Verified legitimate service: {service_name} "
                    f"(UA + path '{matched_path}' match)"
                )
                return -15, service_name, 'path_match'
            else:
                # UA matches but paths don't - be cautious
                sample_paths = [_clean_path(p) for p in request_paths[:3]]
                logging.debug(
                    f"UA claims {service_name} but paths {sample_paths} "
                    f"don't match expected {expected_paths}. Not giving negative score."
                )
                continue

    return 0, None, None


# --- MULTI-SIGNAL THREAT DETECTION CONFIGURATION ---
DEFAULT_THREAT_SIGNALS_CONFIG = {
    # Weights for different threat signals (sum should ideally be around 100)
    "attack_pattern_weight": 40,  # Pattern match in request
    "scanner_ua_weight": 25,  # Known scanner user agent
    "error_rate_weight": 20,  # High 4xx/5xx response rate
    "path_diversity_weight": 10,  # Many unique paths (scanning behavior)
    "rate_weight": 5,  # High request rate

    # Thresholds
    "error_rate_threshold": 0.7,  # 70% error responses
    "path_diversity_threshold": 0.8,  # 80% unique paths
    "rate_threshold": 100,  # 100+ requests in time window

    # Minimum score to be considered malicious (out of 100)
    "min_threat_score": 40,

    # Enable/disable multi-signal mode
    "enabled": True,
}


class ThreatSignals:
    """
    Tracks multiple threat signals for an IP address.
    Used for multi-signal threat detection to reduce false positives.
    """

    def __init__(self):
        self.attack_pattern_hits: int = 0
        self.scanner_ua_hits: int = 0
        self.error_responses: int = 0  # 4xx/5xx responses
        self.total_requests: int = 0
        self.unique_paths: Set[str] = set()
        self.first_seen: Optional[datetime] = None
        self.last_seen: Optional[datetime] = None

    def add_request(
        self,
        has_attack_pattern: bool,
        has_scanner_ua: bool,
        status_code: int,
        path: str,
        timestamp: Optional[datetime] = None,
    ):
        """Record a request and its signals."""
        self.total_requests += 1

        if has_attack_pattern:
            self.attack_pattern_hits += 1

        if has_scanner_ua:
            self.scanner_ua_hits += 1

        if status_code >= 400:
            self.error_responses += 1

        self.unique_paths.add(path)

        if timestamp:
            if self.first_seen is None or timestamp < self.first_seen:
                self.first_seen = timestamp
            if self.last_seen is None or timestamp > self.last_seen:
                self.last_seen = timestamp

    def calculate_threat_score(self, config: Dict) -> Tuple[float, Dict[str, float]]:
        """
        Calculate overall threat score based on multiple signals.

        Returns:
            Tuple of (total_score, breakdown_dict)
        """
        if self.total_requests == 0:
            return 0.0, {}

        breakdown = {}

        # 1. Attack pattern signal
        pattern_ratio = self.attack_pattern_hits / self.total_requests
        pattern_score = pattern_ratio * config["attack_pattern_weight"]
        breakdown["attack_pattern"] = pattern_score

        # 2. Scanner user agent signal
        scanner_ratio = self.scanner_ua_hits / self.total_requests
        scanner_score = scanner_ratio * config["scanner_ua_weight"]
        breakdown["scanner_ua"] = scanner_score

        # 3. Error response rate signal
        error_ratio = self.error_responses / self.total_requests
        if error_ratio >= config["error_rate_threshold"]:
            error_score = config["error_rate_weight"]
        else:
            error_score = (error_ratio / config["error_rate_threshold"]) * config["error_rate_weight"]
        breakdown["error_rate"] = error_score

        # 4. Path diversity signal (scanning behavior)
        path_diversity = len(self.unique_paths) / self.total_requests if self.total_requests > 0 else 0
        if path_diversity >= config["path_diversity_threshold"]:
            diversity_score = config["path_diversity_weight"]
        else:
            diversity_score = (path_diversity / config["path_diversity_threshold"]) * config["path_diversity_weight"]
        breakdown["path_diversity"] = diversity_score

        # 5. Request rate signal
        if self.total_requests >= config["rate_threshold"]:
            rate_score = config["rate_weight"]
        else:
            rate_score = (self.total_requests / config["rate_threshold"]) * config["rate_weight"]
        breakdown["rate"] = rate_score

        total_score = sum(breakdown.values())
        return total_score, breakdown

    def is_malicious(self, config: Dict) -> Tuple[bool, float, Dict[str, float]]:
        """
        Determine if this IP should be considered malicious based on threat score.

        Returns:
            Tuple of (is_malicious, score, breakdown)
        """
        score, breakdown = self.calculate_threat_score(config)
        return score >= config["min_threat_score"], score, breakdown


# --- TIERED BLOCKING CONFIGURATION ---
# Each tier: (min_hits, block_duration, tier_name, priority)
# Priority: Higher number = higher priority (won't be displaced by lower priority)
DEFAULT_TIER_CONFIG = [
    (2000, timedelta(days=7), "critical", 4),  # 2000+ hits → block 7 days
    (1000, timedelta(days=3), "high", 3),  # 1000-1999 hits → block 3 days
    (500, timedelta(hours=48), "medium", 2),  # 500-999 hits → block 48 hours
    (100, timedelta(hours=24), "low", 1),  # 100-499 hits → block 24 hours
    (0, timedelta(hours=1), "minimal", 0),  # Below 100 hits → block 1 hour (rolling)
]


class JsonFormatter(logging.Formatter):
    """
    JSON formatter for structured logging (CloudWatch Logs compatible).
    """

    def format(self, record: logging.LogRecord) -> str:
        log_dict = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
        }

        # Add exception info if present
        if record.exc_info:
            log_dict["exception"] = self.formatException(record.exc_info)

        # Add extra fields if provided
        if hasattr(record, "extra_fields"):
            log_dict.update(record.extra_fields)

        return json.dumps(log_dict)


def setup_logging(debug: bool = False, json_format: bool = False):
    """
    Configures logging level and format.

    Args:
        debug: Enable debug level logging
        json_format: Use JSON structured logging format (for CloudWatch Logs)
    """
    log_level = logging.DEBUG if debug else logging.INFO

    # Remove all existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Create console handler
    handler = logging.StreamHandler()
    handler.setLevel(log_level)

    if json_format:
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
        )

    root_logger.setLevel(log_level)
    root_logger.addHandler(handler)


class CloudWatchMetrics:
    """
    CloudWatch metrics publisher for monitoring the blocker's activity.

    Publishes custom metrics to AWS CloudWatch for:
    - IPs blocked/unblocked
    - Attack patterns detected
    - Processing performance
    - Error rates
    """

    def __init__(
        self,
        namespace: str = "AutoBlockAttackers",
        region: str = "us-east-1",
        enabled: bool = True,
        dry_run: bool = False,
    ):
        """
        Initialize CloudWatch metrics publisher.

        Args:
            namespace: CloudWatch metrics namespace
            region: AWS region
            enabled: Whether to publish metrics
            dry_run: If True, log metrics instead of publishing
        """
        self.namespace = namespace
        self.enabled = enabled
        self.dry_run = dry_run
        self._metric_buffer: List[Dict] = []
        self._buffer_size = 20  # AWS CloudWatch limit per API call
        self._cloudwatch = None

        if enabled:
            try:
                boto_config = Config(
                    connect_timeout=5,
                    read_timeout=10,
                    retries={"max_attempts": 3, "mode": "adaptive"},
                )
                self._cloudwatch = boto3.client(
                    "cloudwatch", region_name=region, config=boto_config
                )
                logging.info(f"CloudWatch metrics enabled (namespace: {namespace})")
            except Exception as e:
                logging.warning(f"Failed to initialize CloudWatch metrics: {e}")
                self.enabled = False

    def put_metric(
        self,
        metric_name: str,
        value: float,
        unit: str = "Count",
        dimensions: Optional[Dict[str, str]] = None,
    ):
        """
        Queue a metric for publishing to CloudWatch.

        Args:
            metric_name: Name of the metric
            value: Metric value
            unit: Metric unit (Count, Seconds, Bytes, etc.)
            dimensions: Optional dimension key-value pairs
        """
        if not self.enabled:
            return

        metric_data = {
            "MetricName": metric_name,
            "Value": value,
            "Unit": unit,
            "Timestamp": datetime.now(timezone.utc),
        }

        if dimensions:
            metric_data["Dimensions"] = [
                {"Name": k, "Value": v} for k, v in dimensions.items()
            ]

        self._metric_buffer.append(metric_data)

        # Flush if buffer is full
        if len(self._metric_buffer) >= self._buffer_size:
            self.flush()

    def put_count(
        self,
        metric_name: str,
        count: int = 1,
        dimensions: Optional[Dict[str, str]] = None,
    ):
        """Convenience method for count metrics."""
        self.put_metric(metric_name, float(count), "Count", dimensions)

    def put_timing(
        self,
        metric_name: str,
        seconds: float,
        dimensions: Optional[Dict[str, str]] = None,
    ):
        """Convenience method for timing metrics in seconds."""
        self.put_metric(metric_name, seconds, "Seconds", dimensions)

    def flush(self):
        """Publish all buffered metrics to CloudWatch."""
        if not self._metric_buffer:
            return

        if self.dry_run:
            logging.debug(
                f"[DRY-RUN] Would publish {len(self._metric_buffer)} metrics to CloudWatch"
            )
            self._metric_buffer.clear()
            return

        if not self.enabled or not self._cloudwatch:
            self._metric_buffer.clear()
            return

        try:
            # Split into chunks of 20 (AWS limit)
            for i in range(0, len(self._metric_buffer), self._buffer_size):
                chunk = self._metric_buffer[i : i + self._buffer_size]
                self._cloudwatch.put_metric_data(
                    Namespace=self.namespace, MetricData=chunk
                )
            logging.debug(f"Published {len(self._metric_buffer)} metrics to CloudWatch")
        except ClientError as e:
            logging.warning(f"Failed to publish CloudWatch metrics: {e}")
        finally:
            self._metric_buffer.clear()


def is_valid_public_ipv4(ip_str: str) -> bool:
    """Checks if a string is a valid, public IPv4 address."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.version == 4
            and not ip.is_private
            and not ip.is_loopback
            and not ip.is_link_local
            and not ip.is_multicast
            and not ip.is_reserved
        )
    except ValueError:
        return False


def is_valid_public_ip(ip_str: str) -> Tuple[bool, int]:
    """
    Checks if a string is a valid, public IP address (IPv4 or IPv6).

    Args:
        ip_str: String representation of an IP address

    Returns:
        Tuple of (is_valid, version) where version is 4 or 6.
        Returns (False, 0) for invalid addresses.
    """
    try:
        ip = ipaddress.ip_address(ip_str)

        # Check if it's a public IP (not private, loopback, etc.)
        is_public = (
            not ip.is_private
            and not ip.is_loopback
            and not ip.is_link_local
            and not ip.is_multicast
            and not ip.is_reserved
        )

        # Additional check for IPv6 site-local addresses (deprecated but still exist)
        if ip.version == 6:
            # Check for unique local addresses (fc00::/7) - similar to private IPv4
            if ip_str.lower().startswith(('fc', 'fd')):
                is_public = False

        return (is_public, ip.version) if is_public else (False, ip.version)
    except ValueError:
        return (False, 0)


def load_aws_ip_ranges(
    file_path: Optional[str],
) -> Tuple[Set[ipaddress.IPv4Network], Set[ipaddress.IPv6Network]]:
    """
    Loads AWS IP ranges from ip-ranges.json file.

    Args:
        file_path: Path to the AWS ip-ranges.json file

    Returns:
        Tuple of (IPv4 networks set, IPv6 networks set) for efficient IP membership testing.

    Note:
        This function is maintained for backward compatibility.
        For O(log N) lookups with service verification, use load_aws_ip_ranges_with_index().
    """
    if not file_path:
        return set(), set()

    try:
        json_path = Path(file_path)
        if not json_path.exists():
            logging.warning(f"AWS IP ranges file not found: {file_path}")
            return set(), set()

        with open(json_path, "r") as f:
            data = json.load(f)

        aws_ipv4_networks = set()
        aws_ipv6_networks = set()

        # Load IPv4 prefixes
        for prefix in data.get("prefixes", []):
            ip_prefix = prefix.get("ip_prefix")
            if ip_prefix and "/" in ip_prefix:
                try:
                    network = ipaddress.ip_network(ip_prefix, strict=False)
                    if network.version == 4:
                        aws_ipv4_networks.add(network)
                except ValueError:
                    continue

        # Load IPv6 prefixes
        for prefix in data.get("ipv6_prefixes", []):
            ip_prefix = prefix.get("ipv6_prefix")
            if ip_prefix and "/" in ip_prefix:
                try:
                    network = ipaddress.ip_network(ip_prefix, strict=False)
                    if network.version == 6:
                        aws_ipv6_networks.add(network)
                except ValueError:
                    continue

        logging.info(
            f"Loaded {len(aws_ipv4_networks)} AWS IPv4 and {len(aws_ipv6_networks)} AWS IPv6 ranges from {file_path}"
        )
        return aws_ipv4_networks, aws_ipv6_networks

    except Exception as e:
        logging.warning(f"Error loading AWS IP ranges from {file_path}: {e}")
        return set(), set()


def load_aws_ip_ranges_with_index(
    file_path: Optional[str] = None,
    auto_download: bool = True,
) -> Tuple[Optional[AWSIPRangeIndex], Set[ipaddress.IPv4Network], Set[ipaddress.IPv6Network]]:
    """
    Load AWS IP ranges with O(log N) index and optional auto-download.

    This function provides:
    - Auto-download of ip-ranges.json if missing or stale
    - O(log N) bisect-based lookups via AWSIPRangeIndex
    - Service-based IP verification (Route53 health checks, CloudFront, etc.)
    - Backward-compatible network sets for legacy code

    Args:
        file_path: Path to ip-ranges.json file. If None, uses environment-appropriate default.
        auto_download: If True, download the file if missing or stale (default: True).
                       Set to False for air-gapped environments.

    Returns:
        Tuple of (AWSIPRangeIndex, IPv4 network set, IPv6 network set)
        - AWSIPRangeIndex: For O(log N) lookups and service verification. None if loading failed.
        - IPv4 networks: Set for backward compatibility
        - IPv6 networks: Set for backward compatibility
    """
    global _aws_ip_index

    # Determine file path
    if file_path is None:
        file_path = get_ip_ranges_path()

    # Try to load or download data
    data = None
    if auto_download:
        data = download_aws_ip_ranges(file_path)
    else:
        # Load without downloading
        path = Path(file_path)
        if path.exists():
            try:
                with open(path) as f:
                    data = json.load(f)
                logging.info(f"Loaded AWS IP ranges from {file_path}")
            except Exception as e:
                logging.warning(f"Failed to load {file_path}: {e}")
        else:
            logging.warning(
                f"AWS IP ranges file not found: {file_path}. "
                f"Use --no-auto-download-ip-ranges=false to auto-download."
            )

    if not data:
        return None, set(), set()

    # Build the index
    _aws_ip_index = AWSIPRangeIndex.from_json_data(data)

    # Also build network sets for backward compatibility
    aws_ipv4_networks = set()
    aws_ipv6_networks = set()

    for prefix in data.get("prefixes", []):
        ip_prefix = prefix.get("ip_prefix")
        if ip_prefix and "/" in ip_prefix:
            try:
                network = ipaddress.ip_network(ip_prefix, strict=False)
                if network.version == 4:
                    aws_ipv4_networks.add(network)
            except ValueError:
                continue

    for prefix in data.get("ipv6_prefixes", []):
        ip_prefix = prefix.get("ipv6_prefix")
        if ip_prefix and "/" in ip_prefix:
            try:
                network = ipaddress.ip_network(ip_prefix, strict=False)
                if network.version == 6:
                    aws_ipv6_networks.add(network)
            except ValueError:
                continue

    return _aws_ip_index, aws_ipv4_networks, aws_ipv6_networks


def is_aws_ip_fast(ip_str: str, aws_index: Optional[AWSIPRangeIndex] = None) -> bool:
    """
    O(log N) check if IP belongs to AWS ranges using bisect-based index.

    This is the preferred method for production use. Falls back to False if
    no index is available.

    Args:
        ip_str: IP address string to check
        aws_index: Optional AWSIPRangeIndex. If None, uses global _aws_ip_index.

    Returns:
        True if the IP belongs to AWS, False otherwise.
    """
    index = aws_index or _aws_ip_index
    if index is None:
        return False
    return index.is_aws_ip(ip_str)


def is_aws_ip(
    ip_str: str,
    aws_ipv4_networks: Set[ipaddress.IPv4Network],
    aws_ipv6_networks: Optional[Set[ipaddress.IPv6Network]] = None,
) -> bool:
    """
    Checks if an IP address belongs to AWS IP ranges.

    Args:
        ip_str: IP address string to check
        aws_ipv4_networks: Set of AWS IPv4 networks
        aws_ipv6_networks: Optional set of AWS IPv6 networks

    Returns:
        True if the IP belongs to AWS, False otherwise.
    """
    try:
        ip = ipaddress.ip_address(ip_str)

        if ip.version == 4:
            if not aws_ipv4_networks:
                return False
            return any(ip in network for network in aws_ipv4_networks)
        elif ip.version == 6:
            if not aws_ipv6_networks:
                return False
            return any(ip in network for network in aws_ipv6_networks)

        return False
    except ValueError:
        return False


class NaclAutoBlocker:
    """
    A class to manage the process of analyzing ALB logs and blocking attackers in NACLs.
    """

    def __init__(
        self,
        lb_name_pattern: str,
        region: str,
        lookback_str: str,
        threshold: int,
        start_rule: int,
        limit: int,
        whitelist_file: Optional[str],
        aws_ip_ranges_file: Optional[str],
        dry_run: bool,
        debug: bool,
        slack_token: Optional[str] = None,
        slack_channel: Optional[str] = None,
        ipinfo_token: Optional[str] = None,
        registry_file: Optional[str] = None,
        tier_config: Optional[List[Tuple]] = None,
        storage_backend: Optional[str] = None,
        dynamodb_table: Optional[str] = None,
        s3_state_bucket: Optional[str] = None,
        s3_state_key: Optional[str] = None,
        create_dynamodb_table: bool = False,
        # IPv6 support parameters
        start_rule_ipv6: int = 180,
        limit_ipv6: int = 20,
        enable_ipv6: bool = True,
        # Incremental processing
        force_reprocess: bool = False,
        # AWS WAF IP Set integration
        waf_ip_set_name: Optional[str] = None,
        waf_ip_set_scope: str = "REGIONAL",  # "REGIONAL" or "CLOUDFRONT"
        waf_ip_set_id: Optional[str] = None,
        create_waf_ip_set: bool = False,
        # Structured logging & CloudWatch metrics
        json_logging: bool = False,
        enable_cloudwatch_metrics: bool = False,
        cloudwatch_namespace: str = "AutoBlockAttackers",
        # Multi-signal threat detection
        enable_multi_signal: bool = True,
        threat_signals_config: Optional[Dict] = None,
        # Enhanced Slack notifications
        enhanced_slack: bool = False,
        # Athena integration for large-scale log analysis
        athena_enabled: bool = False,
        athena_database: str = "alb_logs",
        athena_output_location: Optional[str] = None,
        # Auto-download AWS IP ranges
        auto_download_ip_ranges: bool = True,
    ):
        setup_logging(debug, json_format=json_logging)
        logging.info("Initializing NaclAutoBlocker...")

        # Multi-signal threat detection configuration
        self._enable_multi_signal = enable_multi_signal
        self._threat_signals_config = threat_signals_config or DEFAULT_THREAT_SIGNALS_CONFIG.copy()
        if enable_multi_signal:
            logging.info(
                f"Multi-signal threat detection enabled (min score: {self._threat_signals_config['min_threat_score']})"
            )
        self.lb_name_pattern = lb_name_pattern
        self.region = region
        self.lookback_delta = self._parse_lookback_period(lookback_str)
        self.threshold = threshold

        # IPv4 NACL rule range
        end_rule = min(start_rule + limit, 100)
        self.deny_rule_range = range(start_rule, end_rule)  # Managed IPv4 DENY rules
        self.nacl_limit = limit

        # IPv6 NACL rule range (separate from IPv4)
        self.enable_ipv6 = enable_ipv6
        end_rule_ipv6 = min(start_rule_ipv6 + limit_ipv6, 200)
        self.deny_rule_range_ipv6 = range(start_rule_ipv6, end_rule_ipv6)
        self.nacl_limit_ipv6 = limit_ipv6

        if enable_ipv6:
            logging.info(f"IPv6 blocking enabled: rules {start_rule_ipv6}-{end_rule_ipv6 - 1}")

        logging.info("Loading whitelist and AWS IP ranges...")
        self.whitelist = self._load_whitelist(whitelist_file)

        # Load AWS IP ranges with O(log N) index and optional auto-download
        self._auto_download_ip_ranges = auto_download_ip_ranges
        self.aws_ip_index, self.aws_ipv4_networks, self.aws_ipv6_networks = load_aws_ip_ranges_with_index(
            file_path=aws_ip_ranges_file,
            auto_download=auto_download_ip_ranges,
        )
        # Keep backward compatibility
        self.aws_networks = self.aws_ipv4_networks

        # Store debug mode for logging control
        self._debug = debug

        self.dry_run = dry_run

        # Block registry for persistent time-based blocking
        self.registry_file = registry_file or "./block_registry.json"
        self.tier_config = tier_config or DEFAULT_TIER_CONFIG
        self.block_registry: Dict[str, Dict] = {}

        # Initialize storage backend
        self._storage_backend_type = storage_backend or "local"
        self._storage_backend = self._init_storage_backend(
            backend_type=self._storage_backend_type,
            registry_file=self.registry_file,
            dynamodb_table=dynamodb_table,
            s3_bucket=s3_state_bucket,
            s3_key=s3_state_key or "block_registry.json",
            region=region,
            create_dynamodb_table=create_dynamodb_table,
        )
        self._load_block_registry()

        # Initialize Slack client if credentials provided
        self.slack_client = None
        self._enhanced_slack = enhanced_slack
        if slack_token and slack_channel:
            notification_type = "enhanced" if enhanced_slack else "basic"
            logging.info(f"Initializing Slack notifications ({notification_type})...")
            self.slack_client = SlackClient(token=slack_token, channel=slack_channel)
        elif slack_token or slack_channel:
            logging.warning(
                "Slack token or channel provided but not both. Slack notifications disabled."
            )

        # Initialize ipinfo handler if token provided
        self.ipinfo_handler = None
        self.ipinfo_cache = {}  # Simple in-memory cache: {ip: (timestamp, data)}
        self.ipinfo_cache_ttl = 3600  # 1 hour cache TTL
        if ipinfo_token:
            logging.info("Initializing IPInfo geolocation service...")
            self.ipinfo_handler = ipinfo.getHandler(ipinfo_token)
        else:
            logging.info("No IPInfo token provided. IP geolocation disabled.")

        # IPInfo circuit breaker state
        self._ipinfo_failures = 0
        self._ipinfo_circuit_open = False
        self._ipinfo_failure_threshold = 3

        # Failed Slack messages queue for retry
        self._failed_slack_messages: List[Tuple[str, bool]] = []

        # S3 processing error tracking
        self._s3_processing_errors = 0

        # Skipped IPs tracking (for dry-run summary)
        self._skipped_ips: List[Tuple[str, float, Dict[str, Any]]] = []

        # Incremental log processing state
        self._force_reprocess = force_reprocess
        self._processed_files: Dict[str, str] = {}  # key -> etag
        self._processed_files_cache_key = "_processed_files_cache"
        self._skipped_files_count = 0
        self._new_files_count = 0

        # Load processed files cache (only if not force_reprocess)
        if not force_reprocess:
            self._load_processed_files_cache()
        else:
            logging.info("Force reprocess enabled - ignoring processed files cache")

        # Athena integration for large-scale log analysis
        self._athena_enabled = athena_enabled
        self._athena_database = athena_database
        self._athena_output_location = athena_output_location
        self._athena = None  # Lazy initialization
        if athena_enabled:
            if not athena_output_location:
                logging.warning(
                    "Athena enabled but no output location specified. "
                    "Use --athena-output-location to specify S3 path for query results."
                )
                self._athena_enabled = False
            else:
                logging.info(
                    f"Athena integration enabled (database: {athena_database}, "
                    f"output: {athena_output_location})"
                )

        logging.info("Initializing AWS clients (boto3)...")
        # Enhanced boto config with adaptive retries for production stability
        boto_config = Config(
            connect_timeout=10,
            read_timeout=30,
            retries={
                "max_attempts": 5,
                "mode": "adaptive",  # Exponential backoff with jitter
            },
        )
        self.ec2 = boto3.client("ec2", region_name=self.region, config=boto_config)
        self.elbv2 = boto3.client("elbv2", region_name=self.region, config=boto_config)
        self.s3 = boto3.client("s3", region_name=self.region, config=boto_config)
        self.sts = boto3.client("sts", region_name=self.region, config=boto_config)

        # AWS WAF IP Set integration
        self._waf_ip_set_name = waf_ip_set_name
        self._waf_ip_set_scope = waf_ip_set_scope.upper()
        self._waf_ip_set_id = waf_ip_set_id
        self._create_waf_ip_set = create_waf_ip_set
        self._waf_enabled = bool(waf_ip_set_name or waf_ip_set_id)
        self._waf_ip_set_lock_token: Optional[str] = None
        self._waf_max_addresses = 10000  # AWS WAF limit per IP set

        if self._waf_enabled:
            # CloudFront WAF must use us-east-1 region
            waf_region = "us-east-1" if self._waf_ip_set_scope == "CLOUDFRONT" else self.region
            self.wafv2 = boto3.client("wafv2", region_name=waf_region, config=boto_config)
            logging.info(
                f"AWS WAF integration enabled (scope: {self._waf_ip_set_scope}, region: {waf_region})"
            )
            self._init_waf_ip_set()
        else:
            self.wafv2 = None

        # Initialize CloudWatch metrics
        self._metrics = CloudWatchMetrics(
            namespace=cloudwatch_namespace,
            region=self.region,
            enabled=enable_cloudwatch_metrics,
            dry_run=dry_run,
        )

        logging.info("Initialization complete. Ready to run.")

    def _parse_lookback_period(self, lookback_str: str) -> timedelta:
        match = re.match(r"(\d+)([mhd])", lookback_str.lower())
        if not match:
            raise ValueError(
                f"Invalid lookback format: '{lookback_str}'. Use format like '30m', '2h', or '1d'."
            )
        value, unit = int(match.group(1)), match.group(2)
        if unit == "m":
            return timedelta(minutes=value)
        elif unit == "h":
            return timedelta(hours=value)
        else:  # unit == "d"
            return timedelta(days=value)

    def _init_storage_backend(
        self,
        backend_type: str,
        registry_file: str,
        dynamodb_table: Optional[str],
        s3_bucket: Optional[str],
        s3_key: str,
        region: str,
        create_dynamodb_table: bool,
    ) -> StorageBackend:
        """
        Initialize the appropriate storage backend based on configuration.

        Args:
            backend_type: Type of backend ('local', 'dynamodb', 's3')
            registry_file: Path to local registry file
            dynamodb_table: DynamoDB table name
            s3_bucket: S3 bucket name
            s3_key: S3 object key
            region: AWS region
            create_dynamodb_table: Whether to create DynamoDB table if missing

        Returns:
            StorageBackend: Configured storage backend instance
        """
        try:
            backend = create_storage_backend(
                backend_type=backend_type,
                local_file=registry_file,
                dynamodb_table=dynamodb_table,
                s3_bucket=s3_bucket,
                s3_key=s3_key,
                region=region,
                create_dynamodb_table=create_dynamodb_table,
            )
            logging.info(f"Storage backend initialized: {backend_type}")
            return backend
        except ValueError as e:
            logging.error(f"Invalid storage backend configuration: {e}")
            raise
        except Exception as e:
            logging.error(f"Failed to initialize storage backend: {e}")
            # Fall back to local storage
            logging.warning("Falling back to local file storage")
            return LocalFileBackend(file_path=registry_file)

    def _load_whitelist(self, file_path: Optional[str]) -> Set[str]:
        if not file_path:
            return set()
        try:
            with open(file_path, "r") as f:
                whitelist = {
                    line.strip()
                    for line in f
                    if line.strip() and not line.startswith("#")
                }
            logging.info(
                f"Successfully loaded {len(whitelist)} IPs from whitelist file: {file_path}"
            )
            return whitelist
        except FileNotFoundError:
            logging.warning(f"Whitelist file not found: {file_path}")
            return set()

    def _load_block_registry(self):
        """Loads the block registry from the configured storage backend."""
        try:
            self.block_registry = self._storage_backend.load()
            logging.info(f"Loaded block registry with {len(self.block_registry)} IPs")
        except StorageError as e:
            logging.warning(f"Storage backend error: {e}. Starting fresh.")
            self.block_registry = {}
        except Exception as e:
            logging.warning(f"Error loading block registry: {e}. Starting fresh.")
            self.block_registry = {}

    def _save_block_registry(self):
        """Saves the block registry to the configured storage backend."""
        if self.dry_run:
            logging.info("[DRY RUN] Would save block registry")
            return

        try:
            self._storage_backend.save(self.block_registry)
            logging.info(f"Saved block registry with {len(self.block_registry)} IPs")
        except StorageError as e:
            logging.error(f"Storage backend error saving registry: {e}")
        except Exception as e:
            logging.error(f"Failed to save block registry: {e}")

    def _determine_tier(self, hit_count: int) -> Tuple[str, timedelta, int]:
        """
        Determines the blocking tier based on hit count.
        Returns (tier_name, block_duration, priority)
        """
        for min_hits, duration, tier_name, priority in self.tier_config:
            if hit_count >= min_hits:
                return tier_name, duration, priority
        # Fallback to minimal tier
        return "minimal", timedelta(hours=1), 0

    def _get_registry_entry(self, ip: str) -> Optional[Dict]:
        """Gets registry entry for an IP, returns None if not found."""
        return self.block_registry.get(ip)

    def _update_registry_entry(self, ip: str, hit_count: int, now: datetime, ip_version: int = 4):
        """
        Updates or creates a registry entry for an IP.

        Args:
            ip: IP address to register
            hit_count: Number of malicious hits
            now: Current UTC datetime
            ip_version: IP version (4 or 6)
        """
        tier_name, duration, priority = self._determine_tier(hit_count)
        block_until = now + duration

        existing = self.block_registry.get(ip)
        if existing:
            # Update existing entry
            old_tier = existing.get("tier", "unknown")
            old_priority = existing.get("priority", 0)
            old_block_until = existing.get("block_until")
            # Preserve IP version from existing entry if not explicitly set
            existing_version = existing.get("ip_version", ip_version)

            # Keep the earlier first_seen timestamp
            first_seen = existing.get("first_seen", now.isoformat())

            # Only extend block time if tier upgraded (priority increased)
            if priority > old_priority:
                logging.info(
                    f"Upgrading {ip} (v{ip_version}) from {old_tier} to {tier_name} tier - extending block duration"
                )
                # Tier upgraded - reset block time with new duration
                final_block_until = block_until.isoformat()
            else:
                # Same or lower tier - keep existing block_until (don't reset timer)
                logging.debug(
                    f"IP {ip} detected again but tier unchanged ({tier_name}) - maintaining existing expiration"
                )
                final_block_until = old_block_until

            # Update with new data
            self.block_registry[ip] = {
                "first_seen": first_seen,
                "last_seen": now.isoformat(),
                "total_hits": max(hit_count, existing.get("total_hits", 0)),
                "tier": tier_name,
                "priority": priority,
                "block_until": final_block_until,
                "block_duration_hours": duration.total_seconds() / 3600,
                "ip_version": existing_version,
            }
        else:
            # Create new entry
            logging.info(f"New block for {ip} (IPv{ip_version}): tier={tier_name}, hits={hit_count}")
            self.block_registry[ip] = {
                "first_seen": now.isoformat(),
                "last_seen": now.isoformat(),
                "total_hits": hit_count,
                "tier": tier_name,
                "priority": priority,
                "block_until": block_until.isoformat(),
                "block_duration_hours": duration.total_seconds() / 3600,
                "ip_version": ip_version,
            }

    def _remove_registry_entry(self, ip: str):
        """Removes an IP from the registry."""
        if ip in self.block_registry:
            del self.block_registry[ip]

    def _load_processed_files_cache(self):
        """
        Load the processed files cache from storage backend.
        Uses a special key prefix to store alongside block registry.
        """
        try:
            if self._storage_backend_type == "local":
                # Store in a separate file for local backend
                cache_file = self.registry_file.replace(".json", "_processed.json")
                if os.path.exists(cache_file):
                    with open(cache_file, "r") as f:
                        self._processed_files = json.load(f)
                        logging.debug(f"Loaded {len(self._processed_files)} processed file records")
            else:
                # For cloud backends, retrieve from storage
                cached = self._storage_backend.get(self._processed_files_cache_key)
                if cached and isinstance(cached.get("files"), dict):
                    self._processed_files = cached["files"]
                    logging.debug(f"Loaded {len(self._processed_files)} processed file records")
        except Exception as e:
            logging.warning(f"Failed to load processed files cache: {e}")
            self._processed_files = {}

    def _save_processed_files_cache(self):
        """Save the processed files cache to storage backend."""
        if self.dry_run:
            logging.debug("[DRY RUN] Would save processed files cache")
            return

        try:
            if self._storage_backend_type == "local":
                cache_file = self.registry_file.replace(".json", "_processed.json")
                with open(cache_file, "w") as f:
                    json.dump(self._processed_files, f, indent=2)
            else:
                self._storage_backend.put(
                    self._processed_files_cache_key,
                    {
                        "files": self._processed_files,
                        "updated_at": datetime.now(timezone.utc).isoformat(),
                    },
                )
            logging.debug(f"Saved {len(self._processed_files)} processed file records")
        except Exception as e:
            logging.warning(f"Failed to save processed files cache: {e}")

    def _cleanup_old_processed_files(self, lookback_hours: float):
        """
        Remove processed file records older than 2x lookback period.

        Args:
            lookback_hours: Current lookback period in hours
        """
        if not self._processed_files:
            return

        now = datetime.now(timezone.utc)
        cutoff_hours = lookback_hours * 2  # Keep records for 2x lookback

        keys_to_remove = []
        for key, data in self._processed_files.items():
            try:
                # Parse the processed_at timestamp if it exists
                if isinstance(data, dict):
                    processed_at_str = data.get("processed_at")
                    if processed_at_str:
                        processed_at = datetime.fromisoformat(processed_at_str)
                        if processed_at.tzinfo is None:
                            processed_at = processed_at.replace(tzinfo=timezone.utc)
                        age_hours = (now - processed_at).total_seconds() / 3600
                        if age_hours > cutoff_hours:
                            keys_to_remove.append(key)
            except Exception:
                pass

        for key in keys_to_remove:
            del self._processed_files[key]

        if keys_to_remove:
            logging.info(f"Cleaned up {len(keys_to_remove)} old processed file records")

    def _is_file_already_processed(self, bucket: str, key: str, etag: str) -> bool:
        """
        Check if a file has already been processed (based on ETag).

        Args:
            bucket: S3 bucket name
            key: S3 object key
            etag: S3 object ETag

        Returns:
            True if file was already processed with same ETag
        """
        if self._force_reprocess:
            return False

        cache_key = f"{bucket}:{key}"
        cached = self._processed_files.get(cache_key)

        if cached:
            if isinstance(cached, dict):
                return cached.get("etag") == etag
            else:
                # Backward compatibility: cached value is just the etag
                return cached == etag

        return False

    def _mark_file_processed(self, bucket: str, key: str, etag: str):
        """
        Mark a file as processed.

        Args:
            bucket: S3 bucket name
            key: S3 object key
            etag: S3 object ETag
        """
        cache_key = f"{bucket}:{key}"
        self._processed_files[cache_key] = {
            "etag": etag,
            "processed_at": datetime.now(timezone.utc).isoformat(),
        }

    # -------------------------------------------------------------------------
    # AWS WAF IP Set Integration Methods
    # -------------------------------------------------------------------------

    def _init_waf_ip_set(self):
        """
        Initialize AWS WAF IP Set - find existing or create new if configured.
        """
        if not self._waf_enabled:
            return

        try:
            # If IP Set ID is provided, verify it exists
            if self._waf_ip_set_id:
                ip_set = self._get_waf_ip_set_by_id(self._waf_ip_set_id)
                if ip_set:
                    self._waf_ip_set_name = ip_set.get("Name", self._waf_ip_set_name)
                    logging.info(f"Using existing WAF IP Set: {self._waf_ip_set_name} ({self._waf_ip_set_id})")
                    return
                else:
                    logging.error(f"WAF IP Set ID {self._waf_ip_set_id} not found")
                    self._waf_enabled = False
                    return

            # Search by name
            if self._waf_ip_set_name:
                ip_set_id = self._find_waf_ip_set_by_name(self._waf_ip_set_name)
                if ip_set_id:
                    self._waf_ip_set_id = ip_set_id
                    logging.info(f"Found existing WAF IP Set: {self._waf_ip_set_name} ({ip_set_id})")
                    return

                # Create new IP set if requested
                if self._create_waf_ip_set:
                    self._create_waf_ip_set_resource()
                else:
                    logging.warning(
                        f"WAF IP Set '{self._waf_ip_set_name}' not found. "
                        "Use --create-waf-ip-set to create it."
                    )
                    self._waf_enabled = False

        except ClientError as e:
            logging.error(f"Error initializing WAF IP Set: {e}")
            self._waf_enabled = False

    def _get_waf_ip_set_by_id(self, ip_set_id: str) -> Optional[Dict]:
        """
        Get WAF IP Set details by ID.

        Args:
            ip_set_id: The WAF IP Set ID

        Returns:
            IP Set details dict or None if not found
        """
        try:
            response = self.wafv2.get_ip_set(
                Name=self._waf_ip_set_name or "unknown",
                Scope=self._waf_ip_set_scope,
                Id=ip_set_id,
            )
            self._waf_ip_set_lock_token = response.get("LockToken")
            return response.get("IPSet")
        except ClientError as e:
            if e.response["Error"]["Code"] == "WAFNonexistentItemException":
                return None
            raise

    def _find_waf_ip_set_by_name(self, name: str) -> Optional[str]:
        """
        Find WAF IP Set by name.

        Args:
            name: The IP Set name to search for

        Returns:
            IP Set ID if found, None otherwise
        """
        try:
            paginator = self.wafv2.get_paginator("list_ip_sets")
            for page in paginator.paginate(Scope=self._waf_ip_set_scope):
                for ip_set in page.get("IPSets", []):
                    if ip_set.get("Name") == name:
                        # Get the full IP set to retrieve lock token
                        full_ip_set = self.wafv2.get_ip_set(
                            Name=name,
                            Scope=self._waf_ip_set_scope,
                            Id=ip_set["Id"],
                        )
                        self._waf_ip_set_lock_token = full_ip_set.get("LockToken")
                        return ip_set["Id"]
            return None
        except ClientError as e:
            logging.error(f"Error listing WAF IP Sets: {e}")
            return None

    def _create_waf_ip_set_resource(self):
        """
        Create a new WAF IP Set.
        """
        if self.dry_run:
            logging.info(f"[DRY-RUN] Would create WAF IP Set: {self._waf_ip_set_name}")
            self._waf_enabled = False
            return

        try:
            response = self.wafv2.create_ip_set(
                Name=self._waf_ip_set_name,
                Scope=self._waf_ip_set_scope,
                Description=f"Auto-blocked attackers managed by aws-auto-block-attackers (v{__version__})",
                IPAddressVersion="IPV4",  # We'll handle IPv6 separately if needed
                Addresses=[],
                Tags=[
                    {"Key": "ManagedBy", "Value": "aws-auto-block-attackers"},
                    {"Key": "Version", "Value": __version__},
                ],
            )
            self._waf_ip_set_id = response["Summary"]["Id"]
            self._waf_ip_set_lock_token = response["Summary"]["LockToken"]
            logging.info(f"Created WAF IP Set: {self._waf_ip_set_name} ({self._waf_ip_set_id})")

            # Create IPv6 IP set if enabled
            if self.enable_ipv6:
                self._create_waf_ipv6_ip_set()

        except ClientError as e:
            logging.error(f"Failed to create WAF IP Set: {e}")
            self._waf_enabled = False

    def _create_waf_ipv6_ip_set(self):
        """
        Create a companion IPv6 WAF IP Set.
        """
        ipv6_name = f"{self._waf_ip_set_name}-ipv6"
        try:
            response = self.wafv2.create_ip_set(
                Name=ipv6_name,
                Scope=self._waf_ip_set_scope,
                Description=f"Auto-blocked IPv6 attackers managed by aws-auto-block-attackers (v{__version__})",
                IPAddressVersion="IPV6",
                Addresses=[],
                Tags=[
                    {"Key": "ManagedBy", "Value": "aws-auto-block-attackers"},
                    {"Key": "Version", "Value": __version__},
                ],
            )
            self._waf_ipv6_ip_set_id = response["Summary"]["Id"]
            self._waf_ipv6_ip_set_lock_token = response["Summary"]["LockToken"]
            logging.info(f"Created WAF IPv6 IP Set: {ipv6_name} ({self._waf_ipv6_ip_set_id})")
        except ClientError as e:
            logging.warning(f"Failed to create WAF IPv6 IP Set: {e}")

    def _get_waf_current_addresses(self) -> Set[str]:
        """
        Get current addresses in the WAF IP Set.

        Returns:
            Set of CIDR addresses currently in the IP set
        """
        if not self._waf_enabled or not self._waf_ip_set_id:
            return set()

        try:
            response = self.wafv2.get_ip_set(
                Name=self._waf_ip_set_name,
                Scope=self._waf_ip_set_scope,
                Id=self._waf_ip_set_id,
            )
            self._waf_ip_set_lock_token = response.get("LockToken")
            return set(response.get("IPSet", {}).get("Addresses", []))
        except ClientError as e:
            logging.error(f"Error getting WAF IP Set addresses: {e}")
            return set()

    def _sync_waf_ip_set(self, blocked_ips: Set[str]):
        """
        Synchronize blocked IPs with WAF IP Set.

        Args:
            blocked_ips: Set of IPs to block (will be converted to /32 CIDR)
        """
        if not self._waf_enabled or not self._waf_ip_set_id:
            return

        now = datetime.now(timezone.utc)

        # Get active blocks from registry (not expired)
        active_blocked_ips = set()
        for ip in blocked_ips:
            if ip in self.block_registry:
                data = self.block_registry[ip]
                block_until_str = data.get("block_until")
                if block_until_str:
                    try:
                        block_until = datetime.fromisoformat(block_until_str)
                        if block_until.tzinfo is None:
                            block_until = block_until.replace(tzinfo=timezone.utc)
                        if now < block_until:
                            active_blocked_ips.add(ip)
                    except Exception:
                        pass
            else:
                # New block, include it
                active_blocked_ips.add(ip)

        # Separate IPv4 and IPv6
        ipv4_ips = set()
        ipv6_ips = set()

        for ip in active_blocked_ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                if ip_obj.version == 4:
                    ipv4_ips.add(f"{ip}/32")
                else:
                    ipv6_ips.add(f"{ip}/128")
            except ValueError:
                logging.warning(f"Invalid IP address for WAF sync: {ip}")

        # Sync IPv4 IP Set
        self._update_waf_ip_set_addresses(ipv4_ips, is_ipv6=False)

        # Sync IPv6 IP Set if we have IPv6 addresses and IPv6 is enabled
        if ipv6_ips and self.enable_ipv6 and hasattr(self, "_waf_ipv6_ip_set_id"):
            self._update_waf_ip_set_addresses(ipv6_ips, is_ipv6=True)

    def _update_waf_ip_set_addresses(self, target_addresses: Set[str], is_ipv6: bool = False):
        """
        Update WAF IP Set with target addresses (add missing, remove stale).

        Args:
            target_addresses: Set of CIDR addresses that should be in the IP set
            is_ipv6: Whether this is for the IPv6 IP set
        """
        if is_ipv6:
            if not hasattr(self, "_waf_ipv6_ip_set_id") or not self._waf_ipv6_ip_set_id:
                return
            ip_set_id = self._waf_ipv6_ip_set_id
            ip_set_name = f"{self._waf_ip_set_name}-ipv6"
            lock_token_attr = "_waf_ipv6_ip_set_lock_token"
        else:
            ip_set_id = self._waf_ip_set_id
            ip_set_name = self._waf_ip_set_name
            lock_token_attr = "_waf_ip_set_lock_token"

        try:
            # Get current addresses
            response = self.wafv2.get_ip_set(
                Name=ip_set_name,
                Scope=self._waf_ip_set_scope,
                Id=ip_set_id,
            )
            current_addresses = set(response.get("IPSet", {}).get("Addresses", []))
            lock_token = response.get("LockToken")
            setattr(self, lock_token_attr, lock_token)

            # Calculate changes
            to_add = target_addresses - current_addresses
            to_remove = current_addresses - target_addresses

            if not to_add and not to_remove:
                logging.debug(f"WAF IP Set {ip_set_name} already in sync")
                return

            # Merge current with changes
            new_addresses = (current_addresses | to_add) - to_remove

            # Check WAF limits
            if len(new_addresses) > self._waf_max_addresses:
                logging.warning(
                    f"WAF IP Set would exceed {self._waf_max_addresses} addresses. "
                    f"Truncating to limit."
                )
                # Prioritize keeping newer/higher-priority blocks
                # For simplicity, just truncate (in production, implement smarter logic)
                new_addresses = set(list(new_addresses)[: self._waf_max_addresses])

            ip_version = "IPv6" if is_ipv6 else "IPv4"
            if self.dry_run:
                logging.info(
                    f"[DRY-RUN] Would update WAF {ip_version} IP Set: "
                    f"+{len(to_add)} -{len(to_remove)} addresses"
                )
                return

            # Update IP set
            self.wafv2.update_ip_set(
                Name=ip_set_name,
                Scope=self._waf_ip_set_scope,
                Id=ip_set_id,
                Addresses=list(new_addresses),
                LockToken=lock_token,
            )

            logging.info(
                f"Updated WAF {ip_version} IP Set: +{len(to_add)} -{len(to_remove)} addresses "
                f"(total: {len(new_addresses)})"
            )

            # Send Slack notification for significant changes
            if self.slack_client and (len(to_add) >= 5 or len(to_remove) >= 5):
                self._send_slack_message(
                    f"WAF {ip_version} IP Set updated: +{len(to_add)} -{len(to_remove)} addresses "
                    f"(total: {len(new_addresses)})",
                    is_error=False,
                )

        except ClientError as e:
            error_code = e.response["Error"]["Code"]
            if error_code == "WAFOptimisticLockException":
                logging.warning("WAF IP Set was modified concurrently, retrying...")
                # Retry once
                self._update_waf_ip_set_addresses(target_addresses, is_ipv6)
            else:
                logging.error(f"Failed to update WAF IP Set: {e}")

    def _cleanup_expired_waf_entries(self, expired_ips: Set[str]):
        """
        Remove expired IPs from WAF IP Set.

        Args:
            expired_ips: Set of IPs whose blocks have expired
        """
        if not self._waf_enabled or not expired_ips:
            return

        # Get current active blocks from registry
        now = datetime.now(timezone.utc)
        active_ips = set()

        for ip, data in self.block_registry.items():
            if ip in expired_ips:
                continue
            block_until_str = data.get("block_until")
            if block_until_str:
                try:
                    block_until = datetime.fromisoformat(block_until_str)
                    if block_until.tzinfo is None:
                        block_until = block_until.replace(tzinfo=timezone.utc)
                    if now < block_until:
                        active_ips.add(ip)
                except Exception:
                    pass

        # Sync with remaining active IPs
        self._sync_waf_ip_set(active_ips)

    def _get_waf_statistics(self) -> Dict:
        """
        Get statistics about WAF IP Set usage.

        Returns:
            Dict with WAF statistics
        """
        if not self._waf_enabled:
            return {"enabled": False}

        stats = {
            "enabled": True,
            "scope": self._waf_ip_set_scope,
            "ip_set_id": self._waf_ip_set_id,
            "ip_set_name": self._waf_ip_set_name,
        }

        try:
            current = self._get_waf_current_addresses()
            stats["ipv4_count"] = len([a for a in current if "." in a])
            stats["capacity_used"] = len(current)
            stats["capacity_max"] = self._waf_max_addresses
            stats["capacity_percent"] = round(len(current) / self._waf_max_addresses * 100, 1)
        except Exception as e:
            stats["error"] = str(e)

        return stats

    def _get_expired_blocks(self, now: datetime) -> Set[str]:
        """Returns set of IPs whose blocks have expired."""
        expired = set()
        for ip, data in self.block_registry.items():
            try:
                block_until_str = data.get("block_until")
                if block_until_str:
                    block_until = datetime.fromisoformat(block_until_str)
                    # Make timezone-aware if needed
                    if block_until.tzinfo is None:
                        block_until = block_until.replace(tzinfo=timezone.utc)
                    if now >= block_until:
                        expired.add(ip)
            except Exception as e:
                logging.warning(f"Error checking expiry for {ip}: {e}")
        return expired

    def _cleanup_old_registry_entries(self, now: datetime, days_old: int = 30):
        """Remove very old expired entries from registry to prevent unbounded growth."""
        # For DynamoDB backend, TTL handles cleanup automatically
        if self._storage_backend_type == "dynamodb":
            logging.debug("DynamoDB TTL handles automatic cleanup - skipping manual cleanup")
            return

        cutoff_time = now - timedelta(days=days_old)
        old_entries = []

        for ip, data in self.block_registry.items():
            try:
                block_until_str = data.get("block_until")
                if block_until_str:
                    block_until = datetime.fromisoformat(block_until_str)
                    if block_until.tzinfo is None:
                        block_until = block_until.replace(tzinfo=timezone.utc)
                    # If expired more than `days_old` ago, mark for removal
                    if block_until < cutoff_time:
                        old_entries.append(ip)
            except Exception as e:
                logging.warning(f"Error checking age for {ip}: {e}")

        if old_entries:
            logging.info(
                f"Cleaning {len(old_entries)} old registry entries (expired >{days_old} days ago)"
            )
            for ip in old_entries:
                del self.block_registry[ip]
                # Also delete from storage backend if using S3 (to keep in sync)
                if self._storage_backend_type == "s3":
                    try:
                        self._storage_backend.delete(ip)
                    except Exception:
                        pass  # Will be cleaned up on next full save

    def _get_active_blocks(self, now: datetime) -> Dict[str, Dict]:
        """Returns dict of IPs that should still be blocked (not expired)."""
        active = {}
        for ip, data in self.block_registry.items():
            try:
                block_until_str = data.get("block_until")
                if block_until_str:
                    block_until = datetime.fromisoformat(block_until_str)
                    # Make timezone-aware if needed
                    if block_until.tzinfo is None:
                        block_until = block_until.replace(tzinfo=timezone.utc)
                    if now < block_until:
                        active[ip] = data
            except Exception as e:
                logging.warning(f"Error checking active status for {ip}: {e}")
        return active

    def run(self):
        """Executes the entire blocking process."""
        import time

        run_start_time = time.time()

        logging.info(
            "--- Starting Automated Attacker Blocking Script (Tiered Persistence Mode) ---"
        )
        if self.dry_run:
            logging.warning("*** RUNNING IN DRY RUN MODE. NO CHANGES WILL BE MADE. ***")

        # Reset error counters for this run
        self._s3_processing_errors = 0
        self._ipinfo_failures = 0
        self._ipinfo_circuit_open = False
        self._failed_slack_messages.clear()

        # Track metrics dimensions
        metrics_dimensions = {"Region": self.region}

        now = datetime.now(timezone.utc)

        logging.info("Step 1/7: Discovering target load balancers...")
        target_lbs = self._discover_target_lbs()
        if not target_lbs:
            return

        logging.info("Step 2/7: Extracting log locations from load balancers...")
        unique_log_locations = {
            (lb["LogBucket"], lb["LogPrefix"])
            for lb in target_lbs.values()
            if "LogBucket" in lb
        }
        if not unique_log_locations:
            logging.error(
                "No load balancers with logging enabled found matching the pattern."
            )
            return
        logging.info(f"Found {len(unique_log_locations)} unique log location(s).")

        logging.info("Step 3/7: Finding NACL for subnets...")
        nacl_id = self._find_nacl_for_subnets(target_lbs)
        if not nacl_id:
            return

        # Capture initially blocked IPs early for comparison later
        initial_deny_rules, _ = self._get_nacl_rules(nacl_id)
        initially_blocked_ips = {
            cidr.split("/")[0] for cidr in initial_deny_rules.values()
        }

        # Step 4: Check for expired blocks and remove them
        logging.info("Step 4/7: Checking for expired blocks in registry...")
        expired_ips = self._get_expired_blocks(now)
        if expired_ips:
            logging.info(f"Found {len(expired_ips)} expired block(s): {expired_ips}")
            # Remove from NACL first, then from registry
            for rule_num, cidr in initial_deny_rules.items():
                ip = cidr.split("/")[0]
                if ip in expired_ips and rule_num in self.deny_rule_range:
                    self._delete_deny_rule_with_reason(
                        nacl_id, ip, rule_num, "Block expired"
                    )

            # Now remove from registry
            for ip in expired_ips:
                self._remove_registry_entry(ip)

            # Cleanup WAF IP Set as well
            if self._waf_enabled:
                self._cleanup_expired_waf_entries(expired_ips)

            # Emit metric for expired blocks
            self._metrics.put_count("BlocksExpired", len(expired_ips), metrics_dimensions)
        else:
            logging.info("No expired blocks found.")
            self._metrics.put_count("BlocksExpired", 0, metrics_dimensions)

        # Periodic cleanup of very old entries (prevents unbounded growth)
        self._cleanup_old_registry_entries(now, days_old=30)

        logging.info("Step 5/7: Scanning S3 for ALB log files...")
        start_scan_time = now - self.lookback_delta

        # Cleanup old processed file records (2x lookback period)
        lookback_hours = self.lookback_delta.total_seconds() / 3600
        self._cleanup_old_processed_files(lookback_hours)

        all_log_keys = []
        files_with_etags: Dict[str, str] = {}  # key -> etag mapping for marking processed

        for bucket, prefix in unique_log_locations:
            file_tuples = self._find_log_files_in_window(bucket, prefix, start_scan_time)
            for key, etag in file_tuples:
                all_log_keys.append((bucket, key))
                files_with_etags[f"{bucket}:{key}"] = etag

        logging.info(f"Step 6/7: Processing {len(all_log_keys)} log file(s)...")

        # Emit metric for files processed
        self._metrics.put_count("LogFilesProcessed", len(all_log_keys), metrics_dimensions)

        # Process logs and get new offenders
        new_offenders = set()
        ip_counts: Counter = Counter()
        ip_versions: Dict[str, int] = {}  # Track IP version for each IP

        if all_log_keys:
            all_malicious_ips_with_version = self._process_logs_in_parallel(all_log_keys)
            if all_malicious_ips_with_version:
                # Count IPs and track versions
                for ip, version in all_malicious_ips_with_version:
                    ip_counts[ip] += 1
                    ip_versions[ip] = version  # Store the version

                # Identify new offenders (both IPv4 and IPv6)
                new_offenders = set()
                for ip, count in ip_counts.items():
                    if count < self.threshold:
                        continue
                    if ip in self.whitelist:
                        continue

                    # Check AWS IP with appropriate network list
                    version = ip_versions.get(ip, 4)
                    if version == 4:
                        if is_aws_ip(ip, self.aws_ipv4_networks, None):
                            continue
                    elif version == 6:
                        if is_aws_ip(ip, set(), self.aws_ipv6_networks):
                            continue

                    new_offenders.add(ip)

                # Multi-signal threat filtering (when enabled)
                if self._enable_multi_signal and new_offenders:
                    logging.info("Applying multi-signal threat detection...")
                    multi_signal_offenders = self._filter_by_multi_signal(
                        new_offenders, all_log_keys, metrics_dimensions
                    )
                    filtered_count = len(new_offenders) - len(multi_signal_offenders)
                    if filtered_count > 0:
                        logging.info(
                            f"Multi-signal filtering: {filtered_count} potential false positive(s) removed"
                        )
                        self._metrics.put_count("FalsePositivesFiltered", filtered_count, metrics_dimensions)
                    new_offenders = multi_signal_offenders

                # Emit metric for total malicious hits detected
                self._metrics.put_count(
                    "MaliciousHitsDetected",
                    len(all_malicious_ips_with_version),
                    metrics_dimensions,
                )

                if new_offenders:
                    ipv4_count = sum(1 for ip in new_offenders if ip_versions.get(ip, 4) == 4)
                    ipv6_count = sum(1 for ip in new_offenders if ip_versions.get(ip, 4) == 6)
                    logging.warning(
                        f"Identified {len(new_offenders)} new offender(s) from recent logs "
                        f"(IPv4: {ipv4_count}, IPv6: {ipv6_count})"
                    )

                    # Emit metrics for new offenders
                    self._metrics.put_count("NewOffendersIPv4", ipv4_count, metrics_dimensions)
                    self._metrics.put_count("NewOffendersIPv6", ipv6_count, metrics_dimensions)
                    self._metrics.put_count("NewOffendersTotal", len(new_offenders), metrics_dimensions)

                    # Update registry with new offenders (including IP version)
                    for ip in new_offenders:
                        version = ip_versions.get(ip, 4)
                        self._update_registry_entry(ip, ip_counts[ip], now, version)
                else:
                    self._metrics.put_count("NewOffendersTotal", 0, metrics_dimensions)

                # Mark processed files (even if no malicious activity found)
                for cache_key, etag in files_with_etags.items():
                    parts = cache_key.split(":", 1)
                    if len(parts) == 2:
                        self._mark_file_processed(parts[0], parts[1], etag)
            else:
                logging.info("No malicious activity found in recent log files.")
                # Still mark files as processed
                for cache_key, etag in files_with_etags.items():
                    parts = cache_key.split(":", 1)
                    if len(parts) == 2:
                        self._mark_file_processed(parts[0], parts[1], etag)
        else:
            logging.info("No relevant log files found in lookback window.")

        # Get all IPs that should be blocked (active blocks from registry)
        active_blocks = self._get_active_blocks(now)
        ips_to_block = set(active_blocks.keys())

        logging.info(f"Total active blocks in registry: {len(ips_to_block)}")

        logging.info("Step 7/7: Updating NACL rules with time-based blocks...")
        self._update_nacl_rules_with_registry(nacl_id, ips_to_block, active_blocks)

        # Sync blocked IPs to WAF IP Set (if enabled)
        if self._waf_enabled:
            logging.info("Syncing blocked IPs to WAF IP Set...")
            self._sync_waf_ip_set(ips_to_block)

        # Save registry and processed files cache
        self._save_block_registry()
        self._save_processed_files_cache()

        final_deny_rules, _ = self._get_nacl_rules(nacl_id)
        final_blocked_ips = {cidr.split("/")[0] for cidr in final_deny_rules.values()}
        self._generate_report(
            ip_counts, new_offenders, final_blocked_ips, active_blocks
        )

        # Send summary notification to Slack (only if there were changes)
        if self._enhanced_slack:
            self._send_enhanced_slack_notification(
                new_offenders,
                final_blocked_ips,
                ip_counts,
                initially_blocked_ips,
                active_blocks,
            )
        else:
            self._send_summary_notification_with_registry(
                new_offenders,
                final_blocked_ips,
                ip_counts,
                initially_blocked_ips,
                active_blocks,
            )

        # Retry any failed Slack notifications
        self._retry_failed_slack_messages()

        # Emit metrics for active blocks
        self._metrics.put_count("ActiveBlocksTotal", len(ips_to_block), metrics_dimensions)
        self._metrics.put_count("NACLBlockedIPs", len(final_blocked_ips), metrics_dimensions)

        # Log execution summary with error counts
        if self._s3_processing_errors > 0:
            logging.warning(f"S3 processing errors during this run: {self._s3_processing_errors} file(s) skipped")
            self._metrics.put_count("S3ProcessingErrors", self._s3_processing_errors, metrics_dimensions)
        if self._ipinfo_circuit_open:
            logging.warning("IPInfo was disabled during this run due to repeated failures")
            self._metrics.put_count("IPInfoCircuitBreakerTripped", 1, metrics_dimensions)

        # Emit run timing metric
        run_duration = time.time() - run_start_time
        self._metrics.put_timing("RunDuration", run_duration, metrics_dimensions)

        # Flush all buffered metrics
        self._metrics.flush()

        logging.info(f"--- Script Finished (duration: {run_duration:.2f}s) ---")

    def _discover_target_lbs(self) -> Optional[Dict[str, Dict]]:
        """Finds all LBs matching the pattern and their details."""
        logging.info(
            f"Discovering load balancers matching pattern: '{self.lb_name_pattern}'..."
        )
        target_lbs = {}
        try:
            paginator = self.elbv2.get_paginator("describe_load_balancers")
            for page in paginator.paginate():
                for lb in page["LoadBalancers"]:
                    if fnmatch.fnmatch(lb["LoadBalancerName"], self.lb_name_pattern):
                        logging.debug(f"Found matching LB: {lb['LoadBalancerName']}")
                        target_lbs[lb["LoadBalancerArn"]] = {
                            "Name": lb["LoadBalancerName"],
                            "VpcId": lb["VpcId"],
                            "SubnetIds": [
                                az["SubnetId"] for az in lb["AvailabilityZones"]
                            ],
                        }

            if not target_lbs:
                logging.error(
                    f"No load balancers found matching pattern '{self.lb_name_pattern}'."
                )
                return None

            logging.info(
                f"Found {len(target_lbs)} total LBs matching pattern. Checking for logging attributes..."
            )

            # --- IMPROVEMENT: More verbose logging for excluded LBs ---
            lbs_with_logging = {}
            lb_count = 0
            total_lbs = len(target_lbs)
            for arn, details in target_lbs.items():
                lb_count += 1
                logging.info(
                    f"Checking logging config for LB {lb_count}/{total_lbs}: {details['Name']}"
                )
                attrs = self.elbv2.describe_load_balancer_attributes(
                    LoadBalancerArn=arn
                )["Attributes"]
                attr_map = {a["Key"]: a["Value"] for a in attrs}
                if attr_map.get("access_logs.s3.enabled") == "true":
                    details["LogBucket"] = attr_map.get("access_logs.s3.bucket")
                    details["LogPrefix"] = attr_map.get("access_logs.s3.prefix")
                    lbs_with_logging[arn] = details
                else:
                    logging.warning(
                        f"Excluding LB '{details['Name']}' because access logging is not enabled."
                    )

            logging.info(
                f"Found {len(lbs_with_logging)} LBs with logging enabled for analysis."
            )
            return lbs_with_logging
        except Exception as e:
            logging.error(f"An error occurred during load balancer discovery: {e}")
            return None

    def _find_nacl_for_subnets(self, target_lbs: Dict[str, Dict]) -> Optional[str]:
        """Finds a single, shared NACL for all discovered LBs."""
        all_vpc_ids = {lb["VpcId"] for lb in target_lbs.values()}
        if len(all_vpc_ids) > 1:
            logging.error(
                f"Discovered LBs span multiple VPCs: {list(all_vpc_ids)}. This is not supported."
            )
            return None

        vpc_id = all_vpc_ids.pop()
        all_subnet_ids = list({
            subnet for lb in target_lbs.values() for subnet in lb["SubnetIds"]
        })

        try:
            response = self.ec2.describe_network_acls(
                Filters=[{"Name": "association.subnet-id", "Values": all_subnet_ids}]
            )
            if response["NetworkAcls"]:
                nacl_id = response["NetworkAcls"][0]["NetworkAclId"]
                logging.info(f"Found explicitly associated Network ACL: {nacl_id}")
                return nacl_id
            else:
                response = self.ec2.describe_network_acls(
                    Filters=[
                        {"Name": "vpc-id", "Values": [vpc_id]},
                        {"Name": "default", "Values": ["true"]},
                    ]
                )
                if response["NetworkAcls"]:
                    nacl_id = response["NetworkAcls"][0]["NetworkAclId"]
                    logging.info(f"Found default Network ACL for the VPC: {nacl_id}")
                    return nacl_id
        except Exception as e:
            logging.error(f"Error finding NACL for VPC {vpc_id}: {e}")
        return None

    def _find_log_files_in_window(
        self, bucket: str, prefix: str, start_time: datetime
    ) -> List[Tuple[str, str]]:
        """
        Find log files within the lookback window.

        Args:
            bucket: S3 bucket name
            prefix: S3 prefix for logs
            start_time: Start of lookback window

        Returns:
            List of tuples (key, etag) for each log file found.
        """
        try:
            paginator = self.s3.get_paginator("list_objects_v2")
            account_id = self.sts.get_caller_identity().get("Account")
            base_prefix = (
                f"{prefix}/AWSLogs/{account_id}/elasticloadbalancing/{self.region}/"
            )

            # OPTIMIZATION: Generate date-specific prefixes to reduce S3 scan scope
            # ALB logs are organized by date: .../2025/10/06/file.log.gz
            date_prefixes = []
            current_date = start_time.date()
            end_date = datetime.now(timezone.utc).date()

            while current_date <= end_date:
                date_prefix = f"{base_prefix}{current_date.year:04d}/{current_date.month:02d}/{current_date.day:02d}/"
                date_prefixes.append(date_prefix)
                current_date += timedelta(days=1)

            logging.info(
                f"Searching for logs in s3://{bucket}/{base_prefix} "
                f"across {len(date_prefixes)} date(s) from {start_time.date()} to {end_date}"
            )

            all_files = []
            new_files = []
            skipped_files = 0

            # Scan each date prefix separately (much faster than scanning all dates)
            for date_prefix in date_prefixes:
                pages = paginator.paginate(
                    Bucket=bucket,
                    Prefix=date_prefix,
                    PaginationConfig={"MaxItems": 10000},  # Per-date limit
                )

                for page in pages:
                    if "Contents" in page:
                        for obj in page["Contents"]:
                            if (
                                not obj["Key"].endswith("/")
                                and obj["LastModified"] >= start_time
                            ):
                                key = obj["Key"]
                                etag = obj.get("ETag", "").strip('"')

                                all_files.append((key, etag))

                                # Check if already processed (incremental processing)
                                if self._is_file_already_processed(bucket, key, etag):
                                    skipped_files += 1
                                else:
                                    new_files.append((key, etag))

            # Update counters for metrics
            self._new_files_count = len(new_files)
            self._skipped_files_count = skipped_files

            if skipped_files > 0:
                logging.info(
                    f"S3 scan complete: found {len(all_files)} file(s), "
                    f"skipping {skipped_files} already-processed, "
                    f"processing {len(new_files)} new file(s)"
                )
            else:
                logging.info(
                    f"S3 scan complete: found {len(new_files)} file(s) to process "
                    f"across {len(date_prefixes)} date(s)."
                )

            return new_files
        except Exception as e:
            logging.error(f"Error listing S3 objects for prefix {prefix}: {e}")
            return []

    def _process_logs_in_parallel(
        self, bucket_key_pairs: List[Tuple[str, str]]
    ) -> List[Tuple[str, int]]:
        """
        Uses a thread pool to download and parse logs concurrently.

        Returns:
            List of tuples (ip_address, ip_version) for all malicious IPs found.
        """
        all_malicious_ips: List[Tuple[str, int]] = []
        total_files = len(bucket_key_pairs)
        completed_files = 0

        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_key = {
                executor.submit(self._download_and_parse_log, bucket, key): (
                    bucket,
                    key,
                )
                for bucket, key in bucket_key_pairs
            }
            for future in as_completed(future_to_key):
                completed_files += 1
                try:
                    ips_from_file = future.result()
                    all_malicious_ips.extend(ips_from_file)

                    # Progress update every 10 files or at completion
                    if completed_files % 10 == 0 or completed_files == total_files:
                        logging.info(
                            f"Log processing progress: {completed_files}/{total_files} files "
                            f"({completed_files * 100 // total_files}%) - found {len(all_malicious_ips)} malicious requests so far"
                        )
                except Exception as e:
                    logging.error(f"Error processing a log file in thread: {e}")
        return all_malicious_ips

    def _download_and_parse_log(self, bucket: str, key: str) -> List[Tuple[str, int]]:
        """
        Download and parse a single ALB log file from S3.

        Args:
            bucket: S3 bucket name
            key: S3 object key

        Returns:
            List of tuples (ip_address, ip_version) for malicious IPs found.
            Returns empty list on error (logged but not raised).
        """
        filename = key.split("/")[-1]
        logging.debug(f"Starting processing for file: {filename}")

        try:
            response = self.s3.get_object(Bucket=bucket, Key=key)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("NoSuchKey", "AccessDenied"):
                logging.warning(f"S3 access error for {filename}: {error_code} - skipping file")
            else:
                logging.error(f"S3 error fetching {filename}: {e} - skipping file")
            self._s3_processing_errors += 1
            return []
        except Exception as e:
            logging.error(f"Unexpected error fetching {filename} from S3: {e} - skipping file")
            self._s3_processing_errors += 1
            return []

        try:
            with gzip.open(response["Body"], "rt") as f:
                malicious_ips = []
                for line in f:
                    if ATTACK_PATTERNS.search(line):
                        parts = line.split()
                        if len(parts) > 3:
                            # Client IP:port is in field 4 (index 3)
                            client_field = parts[3]

                            # Handle IPv6 addresses which may be in brackets [::1]:port
                            if client_field.startswith('['):
                                # IPv6 format: [::1]:port
                                bracket_end = client_field.find(']')
                                if bracket_end > 0:
                                    ip_str = client_field[1:bracket_end]
                                else:
                                    continue
                            else:
                                # IPv4 format: 1.2.3.4:port
                                ip_str = client_field.split(":")[0]

                            # Check if it's a valid public IP (v4 or v6)
                            is_valid, ip_version = is_valid_public_ip(ip_str)
                            if is_valid:
                                # If IPv6 disabled, skip IPv6 addresses
                                if ip_version == 6 and not self.enable_ipv6:
                                    continue
                                malicious_ips.append((ip_str, ip_version))
                            elif is_valid_public_ipv4(ip_str):
                                # Fallback for backward compatibility
                                malicious_ips.append((ip_str, 4))

            logging.debug(
                f"Finished processing file: {filename}, found {len(malicious_ips)} malicious IPs."
            )
            return malicious_ips
        except gzip.BadGzipFile as e:
            logging.warning(f"Corrupted gzip file {filename}: {e} - skipping file")
            self._s3_processing_errors += 1
            return []
        except Exception as e:
            logging.error(f"Error parsing log file {filename}: {e} - skipping file")
            self._s3_processing_errors += 1
            return []

    def _download_and_parse_log_multi_signal(
        self, bucket: str, key: str
    ) -> Dict[str, ThreatSignals]:
        """
        Download and parse a log file with multi-signal threat detection.

        Extracts additional signals beyond attack patterns:
        - HTTP status codes (4xx/5xx)
        - User-agent analysis
        - Request paths for diversity scoring

        Args:
            bucket: S3 bucket name
            key: S3 object key

        Returns:
            Dict mapping IP addresses to their ThreatSignals objects.
        """
        filename = key.split("/")[-1]
        logging.debug(f"Multi-signal processing for file: {filename}")

        ip_signals: Dict[str, ThreatSignals] = {}

        try:
            response = self.s3.get_object(Bucket=bucket, Key=key)
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ("NoSuchKey", "AccessDenied"):
                logging.warning(f"S3 access error for {filename}: {error_code} - skipping file")
            else:
                logging.error(f"S3 error fetching {filename}: {e} - skipping file")
            self._s3_processing_errors += 1
            return {}
        except Exception as e:
            logging.error(f"Unexpected error fetching {filename} from S3: {e} - skipping file")
            self._s3_processing_errors += 1
            return {}

        try:
            with gzip.open(response["Body"], "rt") as f:
                for line in f:
                    # Parse ALB log line
                    # ALB log format fields:
                    # 0: type, 1: timestamp, 2: elb, 3: client:port, 4: target:port,
                    # 5: request_processing_time, 6: target_processing_time,
                    # 7: response_processing_time, 8: elb_status_code,
                    # 9: target_status_code, 10: received_bytes, 11: sent_bytes,
                    # 12: "request", 13: "user_agent", ...

                    parts = line.split()
                    if len(parts) < 14:
                        continue

                    # Extract client IP
                    client_field = parts[3]
                    if client_field.startswith('['):
                        bracket_end = client_field.find(']')
                        if bracket_end > 0:
                            ip_str = client_field[1:bracket_end]
                        else:
                            continue
                    else:
                        ip_str = client_field.split(":")[0]

                    # Check if valid public IP
                    is_valid, ip_version = is_valid_public_ip(ip_str)
                    if not is_valid:
                        continue

                    # Skip IPv6 if disabled
                    if ip_version == 6 and not self.enable_ipv6:
                        continue

                    # Parse status code (ELB status code at index 8)
                    try:
                        status_code = int(parts[8])
                    except (ValueError, IndexError):
                        status_code = 0

                    # Parse request (at index 12, quoted)
                    # Format: "GET /path HTTP/1.1"
                    request_field = ""
                    try:
                        # Find quoted request field
                        quote_start = line.find('"')
                        if quote_start >= 0:
                            quote_end = line.find('"', quote_start + 1)
                            if quote_end > quote_start:
                                request_field = line[quote_start + 1 : quote_end]
                    except Exception:
                        pass

                    # Extract path from request
                    path = "/"
                    if request_field:
                        request_parts = request_field.split()
                        if len(request_parts) >= 2:
                            path = request_parts[1].split("?")[0]  # Remove query string

                    # Parse user agent (second quoted field after request)
                    user_agent = ""
                    try:
                        first_quote_end = line.find('"', line.find('"') + 1)
                        if first_quote_end >= 0:
                            ua_start = line.find('"', first_quote_end + 1)
                            if ua_start >= 0:
                                ua_end = line.find('"', ua_start + 1)
                                if ua_end > ua_start:
                                    user_agent = line[ua_start + 1 : ua_end]
                    except Exception:
                        pass

                    # Check for attack patterns
                    has_attack_pattern = bool(ATTACK_PATTERNS.search(line))

                    # Check for scanner user agent
                    has_scanner_ua = bool(SCANNER_USER_AGENTS.search(user_agent)) if user_agent else False

                    # Create or update threat signals for this IP
                    if ip_str not in ip_signals:
                        ip_signals[ip_str] = ThreatSignals()

                    ip_signals[ip_str].add_request(
                        has_attack_pattern=has_attack_pattern,
                        has_scanner_ua=has_scanner_ua,
                        status_code=status_code,
                        path=path,
                    )

            logging.debug(f"Multi-signal processed {filename}: {len(ip_signals)} unique IPs")
            return ip_signals

        except gzip.BadGzipFile as e:
            logging.warning(f"Corrupted gzip file {filename}: {e} - skipping file")
            self._s3_processing_errors += 1
            return {}
        except Exception as e:
            logging.error(f"Error parsing log file {filename}: {e} - skipping file")
            self._s3_processing_errors += 1
            return {}

    def _log_threat_score_details(
        self,
        ip: str,
        score: float,
        details: Dict[str, Any],
        blocked: bool
    ):
        """
        Log threat score details at appropriate verbosity level.

        Args:
            ip: IP address being evaluated
            score: Final threat score
            details: Dict with breakdown details including:
                - hit_count: Total requests from IP
                - reasons: List of reason strings
                - breakdown: Score component breakdown
                - base_score: Score before service adjustment
                - final_score: Score after service adjustment
                - service_name: Verified legitimate service (if any)
            blocked: Whether the IP will be blocked
        """
        status = "BLOCKED" if blocked else "SKIPPED (below threshold)"

        # Get breakdown components safely
        breakdown = details.get('breakdown', {})
        reasons_str = ', '.join(details.get('reasons', [])) if details.get('reasons') else 'no_specific_signals'

        # Always log the summary at INFO level
        hit_count = details.get('hit_count', 0)
        logging.info(
            f"IP {ip}: score={score:.1f}, hits={hit_count}, "
            f"status={status}, reasons=[{reasons_str}]"
        )

        # Determine if this is a borderline case (within 20 points of threshold)
        min_score = self._threat_signals_config.get('min_threat_score', 40)
        is_borderline = abs(score - min_score) <= 20

        # Log detailed breakdown in debug mode, or always for borderline cases
        if self._debug or is_borderline:
            base_score = details.get('base_score', score)
            service_adj = details.get('service_adjustment', 0)

            logging.info(
                f"  → Score breakdown: "
                f"pattern={breakdown.get('attack_pattern', 0):.1f}, "
                f"scanner_ua={breakdown.get('scanner_ua', 0):.1f}, "
                f"error_rate={breakdown.get('error_rate', 0):.1f}, "
                f"path_diversity={breakdown.get('path_diversity', 0):.1f}, "
                f"rate={breakdown.get('rate', 0):.1f}"
            )

            if service_adj != 0:
                service_name = details.get('service_name', 'unknown')
                logging.info(
                    f"  → Service adjustment: {service_adj} ({service_name})"
                )

            aws_service = details.get('aws_service')
            if aws_service:
                logging.info(f"  → AWS service detected: {aws_service}")

            # Log attack pattern and scanner details
            attack_hits = details.get('attack_pattern_hits', 0)
            scanner_hits = details.get('scanner_ua_hits', 0)
            error_count = details.get('error_responses', 0)
            if attack_hits > 0 or scanner_hits > 0:
                logging.info(
                    f"  → Attack patterns: {attack_hits}, Scanner UAs: {scanner_hits}, Errors: {error_count}/{hit_count}"
                )

        # Warn for high-hit IPs that were skipped (potential false negative)
        if not blocked and hit_count >= 100:
            logging.warning(
                f"High-traffic IP {ip} ({hit_count} hits) was NOT blocked due to low threat score ({score:.1f}). "
                f"Review if this is expected behavior. Reasons: [{reasons_str}]"
            )

    def _aggregate_threat_signals(
        self, signal_dicts: List[Dict[str, ThreatSignals]]
    ) -> Dict[str, ThreatSignals]:
        """
        Aggregate threat signals from multiple log files.

        Args:
            signal_dicts: List of dicts mapping IPs to ThreatSignals

        Returns:
            Combined dict with aggregated signals
        """
        aggregated: Dict[str, ThreatSignals] = {}

        for signals in signal_dicts:
            for ip, signals_obj in signals.items():
                if ip not in aggregated:
                    aggregated[ip] = ThreatSignals()

                # Merge signals
                agg = aggregated[ip]
                agg.attack_pattern_hits += signals_obj.attack_pattern_hits
                agg.scanner_ua_hits += signals_obj.scanner_ua_hits
                agg.error_responses += signals_obj.error_responses
                agg.total_requests += signals_obj.total_requests
                agg.unique_paths.update(signals_obj.unique_paths)

                if signals_obj.first_seen:
                    if agg.first_seen is None or signals_obj.first_seen < agg.first_seen:
                        agg.first_seen = signals_obj.first_seen
                if signals_obj.last_seen:
                    if agg.last_seen is None or signals_obj.last_seen > agg.last_seen:
                        agg.last_seen = signals_obj.last_seen

        return aggregated

    def _filter_by_multi_signal(
        self,
        candidate_ips: Set[str],
        log_keys: List[Tuple[str, str]],
        metrics_dimensions: Dict[str, str],
    ) -> Set[str]:
        """
        Filter candidate IPs using multi-signal threat detection.

        Only IPs that meet the threat score threshold are returned.

        Args:
            candidate_ips: Set of IPs that passed initial pattern matching
            log_keys: List of (bucket, key) tuples for log files to analyze
            metrics_dimensions: Dimensions for CloudWatch metrics

        Returns:
            Set of IPs that pass the multi-signal threshold
        """
        if not candidate_ips:
            return set()

        # Process logs with multi-signal extraction
        all_signals: List[Dict[str, ThreatSignals]] = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(self._download_and_parse_log_multi_signal, bucket, key): (bucket, key)
                for bucket, key in log_keys
            }
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        all_signals.append(result)
                except Exception as e:
                    bucket, key = futures[future]
                    logging.warning(f"Error in multi-signal processing for {key}: {e}")

        # Aggregate signals across all files
        aggregated = self._aggregate_threat_signals(all_signals)

        # Filter candidates based on threat scores
        confirmed_offenders = set()
        skipped_ips: List[Tuple[str, float, Dict[str, Any]]] = []

        for ip in candidate_ips:
            if ip not in aggregated:
                # No multi-signal data - use original pattern-match decision
                # This shouldn't happen normally, but be safe
                confirmed_offenders.add(ip)
                continue

            signals = aggregated[ip]
            is_malicious_base, base_score, breakdown = signals.is_malicious(self._threat_signals_config)

            # Enhanced details for logging
            details: Dict[str, Any] = {
                'base_score': base_score,
                'breakdown': breakdown,
                'hit_count': signals.total_requests,
                'reasons': [],
                'top_user_agents': list(signals.unique_paths)[:3] if hasattr(signals, 'unique_paths') else [],
                'attack_pattern_hits': signals.attack_pattern_hits,
                'scanner_ua_hits': signals.scanner_ua_hits,
                'error_responses': signals.error_responses,
            }

            # Add reasons based on signal breakdown
            if breakdown.get('attack_pattern', 0) > 0:
                details['reasons'].append(f"attack_patterns ({signals.attack_pattern_hits} hits)")
            if breakdown.get('scanner_ua', 0) > 0:
                details['reasons'].append(f"scanner_ua ({signals.scanner_ua_hits} hits)")
            if breakdown.get('error_rate', 0) > 0:
                error_ratio = signals.error_responses / signals.total_requests if signals.total_requests else 0
                details['reasons'].append(f"high_error_rate ({error_ratio:.0%})")
            if breakdown.get('path_diversity', 0) > 0:
                details['reasons'].append(f"path_scanning ({len(signals.unique_paths)} unique paths)")

            # Check for legitimate service verification (reduces false positives)
            service_adjustment = 0
            service_name = None
            verification_method = None

            # Get sample request data for service verification
            sample_paths = list(signals.unique_paths)[:20] if hasattr(signals, 'unique_paths') else []
            # For service verification, we need to check if this looks like a legitimate service
            # Since we don't have the actual UA here, we check using basic heuristics
            # The full verification would happen at request parsing time
            if self.aws_ip_index is not None:
                # Check if IP belongs to any known AWS service
                aws_service = self.aws_ip_index.get_service_for_ip(ip)
                if aws_service:
                    details['aws_service'] = aws_service
                    # Only give score reduction for health check services
                    if aws_service in [AWS_SERVICE_ROUTE53_HEALTHCHECKS, AWS_SERVICE_ELB]:
                        service_adjustment = -15
                        service_name = aws_service
                        verification_method = 'aws_service_ip'
                        details['reasons'].append(f"aws_service_ip ({aws_service})")
                        details['service_adjustment'] = service_adjustment

            # Calculate final score with service adjustment
            final_score = max(0, base_score + service_adjustment)
            details['final_score'] = final_score
            details['service_name'] = service_name
            details['verification_method'] = verification_method

            # Determine if malicious based on final score
            min_score = self._threat_signals_config['min_threat_score']
            is_malicious_final = final_score >= min_score

            if is_malicious_final:
                confirmed_offenders.add(ip)
                self._log_threat_score_details(ip, final_score, details, blocked=True)
            else:
                skipped_ips.append((ip, final_score, details))
                self._log_threat_score_details(ip, final_score, details, blocked=False)

        # Store skipped IPs for dry-run summary
        self._skipped_ips = skipped_ips

        # Emit metrics for threat scores
        if aggregated:
            avg_score = sum(
                signals.calculate_threat_score(self._threat_signals_config)[0]
                for ip, signals in aggregated.items()
                if ip in candidate_ips
            ) / len(candidate_ips) if candidate_ips else 0
            self._metrics.put_metric(
                "AverageThreatScore", avg_score, "None", metrics_dimensions
            )

        return confirmed_offenders

    # -------------------------------------------------------------------------
    # Athena Integration for Large-Scale Log Analysis
    # -------------------------------------------------------------------------

    def _init_athena(self):
        """Initialize Athena client if not already done."""
        if not hasattr(self, '_athena') or self._athena is None:
            self._athena = boto3.client("athena", region_name=self.region)

    def _setup_athena_table(
        self,
        database: str,
        table_name: str,
        s3_log_location: str,
        output_location: str,
    ) -> bool:
        """
        Create or verify the Athena table for ALB logs.

        Uses the standard ALB log format as defined by AWS.

        Args:
            database: Athena database name
            table_name: Table name to create
            s3_log_location: S3 location of ALB logs (s3://bucket/prefix/)
            output_location: S3 location for query results

        Returns:
            bool: True if table exists or was created successfully
        """
        self._init_athena()

        # ALB log table DDL (standard AWS format)
        create_table_query = f"""
        CREATE EXTERNAL TABLE IF NOT EXISTS {database}.{table_name} (
            type string,
            time string,
            elb string,
            client_ip string,
            client_port int,
            target_ip string,
            target_port int,
            request_processing_time double,
            target_processing_time double,
            response_processing_time double,
            elb_status_code int,
            target_status_code string,
            received_bytes bigint,
            sent_bytes bigint,
            request_verb string,
            request_url string,
            request_proto string,
            user_agent string,
            ssl_cipher string,
            ssl_protocol string,
            target_group_arn string,
            trace_id string,
            domain_name string,
            chosen_cert_arn string,
            matched_rule_priority string,
            request_creation_time string,
            actions_executed string,
            redirect_url string,
            lambda_error_reason string,
            target_port_list string,
            target_status_code_list string,
            classification string,
            classification_reason string
        )
        ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.RegexSerDe'
        WITH SERDEPROPERTIES (
            'serialization.format' = '1',
            'input.regex' =
            '([^ ]*) ([^ ]*) ([^ ]*) ([^ ]*):([0-9]*) ([^ ]*)[:-]([0-9]*) ([-.0-9]*) ([-.0-9]*) ([-.0-9]*) (|[-0-9]*) (-|[-0-9]*) ([-0-9]*) ([-0-9]*) \"([^ ]*) (.*) (- |[^ ]*)\" \"([^\"]*)\" ([A-Z0-9-_]+) ([A-Za-z0-9.-]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^\"]*)\" ([-.0-9]*) ([^ ]*) \"([^\"]*)\" \"([^\"]*)\" \"([^ ]*)\" \"([^\\s]+?)\" \"([^\\s]+)\" \"([^ ]*)\" \"([^ ]*)\"'
        )
        LOCATION '{s3_log_location}'
        """

        try:
            # Create database if not exists
            self._execute_athena_query(
                f"CREATE DATABASE IF NOT EXISTS {database}",
                output_location,
                wait=True,
            )

            # Create table
            self._execute_athena_query(
                create_table_query,
                output_location,
                wait=True,
            )

            logging.info(f"Athena table {database}.{table_name} ready")
            return True

        except Exception as e:
            logging.error(f"Failed to set up Athena table: {e}")
            return False

    def _execute_athena_query(
        self,
        query: str,
        output_location: str,
        database: Optional[str] = None,
        wait: bool = True,
        timeout_seconds: int = 300,
    ) -> Optional[str]:
        """
        Execute an Athena query and optionally wait for completion.

        Args:
            query: SQL query to execute
            output_location: S3 location for results
            database: Optional database context
            wait: If True, poll until query completes
            timeout_seconds: Max time to wait for query

        Returns:
            str: Query execution ID if successful, None on failure
        """
        self._init_athena()

        try:
            params = {
                "QueryString": query,
                "ResultConfiguration": {
                    "OutputLocation": output_location,
                },
            }
            if database:
                params["QueryExecutionContext"] = {"Database": database}

            response = self._athena.start_query_execution(**params)
            query_id = response["QueryExecutionId"]
            logging.debug(f"Started Athena query: {query_id}")

            if wait:
                return self._wait_for_athena_query(query_id, timeout_seconds)
            return query_id

        except Exception as e:
            logging.error(f"Failed to execute Athena query: {e}")
            return None

    def _wait_for_athena_query(
        self,
        query_id: str,
        timeout_seconds: int = 300,
    ) -> Optional[str]:
        """
        Wait for an Athena query to complete.

        Args:
            query_id: Query execution ID
            timeout_seconds: Max time to wait

        Returns:
            str: Query ID if successful, None on failure
        """
        import time

        start_time = time.time()
        poll_interval = 1  # Start with 1 second

        while time.time() - start_time < timeout_seconds:
            try:
                response = self._athena.get_query_execution(
                    QueryExecutionId=query_id
                )
                state = response["QueryExecution"]["Status"]["State"]

                if state == "SUCCEEDED":
                    return query_id
                elif state in ("FAILED", "CANCELLED"):
                    reason = response["QueryExecution"]["Status"].get(
                        "StateChangeReason", "Unknown"
                    )
                    logging.error(f"Athena query {state}: {reason}")
                    return None

                # Exponential backoff (max 30s)
                time.sleep(poll_interval)
                poll_interval = min(poll_interval * 1.5, 30)

            except Exception as e:
                logging.error(f"Error polling Athena query status: {e}")
                return None

        logging.error(f"Athena query timed out after {timeout_seconds}s")
        return None

    def _query_athena_for_attackers(
        self,
        database: str,
        table_name: str,
        output_location: str,
        lookback_hours: float,
        attack_patterns: List[str],
        min_count: int,
    ) -> Optional[Counter]:
        """
        Query Athena for IPs matching attack patterns with hit counts.

        This is more efficient than processing individual log files for
        large-scale analysis across many log files.

        Args:
            database: Athena database name
            table_name: Table name
            output_location: S3 location for query results
            lookback_hours: How far back to look
            attack_patterns: SQL LIKE patterns for attacks
            min_count: Minimum hit count to include

        Returns:
            Counter: IP -> hit count mapping, or None on failure
        """
        self._init_athena()

        # Build WHERE clause for attack patterns
        pattern_conditions = " OR ".join([
            f"request_url LIKE '%{pattern}%'"
            for pattern in attack_patterns
        ])

        # Calculate time boundary
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)
        time_filter = cutoff_time.strftime("%Y-%m-%dT%H:%M:%S")

        query = f"""
        SELECT
            client_ip,
            COUNT(*) as hit_count
        FROM {database}.{table_name}
        WHERE
            time >= '{time_filter}'
            AND ({pattern_conditions})
        GROUP BY client_ip
        HAVING COUNT(*) >= {min_count}
        ORDER BY hit_count DESC
        LIMIT 10000
        """

        query_id = self._execute_athena_query(
            query,
            output_location,
            database=database,
            wait=True,
            timeout_seconds=600,  # 10 minutes for large queries
        )

        if not query_id:
            return None

        return self._get_athena_results_as_counter(query_id)

    def _get_athena_results_as_counter(self, query_id: str) -> Optional[Counter]:
        """
        Get Athena query results and convert to Counter.

        Args:
            query_id: Completed query execution ID

        Returns:
            Counter: IP -> count mapping, or None on failure
        """
        self._init_athena()

        try:
            paginator = self._athena.get_paginator("get_query_results")
            results = Counter()

            for page in paginator.paginate(QueryExecutionId=query_id):
                for row in page["ResultSet"]["Rows"][1:]:  # Skip header
                    data = row["Data"]
                    if len(data) >= 2:
                        ip = data[0].get("VarCharValue", "")
                        count_str = data[1].get("VarCharValue", "0")
                        if ip and count_str.isdigit():
                            results[ip] = int(count_str)

            logging.info(f"Athena query returned {len(results)} IPs")
            return results

        except Exception as e:
            logging.error(f"Failed to get Athena results: {e}")
            return None

    def _process_logs_via_athena(
        self,
        log_location: str,
        lookback_hours: float,
    ) -> Optional[Counter]:
        """
        Process ALB logs using Athena for large-scale analysis.

        This method is an alternative to _process_logs_in_parallel() for
        scenarios with many log files where S3 GetObject would be too slow.

        Args:
            log_location: S3 URI for ALB logs (s3://bucket/prefix/)
            lookback_hours: How far back to analyze

        Returns:
            Counter: IP -> hit count mapping, or None on failure
        """
        if not self._athena_enabled:
            logging.warning("Athena integration not enabled")
            return None

        # Derive table name from LB pattern
        safe_pattern = re.sub(r'[^a-zA-Z0-9]', '_', self.lb_name_pattern)
        table_name = f"alb_logs_{safe_pattern}_{self.region.replace('-', '_')}"

        # Set up table if needed
        if not self._setup_athena_table(
            self._athena_database,
            table_name,
            log_location,
            self._athena_output_location,
        ):
            return None

        # Attack patterns for SQL LIKE queries
        sql_patterns = [
            "../",           # Path traversal
            ".env",          # Environment file access
            ".git",          # Git repository access
            "wp-login",      # WordPress login
            "wp-admin",      # WordPress admin
            "phpmyadmin",    # phpMyAdmin
            "<script",       # XSS
            "UNION SELECT",  # SQL injection
            "eval(",         # Code injection
            "/etc/passwd",   # System file access
            ".php?",         # PHP with params (often exploits)
        ]

        return self._query_athena_for_attackers(
            self._athena_database,
            table_name,
            self._athena_output_location,
            lookback_hours,
            sql_patterns,
            self.threshold,
        )

    def _get_nacl_rules(self, nacl_id: str) -> Tuple[Dict[int, str], Set[int]]:
        """Gets all rules for a given NACL and separates them."""
        try:
            response = self.ec2.describe_network_acls(NetworkAclIds=[nacl_id])
            all_entries = response["NetworkAcls"][0]["Entries"]

            existing_deny_rules = {
                entry["RuleNumber"]: entry["CidrBlock"]
                for entry in all_entries
                if entry["RuleAction"] == "deny"
                and "CidrBlock" in entry
                and not entry["Egress"]
                and entry["RuleNumber"] != 32767
            }

            all_rule_numbers = {entry["RuleNumber"] for entry in all_entries}

            logging.info(
                f"Found {len(existing_deny_rules)} managed inbound DENY rules in NACL {nacl_id}."
            )
            return existing_deny_rules, all_rule_numbers
        except Exception as e:
            logging.error(f"Error describing network ACL {nacl_id}: {e}")
            return {}, set()

    def _update_nacl_rules(self, nacl_id: str, offenders: Set[str], ip_counts: Counter):
        """Main logic to synchronize the NACL with the identified offenders."""
        existing_deny_rules, all_rule_nums = self._get_nacl_rules(nacl_id)
        existing_blocked_ips = {
            cidr.split("/")[0] for cidr in existing_deny_rules.values()
        }

        ips_to_add = offenders - existing_blocked_ips
        ips_to_remove = existing_blocked_ips - offenders

        if ips_to_remove:
            logging.warning(
                f"Found {len(ips_to_remove)} IP(s) to unblock as they are no longer top offenders."
            )
            for rule_num, cidr in existing_deny_rules.items():
                # Only remove rules in our managed range
                if (
                    rule_num in self.deny_rule_range
                    and cidr.split("/")[0] in ips_to_remove
                ):
                    self._delete_deny_rule(nacl_id, cidr.split("/")[0], rule_num)

        if ips_to_add:
            logging.warning(f"Found {len(ips_to_add)} new offender(s) to block.")
            self._manage_rule_limit_and_add(nacl_id, ips_to_add, ip_counts)

    def _update_nacl_rules_with_registry(
        self, nacl_id: str, ips_to_block: Set[str], active_blocks: Dict[str, Dict]
    ):
        """
        Updates NACL rules based on the persistent registry with priority-based slot management.
        """
        existing_deny_rules, all_rule_nums = self._get_nacl_rules(nacl_id)
        existing_blocked_ips = {
            cidr.split("/")[0] for cidr in existing_deny_rules.values()
        }

        ips_to_add = ips_to_block - existing_blocked_ips
        ips_to_remove = existing_blocked_ips - ips_to_block

        # Remove expired or no-longer-needed blocks
        if ips_to_remove:
            logging.warning(
                f"Found {len(ips_to_remove)} IP(s) to unblock (expired or removed from registry)."
            )
            for rule_num, cidr in existing_deny_rules.items():
                if (
                    rule_num in self.deny_rule_range
                    and cidr.split("/")[0] in ips_to_remove
                ):
                    ip_to_remove = cidr.split("/")[0]
                    self._delete_deny_rule_with_reason(
                        nacl_id, ip_to_remove, rule_num, "Block expired"
                    )

        # Add new blocks with priority management
        if ips_to_add:
            logging.warning(
                f"Found {len(ips_to_add)} new IP(s) to block from registry."
            )
            self._manage_rule_limit_and_add_with_priority(
                nacl_id, ips_to_add, active_blocks
            )

    def _manage_rule_limit_and_add_with_priority(
        self, nacl_id: str, ips_to_add: Set[str], active_blocks: Dict[str, Dict]
    ):
        """
        Adds new IPs with priority-based slot management.
        Higher priority blocks won't be displaced by lower priority ones.
        """
        deny_rules, total_rule_nums = self._get_nacl_rules(nacl_id)

        # Sort IPs to add by priority (highest first)
        sorted_ips_to_add = sorted(
            list(ips_to_add),
            key=lambda ip: active_blocks.get(ip, {}).get("priority", 0),
            reverse=True,
        )

        available_slots = [i for i in self.deny_rule_range if i not in total_rule_nums]

        # Fill available slots first
        for ip in list(sorted_ips_to_add):
            if available_slots:
                rule_num = available_slots.pop(0)
                self._create_deny_rule_with_tier(
                    nacl_id, ip, rule_num, active_blocks.get(ip, {})
                )
                sorted_ips_to_add.remove(ip)
            else:
                break

        # If still have IPs to add, need to prune lowest priority rules
        if sorted_ips_to_add:
            logging.warning(
                f"No more free slots. Need to prune {len(sorted_ips_to_add)} rule(s) to make space."
            )

            # Get existing rules with their priorities from registry
            managed_deny_rules = {
                k: v for k, v in deny_rules.items() if k in self.deny_rule_range
            }

            # Build list of (rule_num, ip, priority) for existing rules
            rules_with_priority = []
            for rule_num, cidr in managed_deny_rules.items():
                ip = cidr.split("/")[0]
                registry_entry = self._get_registry_entry(ip)
                priority = registry_entry.get("priority", 0) if registry_entry else 0
                rules_with_priority.append((rule_num, ip, priority))

            # Sort by priority (lowest first), then by rule number
            rules_with_priority.sort(key=lambda x: (x[2], x[0]))

            for ip_to_add in sorted_ips_to_add:
                if rules_with_priority:
                    new_ip_priority = active_blocks.get(ip_to_add, {}).get(
                        "priority", 0
                    )

                    # Find a rule with lower or equal priority to replace
                    replaced = False
                    for idx, (rule_num, existing_ip, existing_priority) in enumerate(
                        rules_with_priority
                    ):
                        if new_ip_priority >= existing_priority:
                            # Can replace this rule
                            logging.info(
                                f"Replacing {existing_ip} (priority {existing_priority}) "
                                f"with {ip_to_add} (priority {new_ip_priority})"
                            )
                            self._delete_deny_rule_with_reason(
                                nacl_id,
                                existing_ip,
                                rule_num,
                                "Displaced by higher priority IP",
                            )
                            self._create_deny_rule_with_tier(
                                nacl_id,
                                ip_to_add,
                                rule_num,
                                active_blocks.get(ip_to_add, {}),
                            )
                            rules_with_priority.pop(idx)
                            replaced = True
                            break

                    if not replaced:
                        logging.warning(
                            f"Cannot add {ip_to_add}: all existing rules have higher priority"
                        )
                else:
                    logging.error("No managed DENY rules available to replace.")
                    break

    def _manage_rule_limit_and_add(
        self, nacl_id: str, ips_to_add: Set[str], ip_counts: Counter
    ):
        """Deletes oldest DENY rules if limit is hit, then adds new IPs."""
        # Refresh state after potential deletions
        deny_rules, total_rule_nums = self._get_nacl_rules(nacl_id)

        sorted_ips_to_add = sorted(
            list(ips_to_add), key=lambda ip: ip_counts[ip], reverse=True
        )

        available_slots = [i for i in self.deny_rule_range if i not in total_rule_nums]

        # Fill available slots first
        for ip in list(sorted_ips_to_add):
            if available_slots:
                rule_num = available_slots.pop(0)
                self._create_deny_rule(nacl_id, ip, rule_num)
                sorted_ips_to_add.remove(ip)
            else:
                break

        # Prune if we still have offenders to add
        if sorted_ips_to_add:
            logging.warning(
                f"No more free slots. Pruning {len(sorted_ips_to_add)} oldest rule(s) to make space."
            )

            managed_deny_rules = {
                k: v for k, v in deny_rules.items() if k in self.deny_rule_range
            }
            sorted_deny_rules_by_num = sorted(managed_deny_rules.items())

            for ip_to_add in sorted_ips_to_add:
                if sorted_deny_rules_by_num:
                    rule_num_to_replace, cidr_to_replace = sorted_deny_rules_by_num.pop(
                        0
                    )
                    self._delete_deny_rule(
                        nacl_id, cidr_to_replace.split("/")[0], rule_num_to_replace
                    )
                    self._create_deny_rule(nacl_id, ip_to_add, rule_num_to_replace)
                else:
                    logging.error(
                        "Needed to prune rules, but no managed DENY rules were available to replace."
                    )
                    break

    def _send_slack_notification(self, message: str, is_critical: bool = False):
        """
        Sends a notification to Slack if configured.

        Args:
            message: The message to send
            is_critical: If True, adds warning emoji to the message

        Note:
            Failed notifications are queued for retry at end of run.
            Notification failures never affect core blocking logic.
        """
        if not self.slack_client:
            return

        # Add emoji prefix for critical messages
        if is_critical:
            message = f":warning: {message}"

        try:
            success = self.slack_client.post_message(message=message)
            if success:
                logging.debug(f"Slack notification sent successfully")
            else:
                # Queue for retry
                self._failed_slack_messages.append((message, is_critical))
                logging.debug("Slack notification failed - queued for retry")
        except Exception as e:
            # Queue for retry - don't let Slack failures affect blocking
            self._failed_slack_messages.append((message, is_critical))
            logging.warning(f"Error sending Slack notification (queued for retry): {e}")

    def _retry_failed_slack_messages(self):
        """
        Retry sending failed Slack messages at end of run.
        Called once after all blocking operations complete.
        """
        if not self._failed_slack_messages or not self.slack_client:
            return

        logging.info(f"Retrying {len(self._failed_slack_messages)} failed Slack notification(s)...")
        retry_successes = 0

        for message, is_critical in self._failed_slack_messages:
            try:
                # Remove emoji prefix if already added (to avoid duplication)
                clean_message = message.replace(":warning: ", "") if is_critical else message
                final_message = f":warning: {clean_message}" if is_critical else clean_message

                success = self.slack_client.post_message(message=final_message)
                if success:
                    retry_successes += 1
            except Exception as e:
                logging.debug(f"Retry failed for Slack message: {e}")

        if retry_successes > 0:
            logging.info(f"Successfully sent {retry_successes}/{len(self._failed_slack_messages)} queued Slack notifications")
        else:
            logging.warning(f"All {len(self._failed_slack_messages)} Slack notification retries failed")

        # Clear the queue
        self._failed_slack_messages.clear()

    def _send_summary_notification(
        self,
        offenders: Set[str],
        final_blocked_ips: Set[str],
        ip_counts: Counter,
        initially_blocked_ips: Set[str],
    ):
        """
        Sends a summary notification to Slack at the end of execution.
        Only sends notification if there were actual changes (new blocks or unblocks).

        Args:
            offenders: Set of IPs that should be blocked
            final_blocked_ips: Set of IPs actually blocked in NACL
            ip_counts: Counter of malicious hits per IP
            initially_blocked_ips: Set of IPs that were blocked before this run
        """
        if not self.slack_client or self.dry_run:
            return

        # Calculate actual changes in this run
        newly_blocked = final_blocked_ips - initially_blocked_ips
        newly_unblocked = initially_blocked_ips - final_blocked_ips

        # Only send notification if there were actual changes
        if not newly_blocked and not newly_unblocked:
            logging.info("No changes to blocked IPs. Skipping Slack notification.")
            return

        total_blocked = len(final_blocked_ips)

        # Build summary message
        summary_lines = [
            f"*Auto Block Attackers Summary - {self.region}*",
            f"• Total IPs currently blocked: {total_blocked}",
            f"• Pattern: `{self.lb_name_pattern}`",
            f"• Lookback period: {self.lookback_delta}",
            f"• Threshold: {self.threshold} malicious requests",
        ]

        if newly_blocked:
            top_offenders = sorted(
                [(ip, ip_counts[ip]) for ip in list(newly_blocked)[:5]],
                key=lambda x: x[1],
                reverse=True,
            )
            summary_lines.append(f"\n*Newly Blocked ({len(newly_blocked)} IPs):*")
            for ip, count in top_offenders:
                summary_lines.append(f"  • {ip} ({count} malicious requests)")
            if len(newly_blocked) > 5:
                summary_lines.append(f"  • ... and {len(newly_blocked) - 5} more")

        if newly_unblocked:
            summary_lines.append(f"\n*Unblocked ({len(newly_unblocked)} IPs):*")
            for ip in list(newly_unblocked)[:5]:
                summary_lines.append(f"  • {ip}")
            if len(newly_unblocked) > 5:
                summary_lines.append(f"  • ... and {len(newly_unblocked) - 5} more")

        message = "\n".join(summary_lines)
        self._send_slack_notification(message, is_critical=bool(newly_blocked))

    def _send_summary_notification_with_registry(
        self,
        new_offenders: Set[str],
        final_blocked_ips: Set[str],
        ip_counts: Counter,
        initially_blocked_ips: Set[str],
        active_blocks: Dict[str, Dict],
    ):
        """
        Sends a summary notification to Slack with tier information from registry.
        Only sends notification if there were actual changes (new blocks or unblocks).
        """
        if not self.slack_client or self.dry_run:
            return

        # Calculate actual changes in this run
        newly_blocked = final_blocked_ips - initially_blocked_ips
        newly_unblocked = initially_blocked_ips - final_blocked_ips

        # Only send notification if there were actual changes
        if not newly_blocked and not newly_unblocked:
            logging.info("No changes to blocked IPs. Skipping Slack notification.")
            return

        total_blocked = len(final_blocked_ips)

        # Build summary message with tier breakdown
        tier_counts = {}
        for ip in final_blocked_ips:
            if ip in active_blocks:
                tier = active_blocks[ip].get("tier", "unknown")
                tier_counts[tier] = tier_counts.get(tier, 0) + 1

        summary_lines = [
            f"*Auto Block Attackers Summary - {self.region} (Tiered Mode)*",
            f"• Total IPs currently blocked: {total_blocked}",
        ]

        if tier_counts:
            tier_breakdown = ", ".join([
                f"{tier}: {count}" for tier, count in sorted(tier_counts.items())
            ])
            summary_lines.append(f"• Tier breakdown: {tier_breakdown}")

        summary_lines.extend([
            f"• Lookback period: {self.lookback_delta}",
            f"• Threshold: {self.threshold} malicious requests",
        ])

        if newly_blocked:
            # Show tier and block duration for newly blocked IPs
            blocked_with_info = []
            for ip in list(newly_blocked)[:5]:
                hits = ip_counts.get(ip, active_blocks.get(ip, {}).get("total_hits", 0))
                tier = active_blocks.get(ip, {}).get("tier", "unknown")
                block_duration_hours = active_blocks.get(ip, {}).get(
                    "block_duration_hours", 0
                )
                blocked_with_info.append((ip, hits, tier, block_duration_hours))

            # Sort by hits
            blocked_with_info.sort(key=lambda x: x[1], reverse=True)

            summary_lines.append(f"\n*Newly Blocked ({len(newly_blocked)} IPs):*")
            for ip, hits, tier, duration_hours in blocked_with_info:
                # Format duration nicely
                if duration_hours >= 24:
                    duration_str = f"{int(duration_hours / 24)}d"
                elif duration_hours >= 1:
                    duration_str = f"{int(duration_hours)}h"
                else:
                    duration_str = f"{int(duration_hours * 60)}m"

                summary_lines.append(
                    f"  • {ip} ({hits} hits, tier: {tier.upper()}, blocked for {duration_str})"
                )
            if len(newly_blocked) > 5:
                summary_lines.append(f"  • ... and {len(newly_blocked) - 5} more")

        if newly_unblocked:
            summary_lines.append(f"\n*Unblocked ({len(newly_unblocked)} IPs):*")
            for ip in list(newly_unblocked)[:5]:
                summary_lines.append(f"  • {ip}")
            if len(newly_unblocked) > 5:
                summary_lines.append(f"  • ... and {len(newly_unblocked) - 5} more")

        message = "\n".join(summary_lines)
        self._send_slack_notification(message, is_critical=bool(newly_blocked))

    def _send_enhanced_slack_notification(
        self,
        new_offenders: Set[str],
        final_blocked_ips: Set[str],
        ip_counts: Counter,
        initially_blocked_ips: Set[str],
        active_blocks: Dict[str, Dict],
        run_id: Optional[str] = None,
    ):
        """
        Sends enhanced Slack notifications with:
        - Severity-based color coding
        - Incident threading (all messages grouped by run_id)
        - Actionable information organized by threat tier

        Args:
            new_offenders: Set of newly detected offending IPs
            final_blocked_ips: Set of IPs actually blocked in NACL
            ip_counts: Counter of malicious hits per IP
            initially_blocked_ips: Set of IPs that were blocked before this run
            active_blocks: Current block registry with tier information
            run_id: Optional run identifier for threading
        """
        if not self.slack_client or self.dry_run:
            return

        # Calculate actual changes
        newly_blocked = final_blocked_ips - initially_blocked_ips
        newly_unblocked = initially_blocked_ips - final_blocked_ips

        # Skip if no changes
        if not newly_blocked and not newly_unblocked:
            logging.info("No changes to blocked IPs. Skipping enhanced Slack notification.")
            return

        # Generate run_id for threading if not provided
        if not run_id:
            run_id = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

        incident_id = f"block_run_{run_id}"

        # Determine overall severity based on highest threat tier
        max_severity = SlackSeverity.INFO
        tier_breakdown = {"minimal": 0, "low": 0, "medium": 0, "high": 0, "critical": 0}

        for ip in newly_blocked:
            tier = active_blocks.get(ip, {}).get("tier", "low")
            tier_breakdown[tier] = tier_breakdown.get(tier, 0) + 1
            tier_severity = TIER_TO_SEVERITY.get(tier, SlackSeverity.LOW)
            if tier_severity.value > max_severity.value:
                max_severity = tier_severity

        # Use critical severity if many IPs blocked
        if len(newly_blocked) >= 10:
            max_severity = SlackSeverity.CRITICAL
        elif len(newly_blocked) >= 5 and max_severity.value < SlackSeverity.HIGH.value:
            max_severity = SlackSeverity.HIGH

        # Build summary fields
        fields = [
            ("Region", self.region),
            ("Pattern", f"`{self.lb_name_pattern}`"),
            ("Total Blocked", str(len(final_blocked_ips))),
            ("Lookback", str(self.lookback_delta)),
        ]

        if newly_blocked:
            fields.append(("Newly Blocked", str(len(newly_blocked))))
        if newly_unblocked:
            fields.append(("Unblocked", str(len(newly_unblocked))))

        # Tier breakdown
        active_tiers = [f"{t}: {c}" for t, c in tier_breakdown.items() if c > 0]
        if active_tiers:
            fields.append(("Tier Breakdown", ", ".join(active_tiers)))

        # Build description with top offenders
        description_parts = []
        if newly_blocked:
            # Group by tier and show top offenders
            tier_groups = {"critical": [], "high": [], "medium": [], "low": [], "minimal": []}
            for ip in newly_blocked:
                tier = active_blocks.get(ip, {}).get("tier", "low")
                hits = ip_counts.get(ip, active_blocks.get(ip, {}).get("total_hits", 0))
                tier_groups[tier].append((ip, hits))

            # Show critical/high first
            for tier_name in ["critical", "high", "medium", "low", "minimal"]:
                ips_in_tier = tier_groups[tier_name]
                if ips_in_tier:
                    ips_in_tier.sort(key=lambda x: x[1], reverse=True)
                    emoji = self._get_tier_emoji(tier_name)
                    description_parts.append(f"\n{emoji} *{tier_name.upper()} tier ({len(ips_in_tier)}):*")
                    for ip, hits in ips_in_tier[:3]:  # Top 3 per tier
                        duration = active_blocks.get(ip, {}).get("block_duration_hours", 0)
                        duration_str = self._format_duration(duration)
                        ip_info = self._get_ip_info(ip)
                        location = ""
                        if ip_info:
                            location = f" ({ip_info.get('country_code', '')})"
                        description_parts.append(f"  `{ip}`{location} - {hits} hits, blocked {duration_str}")
                    if len(ips_in_tier) > 3:
                        description_parts.append(f"  _...and {len(ips_in_tier) - 3} more_")

        if newly_unblocked:
            description_parts.append(f"\n:white_check_mark: *Unblocked ({len(newly_unblocked)}):*")
            for ip in list(newly_unblocked)[:3]:
                description_parts.append(f"  `{ip}`")
            if len(newly_unblocked) > 3:
                description_parts.append(f"  _...and {len(newly_unblocked) - 3} more_")

        description = "\n".join(description_parts) if description_parts else "No details available"

        # Build action buttons (informational - actual action requires external handling)
        action_buttons = []
        if newly_blocked:
            # Add informational button
            action_buttons.append({
                "text": "View Details",
                "action_id": f"view_details_{run_id}",
                "value": json.dumps({
                    "run_id": run_id,
                    "newly_blocked": list(newly_blocked)[:10],
                    "region": self.region,
                }),
            })

        # Post the enhanced notification
        try:
            self.slack_client.post_incident_notification(
                title=f":shield: Auto Block Attackers - {self.region}",
                description=description,
                fields=fields,
                severity=max_severity,
                incident_id=incident_id,
                action_buttons=action_buttons if action_buttons else None,
            )
            logging.info(f"Enhanced Slack notification sent for run {run_id}")
        except Exception as e:
            logging.warning(f"Failed to send enhanced Slack notification: {e}")
            # Fall back to basic notification
            self._send_slack_notification(
                f"Auto Block Attackers - {self.region}: {len(newly_blocked)} blocked, {len(newly_unblocked)} unblocked",
                is_critical=bool(newly_blocked),
            )

    def _get_tier_emoji(self, tier: str) -> str:
        """Get emoji for threat tier."""
        emoji_map = {
            "critical": ":rotating_light:",
            "high": ":red_circle:",
            "medium": ":large_orange_circle:",
            "low": ":large_yellow_circle:",
            "minimal": ":white_circle:",
        }
        return emoji_map.get(tier, ":question:")

    def _format_duration(self, hours: float) -> str:
        """Format duration in hours to human readable string."""
        if hours >= 24:
            days = int(hours / 24)
            return f"{days}d"
        elif hours >= 1:
            return f"{int(hours)}h"
        else:
            return f"{int(hours * 60)}m"

    def _get_ip_info(self, ip: str) -> Optional[Dict]:
        """
        Fetches detailed geolocation and hosting information for an IP address.
        Returns None if ipinfo is not configured or if lookup fails.
        Uses in-memory caching to reduce API calls.
        Implements circuit breaker to disable after repeated failures.
        """
        if not self.ipinfo_handler:
            return None

        # Circuit breaker: skip if too many failures
        if self._ipinfo_circuit_open:
            return None

        # Check cache first
        now = datetime.now(timezone.utc)
        if ip in self.ipinfo_cache:
            cache_time, cached_data = self.ipinfo_cache[ip]
            age = (now - cache_time).total_seconds()
            if age < self.ipinfo_cache_ttl:
                logging.debug(f"Using cached IP info for {ip} (age: {int(age)}s)")
                return cached_data

        # Cache miss or expired - fetch from API
        try:
            details = self.ipinfo_handler.getDetails(ip)
            info = {
                "ip": ip,
                "city": getattr(details, "city", "Unknown"),
                "region": getattr(details, "region", "Unknown"),
                "country": getattr(details, "country_name", "Unknown"),
                "country_code": getattr(details, "country", "Unknown"),
                "location": getattr(details, "loc", "Unknown"),  # "latitude,longitude"
                "org": getattr(details, "org", "Unknown"),  # ISP/Hosting provider
                "postal": getattr(details, "postal", "Unknown"),
                "timezone": getattr(details, "timezone", "Unknown"),
            }

            # Add additional details if available
            if hasattr(details, "hostname"):
                info["hostname"] = details.hostname
            if hasattr(details, "asn"):
                info["asn"] = details.asn
            if hasattr(details, "company"):
                info["company"] = details.company

            # Store in cache
            self.ipinfo_cache[ip] = (now, info)

            # Reset failure counter on success
            self._ipinfo_failures = 0

            return info
        except Exception as e:
            self._ipinfo_failures += 1
            logging.warning(f"Failed to fetch IP info for {ip}: {e} (failure {self._ipinfo_failures}/{self._ipinfo_failure_threshold})")

            # Open circuit breaker after threshold failures
            if self._ipinfo_failures >= self._ipinfo_failure_threshold:
                self._ipinfo_circuit_open = True
                logging.warning(
                    f"IPInfo circuit breaker OPEN - disabled for rest of run after {self._ipinfo_failures} consecutive failures"
                )

            return None

    def _format_ip_info(self, ip_info: Optional[Dict]) -> str:
        """
        Formats IP information into a readable string for logging and notifications.
        """
        if not ip_info:
            return "IP info not available"

        parts = []

        # Location info
        location_parts = []
        if ip_info.get("city") and ip_info["city"] != "Unknown":
            location_parts.append(str(ip_info["city"]))
        if ip_info.get("region") and ip_info["region"] != "Unknown":
            location_parts.append(str(ip_info["region"]))
        if ip_info.get("country") and ip_info["country"] != "Unknown":
            location_parts.append(str(ip_info["country"]))

        if location_parts:
            parts.append(f"Location: {', '.join(location_parts)}")

        # Coordinates
        if ip_info.get("location") and ip_info["location"] != "Unknown":
            parts.append(f"Coordinates: {str(ip_info['location'])}")

        # Hosting/ISP info
        if ip_info.get("org") and ip_info["org"] != "Unknown":
            parts.append(f"Hosting: {str(ip_info['org'])}")

        # Hostname if available (ensure it's a string)
        if ip_info.get("hostname") and isinstance(ip_info["hostname"], str):
            parts.append(f"Hostname: {ip_info['hostname']}")

        return " | ".join(parts) if parts else "IP info not available"

    def _delete_deny_rule(self, nacl_id: str, ip: str, rule_num: int):
        logging.warning(f"ACTION: Pruning rule {rule_num} for stale IP: {ip}")
        if not self.dry_run:
            try:
                self.ec2.delete_network_acl_entry(
                    NetworkAclId=nacl_id, RuleNumber=rule_num, Egress=False
                )
                logging.info(f"Successfully deleted rule {rule_num}.")
                # Send Slack notification for IP unblocking (no IP info needed for unblocks)
                self._send_slack_notification(
                    f"[{self.region}] Removed IP block: {ip} (rule {rule_num}) - no longer meets threshold"
                )
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code == "InvalidNetworkAclEntry.NotFound":
                    # Rule already deleted (possibly manually) - treat as success
                    logging.warning(f"Rule {rule_num} for {ip} was already deleted (not found)")
                else:
                    logging.error(f"Failed to delete rule {rule_num}: {e}")
            except Exception as e:
                logging.error(f"Failed to delete rule {rule_num}: {e}")
        else:
            logging.info(f"[DRY RUN] Would delete DENY rule number {rule_num}.")

    def _delete_deny_rule_with_reason(
        self, nacl_id: str, ip: str, rule_num: int, reason: str
    ):
        """Delete a DENY rule with a specific reason message."""
        logging.warning(
            f"ACTION: Removing rule {rule_num} for IP: {ip} - Reason: {reason}"
        )
        if not self.dry_run:
            try:
                self.ec2.delete_network_acl_entry(
                    NetworkAclId=nacl_id, RuleNumber=rule_num, Egress=False
                )
                logging.info(f"Successfully deleted rule {rule_num}.")
                # Send Slack notification for IP unblocking
                self._send_slack_notification(
                    f"[{self.region}] Removed IP block: {ip} (rule {rule_num}) - {reason}"
                )
            except ClientError as e:
                error_code = e.response.get("Error", {}).get("Code", "")
                if error_code == "InvalidNetworkAclEntry.NotFound":
                    # Rule already deleted (possibly manually) - treat as success
                    logging.warning(f"Rule {rule_num} for {ip} was already deleted (not found)")
                else:
                    logging.error(f"Failed to delete rule {rule_num}: {e}")
            except Exception as e:
                logging.error(f"Failed to delete rule {rule_num}: {e}")
        else:
            logging.info(f"[DRY RUN] Would delete DENY rule {rule_num} for {ip}.")

    def _create_deny_rule(self, nacl_id: str, ip: str, rule_num: int):
        cidr = f"{ip}/32"
        logging.warning(f"ACTION: Blocking new attacker IP: {ip} with rule {rule_num}")

        # Fetch IP geolocation info (only for blocked IPs)
        ip_info = self._get_ip_info(ip)
        ip_info_str = self._format_ip_info(ip_info)

        # Log detailed IP information
        if ip_info:
            logging.warning(f"IP Details for {ip}: {ip_info_str}")

        if not self.dry_run:
            try:
                self.ec2.create_network_acl_entry(
                    NetworkAclId=nacl_id,
                    RuleNumber=rule_num,
                    Protocol="-1",
                    RuleAction="deny",
                    CidrBlock=cidr,
                    Egress=False,
                )
                logging.info(f"Successfully created DENY rule {rule_num} for {ip}.")

                # Send Slack notification for ACTIVE BLOCK with IP details
                message = f"[{self.region}] ACTIVE BLOCK: Blocked attacker IP {ip} (rule {rule_num}, NACL: {nacl_id})"
                if ip_info:
                    message += f"\n{ip_info_str}"

                self._send_slack_notification(message, is_critical=True)
            except Exception as e:
                logging.error(f"Failed to create DENY rule for {ip}: {e}")
        else:
            logging.info(f"[DRY RUN] Would create DENY rule {rule_num} for {ip}.")
            if ip_info:
                logging.info(f"[DRY RUN] IP Details: {ip_info_str}")

    def _create_deny_rule_with_tier(
        self, nacl_id: str, ip: str, rule_num: int, registry_data: Dict
    ):
        """Create a DENY rule with tier information from registry."""
        cidr = f"{ip}/32"
        tier = registry_data.get("tier", "unknown")
        total_hits = registry_data.get("total_hits", 0)
        block_until = registry_data.get("block_until", "unknown")

        # Parse block_until for display
        try:
            block_until_dt = datetime.fromisoformat(block_until)
            if block_until_dt.tzinfo is None:
                block_until_dt = block_until_dt.replace(tzinfo=timezone.utc)
            block_until_str = block_until_dt.strftime("%Y-%m-%d %H:%M UTC")
        except Exception:
            block_until_str = "unknown"

        logging.warning(
            f"ACTION: Blocking IP {ip} with rule {rule_num} "
            f"[Tier: {tier}, Hits: {total_hits}, Until: {block_until_str}]"
        )

        # Fetch IP geolocation info
        ip_info = self._get_ip_info(ip)
        ip_info_str = self._format_ip_info(ip_info)

        if ip_info:
            logging.warning(f"IP Details for {ip}: {ip_info_str}")

        if not self.dry_run:
            try:
                self.ec2.create_network_acl_entry(
                    NetworkAclId=nacl_id,
                    RuleNumber=rule_num,
                    Protocol="-1",
                    RuleAction="deny",
                    CidrBlock=cidr,
                    Egress=False,
                )
                logging.info(f"Successfully created DENY rule {rule_num} for {ip}.")

                # Send Slack notification with tier info
                message = (
                    f"[{self.region}] ACTIVE BLOCK: Blocked {ip} (rule {rule_num})\n"
                    f"Tier: {tier.upper()} | Hits: {total_hits} | Blocked until: {block_until_str}"
                )
                if ip_info:
                    message += f"\n{ip_info_str}"

                self._send_slack_notification(message, is_critical=True)
            except Exception as e:
                logging.error(f"Failed to create DENY rule for {ip}: {e}")
        else:
            logging.info(
                f"[DRY RUN] Would create DENY rule {rule_num} for {ip} "
                f"[Tier: {tier}, Until: {block_until_str}]"
            )
            if ip_info:
                logging.info(f"[DRY RUN] IP Details: {ip_info_str}")

    def _generate_report(
        self,
        ip_counts: Counter,
        offenders: Set[str],
        final_blocked_ips: Set[str],
        active_blocks: Optional[Dict[str, Dict]] = None,
        ips_to_add: Optional[Set[str]] = None,
        ips_to_remove: Optional[Set[str]] = None,
    ):
        """
        Prints a final summary table of actions taken or planned.

        In dry-run mode, shows expected state changes rather than current state.

        Args:
            ip_counts: Counter of IP addresses and their hit counts
            offenders: Set of IPs that should be blocked
            final_blocked_ips: Set of IPs currently blocked
            active_blocks: Dict of active block registry entries
            ips_to_add: IPs that will be added to blocklist (dry-run tracking)
            ips_to_remove: IPs that will be removed from blocklist (dry-run tracking)
        """
        print("\n--- SCRIPT EXECUTION SUMMARY ---")

        if self.dry_run:
            print("(DRY RUN - showing planned changes, no actual modifications made)\n")

        # Use sets for comparison
        ips_to_add = ips_to_add or set()
        ips_to_remove = ips_to_remove or set()

        # Build skipped IPs lookup
        skipped_ip_details: Dict[str, Tuple[float, Dict]] = {}
        for ip, score, details in self._skipped_ips:
            skipped_ip_details[ip] = (score, details)

        if active_blocks:
            print(
                f"{'IP Address':<20} {'Hits':<10} {'Tier':<12} {'Status':<30} {'Block Until':<20}"
            )
            print("-" * 92)
        else:
            print(f"{'IP Address':<20} {'Malicious Hits':<15} {'Status':<30}")
            print("-" * 65)

        # Collect all IPs to report
        report_ips = set()

        # IPs detected in this run (above threshold)
        detected_ips = {ip for ip, count in ip_counts.items() if count >= self.threshold}
        report_ips.update(detected_ips)

        # Currently blocked IPs
        report_ips.update(final_blocked_ips)

        # IPs in active blocks registry
        if active_blocks:
            report_ips.update(active_blocks.keys())

        # IPs that will be added/removed
        report_ips.update(ips_to_add)
        report_ips.update(ips_to_remove)

        # Include skipped IPs in report
        report_ips.update(skipped_ip_details.keys())

        sorted_report_ips = sorted(
            list(report_ips),
            key=lambda ip: (ip_counts.get(ip, 0), ip),
            reverse=True,
        )

        if not sorted_report_ips and ip_counts:
            logging.info(
                "Malicious activity was detected, but no single IP met the threshold."
            )

        for ip in sorted_report_ips:
            # Determine status based on dry-run vs live-run
            if self.dry_run:
                status = self._get_dry_run_status(
                    ip,
                    ips_to_add=ips_to_add,
                    ips_to_remove=ips_to_remove,
                    final_blocked_ips=final_blocked_ips,
                    skipped_ip_details=skipped_ip_details,
                    hits=ip_counts.get(ip, 0),
                )
            else:
                status = self._get_live_run_status(
                    ip,
                    final_blocked_ips=final_blocked_ips,
                    offenders=offenders,
                    hits=ip_counts.get(ip, 0),
                )

            hits = ip_counts.get(ip, 0)
            tier = ""
            block_until_str = ""

            if active_blocks and ip in active_blocks:
                # Enhanced display with tier info
                tier = active_blocks[ip].get("tier", "unknown")
                block_until = active_blocks[ip].get("block_until", "unknown")

                # Format block_until in local timezone
                try:
                    block_until_dt = datetime.fromisoformat(block_until)
                    if block_until_dt.tzinfo is None:
                        block_until_dt = block_until_dt.replace(tzinfo=timezone.utc)
                    # Show in local time with timezone indicator
                    local_dt = block_until_dt.astimezone()
                    block_until_str = local_dt.strftime("%Y-%m-%d %H:%M %Z")
                except Exception:
                    block_until_str = str(block_until) if block_until else ""

                # Show total hits from registry if no recent hits
                if hits == 0:
                    hits = active_blocks[ip].get("total_hits", 0)

            if active_blocks:
                print(
                    f"{ip:<20} {str(hits):<10} {tier:<12} {status:<30} {block_until_str:<20}"
                )
            else:
                print(f"{ip:<20} {str(hits):<15} {status:<30}")

        # Print separator
        if active_blocks:
            print("-" * 92)
        else:
            print("-" * 65)

        # Print legend for dry-run mode
        if self.dry_run:
            print("\nLegend:")
            print("  → WILL BE BLOCKED    = New block to be added")
            print("  → WILL BE UNBLOCKED  = Expired block to be removed")
            print("  NO CHANGE (blocked)  = Currently blocked, no change needed")
            print("  SKIPPED (score=XX)   = Below threat score threshold")

        # Log AWS IP lookup stats if available
        if self.aws_ip_index is not None:
            hits, misses, hit_rate = self.aws_ip_index.get_lookup_stats()
            if hits + misses > 0:
                logging.info(
                    f"AWS IP lookup stats: {hits} lookups performed, "
                    f"{misses} unique IPs checked"
                )

    def _get_dry_run_status(
        self,
        ip: str,
        ips_to_add: Set[str],
        ips_to_remove: Set[str],
        final_blocked_ips: Set[str],
        skipped_ip_details: Dict[str, Tuple[float, Dict]],
        hits: int,
    ) -> str:
        """Determine display status for dry-run mode."""

        if ip in self.whitelist:
            return "WHITELISTED"

        if is_aws_ip_fast(ip, self.aws_ip_index):
            return "AWS IP (excluded)"

        if ip in ips_to_add:
            return "→ WILL BE BLOCKED"

        if ip in ips_to_remove:
            return "→ WILL BE UNBLOCKED (expired)"

        if ip in final_blocked_ips:
            return "NO CHANGE (blocked)"

        if ip in skipped_ip_details:
            score, _ = skipped_ip_details[ip]
            return f"SKIPPED (score={score:.0f})"

        if hits < self.threshold:
            return f"BELOW THRESHOLD ({hits}<{self.threshold})"

        return "NOT BLOCKED"

    def _get_live_run_status(
        self,
        ip: str,
        final_blocked_ips: Set[str],
        offenders: Set[str],
        hits: int,
    ) -> str:
        """Determine display status for live-run mode."""

        if ip in self.whitelist:
            return "WHITELISTED"

        if is_aws_ip_fast(ip, self.aws_ip_index):
            return "AWS IP (excluded)"

        if ip in final_blocked_ips:
            return "ACTIVE BLOCK"

        if ip in offenders:
            return "SHOULD BE BLOCKED (slot full?)"

        if hits < self.threshold:
            return "BELOW THRESHOLD"

        return "NOT BLOCKED"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Analyze ALB logs, identify attacker IPs, and automatically block them in the associated Network ACL.",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Example Dry Run (scans all LBs matching the default 'alb-*' pattern):
  python %(prog)s

Example Live Run (scans a specific pattern, provides a whitelist):
  python %(prog)s --lb-name-pattern "alb-test-*" --whitelist-file whitelist.txt --live-run
""",
    )
    parser.add_argument(
        "--lb-name-pattern",
        default="alb-*",
        help="Pattern to match Load Balancer names (e.g., 'alb-*'). Default is 'alb-*'.",
    )
    parser.add_argument(
        "--region",
        default="ap-southeast-2",
        help="The AWS region of the resources (default: ap-southeast-2).",
    )
    parser.add_argument(
        "--lookback",
        default="60m",
        help="Lookback period to scan for logs. Format: 30m, 2h, 1d (default: 60m).",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=50,
        help="Block an IP if it sends more than this many malicious requests (default: 50).",
    )
    parser.add_argument(
        "--start-rule",
        type=int,
        default=80,
        help="The starting rule number for the managed DENY rule block (default: 80).",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Maximum number of DENY rules to manage (default: 20, capped by NACL rule 99).",
    )
    parser.add_argument(
        "--whitelist-file",
        default="whitelist.txt",
        help="Path to a file containing whitelisted IPs (one per line).",
    )
    parser.add_argument(
        "--aws-ip-ranges-file",
        default="ip-ranges.json",
        help="Path to AWS ip-ranges.json file. If provided, automatically excludes all AWS IPs from blocking.",
    )
    parser.add_argument(
        "--no-auto-download-ip-ranges",
        action="store_true",
        help="Disable automatic download of AWS IP ranges file. Use for air-gapped environments. "
        "If disabled and file is missing, AWS IP exclusion will be unavailable.",
    )
    parser.add_argument(
        "--live-run",
        action="store_true",
        help="Actually create the NACL rules. Default is a dry run.",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable verbose debug logging."
    )
    parser.add_argument(
        "--slack-token",
        default=None,
        help="Slack bot token for sending notifications (also can use SLACK_BOT_TOKEN env var).",
    )
    parser.add_argument(
        "--slack-channel",
        default=None,
        help="Slack channel to send notifications to (also can use SLACK_CHANNEL env var).",
    )
    parser.add_argument(
        "--enhanced-slack",
        action="store_true",
        help="Enable enhanced Slack notifications with color coding, threading, and formatted fields.",
    )

    # Athena integration options
    parser.add_argument(
        "--athena",
        action="store_true",
        help="Enable Athena for large-scale log analysis. Recommended for >1000 log files.",
    )
    parser.add_argument(
        "--athena-database",
        default="alb_logs",
        help="Athena database name for ALB log tables (default: alb_logs).",
    )
    parser.add_argument(
        "--athena-output-location",
        default=None,
        help="S3 location for Athena query results (e.g., s3://my-bucket/athena-results/). Required if --athena is used.",
    )

    parser.add_argument(
        "--ipinfo-token",
        default=None,
        help="IPInfo API token for IP geolocation (also can use IPINFO_TOKEN env var).",
    )
    parser.add_argument(
        "--registry-file",
        default=None,
        help="Path to block registry JSON file for persistent time-based blocking (default: ./block_registry.json).",
    )

    # Storage backend options
    parser.add_argument(
        "--storage-backend",
        choices=["local", "dynamodb", "s3"],
        default=None,
        help="Storage backend type: 'local' (JSON file), 'dynamodb' (DynamoDB table), 's3' (S3 bucket). "
        "Default: 'local'. Also can use STORAGE_BACKEND env var.",
    )
    parser.add_argument(
        "--dynamodb-table",
        default=None,
        help="DynamoDB table name for block registry (required if storage-backend=dynamodb). "
        "Also can use DYNAMODB_TABLE env var.",
    )
    parser.add_argument(
        "--s3-state-bucket",
        default=None,
        help="S3 bucket name for block registry (required if storage-backend=s3). "
        "Also can use S3_STATE_BUCKET env var.",
    )
    parser.add_argument(
        "--s3-state-key",
        default="block_registry.json",
        help="S3 object key for block registry (default: block_registry.json). "
        "Also can use S3_STATE_KEY env var.",
    )
    parser.add_argument(
        "--create-dynamodb-table",
        action="store_true",
        help="Create the DynamoDB table if it doesn't exist (requires additional IAM permissions).",
    )

    # IPv6 support options
    parser.add_argument(
        "--enable-ipv6",
        action="store_true",
        default=True,
        help="Enable IPv6 blocking (default: enabled). Use --no-ipv6 to disable.",
    )
    parser.add_argument(
        "--no-ipv6",
        action="store_true",
        help="Disable IPv6 blocking (only block IPv4 addresses).",
    )
    parser.add_argument(
        "--start-rule-ipv6",
        type=int,
        default=180,
        help="Starting NACL rule number for IPv6 DENY rules (default: 180).",
    )
    parser.add_argument(
        "--limit-ipv6",
        type=int,
        default=20,
        help="Maximum number of IPv6 DENY rules to manage (default: 20).",
    )
    parser.add_argument(
        "--force-reprocess",
        action="store_true",
        help="Force reprocessing of all log files, ignoring the processed files cache.",
    )

    # AWS WAF IP Set arguments
    parser.add_argument(
        "--waf-ip-set-name",
        type=str,
        help="Name of the AWS WAF IP Set to sync blocked IPs to (enables WAF integration).",
    )
    parser.add_argument(
        "--waf-ip-set-id",
        type=str,
        help="ID of an existing AWS WAF IP Set to use (alternative to --waf-ip-set-name).",
    )
    parser.add_argument(
        "--waf-ip-set-scope",
        type=str,
        choices=["REGIONAL", "CLOUDFRONT"],
        default="REGIONAL",
        help="WAF IP Set scope: REGIONAL (for ALB/API Gateway) or CLOUDFRONT (default: REGIONAL).",
    )
    parser.add_argument(
        "--create-waf-ip-set",
        action="store_true",
        help="Create the WAF IP Set if it doesn't exist.",
    )

    # Structured logging & CloudWatch metrics
    parser.add_argument(
        "--json-logging",
        action="store_true",
        help="Enable JSON structured logging format (for CloudWatch Logs ingestion).",
    )
    parser.add_argument(
        "--enable-cloudwatch-metrics",
        action="store_true",
        help="Enable publishing metrics to CloudWatch (requires IAM permissions).",
    )
    parser.add_argument(
        "--cloudwatch-namespace",
        type=str,
        default="AutoBlockAttackers",
        help="CloudWatch metrics namespace (default: AutoBlockAttackers).",
    )

    # Multi-signal threat detection
    parser.add_argument(
        "--disable-multi-signal",
        action="store_true",
        help="Disable multi-signal threat detection (use pattern matching only).",
    )
    parser.add_argument(
        "--min-threat-score",
        type=int,
        default=40,
        help="Minimum threat score (0-100) to block an IP (default: 40).",
    )

    args = parser.parse_args()

    # Get Slack credentials from args or environment variables
    slack_token = args.slack_token or os.getenv("SLACK_BOT_TOKEN")
    slack_channel = args.slack_channel or os.getenv("SLACK_CHANNEL")

    # Get IPInfo token from args or environment variable
    ipinfo_token = args.ipinfo_token or os.getenv("IPINFO_TOKEN")

    # Get storage backend configuration from args or environment variables
    storage_backend = args.storage_backend or os.getenv("STORAGE_BACKEND", "local")
    dynamodb_table = args.dynamodb_table or os.getenv("DYNAMODB_TABLE")
    s3_state_bucket = args.s3_state_bucket or os.getenv("S3_STATE_BUCKET")
    s3_state_key = args.s3_state_key or os.getenv("S3_STATE_KEY", "block_registry.json")

    # Get WAF configuration from args or environment variables
    waf_ip_set_name = args.waf_ip_set_name or os.getenv("WAF_IP_SET_NAME")
    waf_ip_set_id = args.waf_ip_set_id or os.getenv("WAF_IP_SET_ID")
    waf_ip_set_scope = args.waf_ip_set_scope or os.getenv("WAF_IP_SET_SCOPE", "REGIONAL")
    create_waf_ip_set = args.create_waf_ip_set or os.getenv("CREATE_WAF_IP_SET", "").lower() == "true"

    # Get logging & metrics configuration
    json_logging = args.json_logging or os.getenv("JSON_LOGGING", "").lower() == "true"
    enable_cloudwatch_metrics = args.enable_cloudwatch_metrics or os.getenv("ENABLE_CLOUDWATCH_METRICS", "").lower() == "true"
    cloudwatch_namespace = args.cloudwatch_namespace or os.getenv("CLOUDWATCH_NAMESPACE", "AutoBlockAttackers")

    # Get multi-signal configuration
    disable_multi_signal = args.disable_multi_signal or os.getenv("DISABLE_MULTI_SIGNAL", "").lower() == "true"
    enable_multi_signal = not disable_multi_signal
    min_threat_score_env = os.getenv("MIN_THREAT_SCORE")
    min_threat_score = args.min_threat_score if not min_threat_score_env else int(min_threat_score_env)

    # Build threat signals config if score is customized
    threat_signals_config = None
    if min_threat_score != 40:  # Non-default value
        threat_signals_config = DEFAULT_THREAT_SIGNALS_CONFIG.copy()
        threat_signals_config["min_threat_score"] = min_threat_score

    # Validate inputs
    if args.threshold < 1:
        parser.error("Threshold must be at least 1")
    if args.threshold < 10:
        logging.warning(
            f"Threshold of {args.threshold} is very low and may block benign traffic. Recommended value is >= 25."
        )
    if args.start_rule < 1 or args.start_rule >= 100:
        parser.error("start-rule must be between 1 and 99")
    if args.limit < 1:
        parser.error("limit must be at least 1")
    if args.start_rule + args.limit > 100:
        logging.warning(
            f"start-rule ({args.start_rule}) + limit ({args.limit}) exceeds 100. "
            f"Will be capped at rule 99."
        )

    # Validate storage backend configuration
    if storage_backend == "dynamodb" and not dynamodb_table:
        parser.error("--dynamodb-table is required when using dynamodb storage backend")
    if storage_backend == "s3" and not s3_state_bucket:
        parser.error("--s3-state-bucket is required when using s3 storage backend")

    # Handle IPv6 enable/disable flag
    enable_ipv6 = not args.no_ipv6

    blocker = NaclAutoBlocker(
        lb_name_pattern=args.lb_name_pattern,
        region=args.region,
        lookback_str=args.lookback,
        threshold=args.threshold,
        start_rule=args.start_rule,
        limit=args.limit,
        whitelist_file=args.whitelist_file,
        aws_ip_ranges_file=args.aws_ip_ranges_file,
        dry_run=not args.live_run,
        debug=args.debug,
        slack_token=slack_token,
        slack_channel=slack_channel,
        ipinfo_token=ipinfo_token,
        registry_file=args.registry_file,
        storage_backend=storage_backend,
        dynamodb_table=dynamodb_table,
        s3_state_bucket=s3_state_bucket,
        s3_state_key=s3_state_key,
        create_dynamodb_table=args.create_dynamodb_table,
        # IPv6 support parameters
        start_rule_ipv6=args.start_rule_ipv6,
        limit_ipv6=args.limit_ipv6,
        enable_ipv6=enable_ipv6,
        # Incremental processing
        force_reprocess=args.force_reprocess,
        # AWS WAF IP Set integration
        waf_ip_set_name=waf_ip_set_name,
        waf_ip_set_scope=waf_ip_set_scope,
        waf_ip_set_id=waf_ip_set_id,
        create_waf_ip_set=create_waf_ip_set,
        # Structured logging & CloudWatch metrics
        json_logging=json_logging,
        enable_cloudwatch_metrics=enable_cloudwatch_metrics,
        cloudwatch_namespace=cloudwatch_namespace,
        # Multi-signal threat detection
        enable_multi_signal=enable_multi_signal,
        threat_signals_config=threat_signals_config,
        # Enhanced Slack notifications
        enhanced_slack=args.enhanced_slack,
        # Athena integration
        athena_enabled=args.athena,
        athena_database=args.athena_database,
        athena_output_location=args.athena_output_location,
        # Auto-download AWS IP ranges
        auto_download_ip_ranges=not args.no_auto_download_ip_ranges,
    )
    blocker.run()
