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

__version__ = "1.0.0"
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
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import fnmatch
from typing import Set, List, Dict, Tuple, Optional
import os
import sys
import ipinfo

# Import SlackClient from the same directory
try:
    from slack_client import SlackClient
except ImportError:
    # If running from a different directory
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from slack_client import SlackClient

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


def setup_logging(debug: bool = False):
    """Configures logging level."""
    log_level = logging.DEBUG if debug else logging.INFO
    # Force reconfiguration even if basicConfig was already called
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s - %(levelname)s - %(message)s",
        force=True,  # Python 3.8+ - forces reconfiguration
    )


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


def load_aws_ip_ranges(file_path: Optional[str]) -> Set[ipaddress.IPv4Network]:
    """
    Loads AWS IP ranges from ip-ranges.json file.
    Returns a set of IPv4Network objects for efficient IP membership testing.
    """
    if not file_path:
        return set()

    try:
        json_path = Path(file_path)
        if not json_path.exists():
            logging.warning(f"AWS IP ranges file not found: {file_path}")
            return set()

        with open(json_path, "r") as f:
            data = json.load(f)

        aws_networks = set()
        for prefix in data.get("prefixes", []):
            ip_prefix = prefix.get("ip_prefix")
            if ip_prefix and "/" in ip_prefix:
                try:
                    network = ipaddress.ip_network(ip_prefix, strict=False)
                    if network.version == 4:  # Only IPv4
                        aws_networks.add(network)
                except ValueError:
                    continue

        logging.info(f"Loaded {len(aws_networks)} AWS IPv4 ranges from {file_path}")
        return aws_networks

    except Exception as e:
        logging.warning(f"Error loading AWS IP ranges from {file_path}: {e}")
        return set()


def is_aws_ip(ip_str: str, aws_networks: Set[ipaddress.IPv4Network]) -> bool:
    """
    Checks if an IP address belongs to AWS IP ranges.
    Uses early termination for efficiency.
    """
    if not aws_networks:
        return False

    try:
        ip = ipaddress.ip_address(ip_str)
        # Iterate through networks - will return True immediately on first match
        return any(ip in network for network in aws_networks)
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
    ):
        setup_logging(debug)
        logging.info("Initializing NaclAutoBlocker...")
        self.lb_name_pattern = lb_name_pattern
        self.region = region
        self.lookback_delta = self._parse_lookback_period(lookback_str)
        self.threshold = threshold
        # Calculate end rule based on start_rule and limit
        end_rule = min(start_rule + limit, 100)
        self.deny_rule_range = range(start_rule, end_rule)  # Managed DENY rules
        self.nacl_limit = limit
        logging.info("Loading whitelist and AWS IP ranges...")
        self.whitelist = self._load_whitelist(whitelist_file)
        self.aws_networks = load_aws_ip_ranges(aws_ip_ranges_file)
        self.dry_run = dry_run

        # Block registry for persistent time-based blocking
        self.registry_file = registry_file or "./block_registry.json"
        self.tier_config = tier_config or DEFAULT_TIER_CONFIG
        self.block_registry: Dict[str, Dict] = {}
        logging.info(f"Using block registry file: {self.registry_file}")
        self._load_block_registry()

        # Initialize Slack client if credentials provided
        self.slack_client = None
        if slack_token and slack_channel:
            logging.info("Initializing Slack notifications...")
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

        logging.info("Initializing AWS clients (boto3)...")
        boto_config = Config(
            connect_timeout=10, read_timeout=15, retries={"max_attempts": 3}
        )
        self.ec2 = boto3.client("ec2", region_name=self.region, config=boto_config)
        self.elbv2 = boto3.client("elbv2", region_name=self.region, config=boto_config)
        self.s3 = boto3.client("s3", region_name=self.region, config=boto_config)
        self.sts = boto3.client("sts", region_name=self.region, config=boto_config)
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
        """Loads the block registry from JSON file. Creates new if not exists or corrupted."""
        try:
            if os.path.exists(self.registry_file):
                with open(self.registry_file, "r") as f:
                    data = json.load(f)
                    # Validate structure
                    if isinstance(data, dict):
                        self.block_registry = data
                        logging.info(
                            f"Loaded block registry with {len(self.block_registry)} IPs"
                        )
                    else:
                        logging.warning(
                            "Block registry has invalid structure. Starting fresh."
                        )
                        self.block_registry = {}
            else:
                logging.info(
                    "Block registry file not found. Starting with empty registry."
                )
                self.block_registry = {}
        except json.JSONDecodeError as e:
            logging.warning(f"Block registry JSON is corrupted: {e}. Starting fresh.")
            self.block_registry = {}
        except Exception as e:
            logging.warning(f"Error loading block registry: {e}. Starting fresh.")
            self.block_registry = {}

    def _save_block_registry(self):
        """Saves the block registry to JSON file."""
        if self.dry_run:
            logging.info("[DRY RUN] Would save block registry to file")
            return

        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(self.registry_file), exist_ok=True)

            # Write to temp file first, then atomic rename
            temp_file = f"{self.registry_file}.tmp"
            with open(temp_file, "w") as f:
                json.dump(self.block_registry, f, indent=2, default=str)
            os.rename(temp_file, self.registry_file)
            logging.info(f"Saved block registry with {len(self.block_registry)} IPs")
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

    def _update_registry_entry(self, ip: str, hit_count: int, now: datetime):
        """Updates or creates a registry entry for an IP."""
        tier_name, duration, priority = self._determine_tier(hit_count)
        block_until = now + duration

        existing = self.block_registry.get(ip)
        if existing:
            # Update existing entry
            old_tier = existing.get("tier", "unknown")
            old_priority = existing.get("priority", 0)
            old_block_until = existing.get("block_until")

            # Keep the earlier first_seen timestamp
            first_seen = existing.get("first_seen", now.isoformat())

            # Only extend block time if tier upgraded (priority increased)
            if priority > old_priority:
                logging.info(
                    f"Upgrading {ip} from {old_tier} to {tier_name} tier - extending block duration"
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
            }
        else:
            # Create new entry
            self.block_registry[ip] = {
                "first_seen": now.isoformat(),
                "last_seen": now.isoformat(),
                "total_hits": hit_count,
                "tier": tier_name,
                "priority": priority,
                "block_until": block_until.isoformat(),
                "block_duration_hours": duration.total_seconds() / 3600,
            }

    def _remove_registry_entry(self, ip: str):
        """Removes an IP from the registry."""
        if ip in self.block_registry:
            del self.block_registry[ip]

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
        logging.info(
            "--- Starting Automated Attacker Blocking Script (Tiered Persistence Mode) ---"
        )
        if self.dry_run:
            logging.warning("*** RUNNING IN DRY RUN MODE. NO CHANGES WILL BE MADE. ***")

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
        else:
            logging.info("No expired blocks found.")

        # Periodic cleanup of very old entries (prevents unbounded growth)
        self._cleanup_old_registry_entries(now, days_old=30)

        logging.info("Step 5/7: Scanning S3 for ALB log files...")
        start_scan_time = now - self.lookback_delta
        all_log_keys = []
        for bucket, prefix in unique_log_locations:
            keys = self._find_log_files_in_window(bucket, prefix, start_scan_time)
            all_log_keys.extend([(bucket, key) for key in keys])

        logging.info(f"Step 6/7: Processing {len(all_log_keys)} log file(s)...")

        # Process logs and get new offenders
        new_offenders = set()
        ip_counts = Counter()

        if all_log_keys:
            all_malicious_ips = self._process_logs_in_parallel(all_log_keys)
            if all_malicious_ips:
                ip_counts = Counter(all_malicious_ips)
                new_offenders = {
                    ip
                    for ip, count in ip_counts.items()
                    if count >= self.threshold
                    and ip not in self.whitelist
                    and not is_aws_ip(ip, self.aws_networks)
                }

                if new_offenders:
                    logging.warning(
                        f"Identified {len(new_offenders)} new offender(s) from recent logs."
                    )
                    # Update registry with new offenders
                    for ip in new_offenders:
                        self._update_registry_entry(ip, ip_counts[ip], now)
            else:
                logging.info("No malicious activity found in recent log files.")
        else:
            logging.info("No relevant log files found in lookback window.")

        # Get all IPs that should be blocked (active blocks from registry)
        active_blocks = self._get_active_blocks(now)
        ips_to_block = set(active_blocks.keys())

        logging.info(f"Total active blocks in registry: {len(ips_to_block)}")

        logging.info("Step 7/7: Updating NACL rules with time-based blocks...")
        self._update_nacl_rules_with_registry(nacl_id, ips_to_block, active_blocks)

        # Save registry
        self._save_block_registry()

        final_deny_rules, _ = self._get_nacl_rules(nacl_id)
        final_blocked_ips = {cidr.split("/")[0] for cidr in final_deny_rules.values()}
        self._generate_report(
            ip_counts, new_offenders, final_blocked_ips, active_blocks
        )

        # Send summary notification to Slack (only if there were changes)
        self._send_summary_notification_with_registry(
            new_offenders,
            final_blocked_ips,
            ip_counts,
            initially_blocked_ips,
            active_blocks,
        )

        logging.info("--- Script Finished ---")

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
    ) -> List[str]:
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

            log_files_to_process = []

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
                                log_files_to_process.append(obj["Key"])

            logging.info(
                f"S3 scan complete: found {len(log_files_to_process)} matching log file(s) across {len(date_prefixes)} date(s)."
            )
            return log_files_to_process
        except Exception as e:
            logging.error(f"Error listing S3 objects for prefix {prefix}: {e}")
            return []

    def _process_logs_in_parallel(
        self, bucket_key_pairs: List[Tuple[str, str]]
    ) -> List[str]:
        """Uses a thread pool to download and parse logs concurrently."""
        all_malicious_ips = []
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

    def _download_and_parse_log(self, bucket: str, key: str) -> List[str]:
        logging.debug(f"Starting processing for file: {key.split('/')[-1]}")
        response = self.s3.get_object(Bucket=bucket, Key=key)
        with gzip.open(response["Body"], "rt") as f:
            malicious_ips = []
            for line in f:
                if ATTACK_PATTERNS.search(line):
                    parts = line.split()
                    if len(parts) > 3:
                        ip_str = parts[3].split(":")[0]
                        if is_valid_public_ipv4(ip_str):
                            malicious_ips.append(ip_str)
        logging.debug(
            f"Finished processing file: {key.split('/')[-1]}, found {len(malicious_ips)} malicious IPs."
        )
        return malicious_ips

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
        """
        if not self.slack_client:
            return

        # Add emoji prefix for critical messages
        if is_critical:
            message = f":warning: {message}"

        try:
            success = self.slack_client.post_message(message=message)
            if success:
                logging.debug(f"Slack notification sent: {message}")
            else:
                logging.debug("Failed to send Slack notification")
        except Exception as e:
            logging.warning(f"Error sending Slack notification: {e}")

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

    def _get_ip_info(self, ip: str) -> Optional[Dict]:
        """
        Fetches detailed geolocation and hosting information for an IP address.
        Returns None if ipinfo is not configured or if lookup fails.
        Uses in-memory caching to reduce API calls.
        """
        if not self.ipinfo_handler:
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

            return info
        except Exception as e:
            logging.warning(f"Failed to fetch IP info for {ip}: {e}")
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
    ):
        """Prints a final summary table of actions taken."""
        print("\n--- SCRIPT EXECUTION SUMMARY ---")
        if active_blocks:
            print(
                f"{'IP Address':<20} {'Hits':<10} {'Tier':<12} {'Status':<25} {'Block Until':<20}"
            )
            print("-" * 87)
        else:
            print(f"{'IP Address':<20} {'Malicious Hits':<15} {'Status':<20}")
            print("-" * 55)

        # Include IPs from recent detection and registry
        all_detected_ips = {
            ip for ip, count in ip_counts.items() if count >= self.threshold
        }
        report_ips = all_detected_ips.union(final_blocked_ips)

        # If using registry, include all active blocks
        if active_blocks:
            report_ips = report_ips.union(set(active_blocks.keys()))

        sorted_report_ips = sorted(
            list(report_ips), key=lambda ip: ip_counts.get(ip, 0), reverse=True
        )

        if not sorted_report_ips and ip_counts:
            logging.info(
                "Malicious activity was detected, but no single IP met the threshold."
            )

        for ip in sorted_report_ips:
            status = "NOT BLOCKED (Below Threshold)"
            if ip in self.whitelist:
                status = "WHITELISTED"
            elif is_aws_ip(ip, self.aws_networks):
                status = "AWS IP (Excluded)"
            elif ip in final_blocked_ips:
                status = "ACTIVE BLOCK"
            elif ip in offenders:
                status = "SHOULD BE BLOCKED"

            hits = ip_counts.get(ip, 0)

            if active_blocks and ip in active_blocks:
                # Enhanced display with tier info
                tier = active_blocks[ip].get("tier", "unknown")
                block_until = active_blocks[ip].get("block_until", "unknown")

                # Format block_until
                try:
                    block_until_dt = datetime.fromisoformat(block_until)
                    if block_until_dt.tzinfo is None:
                        block_until_dt = block_until_dt.replace(tzinfo=timezone.utc)
                    block_until_str = block_until_dt.strftime("%Y-%m-%d %H:%M")
                except Exception:
                    block_until_str = "unknown"

                # Show total hits from registry if no recent hits
                if hits == 0:
                    hits = active_blocks[ip].get("total_hits", 0)

                print(
                    f"{ip:<20} {str(hits):<10} {tier:<12} {status:<25} {block_until_str:<20}"
                )
            else:
                print(f"{ip:<20} {str(hits):<15} {status:<20}")

        if active_blocks:
            print("-" * 87)
        else:
            print("-" * 55)


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
        "--ipinfo-token",
        default=None,
        help="IPInfo API token for IP geolocation (also can use IPINFO_TOKEN env var).",
    )
    parser.add_argument(
        "--registry-file",
        default=None,
        help="Path to block registry JSON file for persistent time-based blocking (default: ./block_registry.json).",
    )

    args = parser.parse_args()

    # Get Slack credentials from args or environment variables
    slack_token = args.slack_token or os.getenv("SLACK_BOT_TOKEN")
    slack_channel = args.slack_channel or os.getenv("SLACK_CHANNEL")

    # Get IPInfo token from args or environment variable
    ipinfo_token = args.ipinfo_token or os.getenv("IPINFO_TOKEN")

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
    )
    blocker.run()
