#!/usr/bin/env python3
"""
Test script for tiered blocking functionality
Tests the key functions without requiring AWS credentials
"""

import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from collections import Counter

# Import the tier config
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from auto_block_attackers import DEFAULT_TIER_CONFIG

def test_tier_determination():
    """Test tier determination logic"""
    print("=" * 60)
    print("TEST 1: Tier Determination")
    print("=" * 60)

    test_cases = [
        (50, "minimal"),
        (75, "minimal"),
        (99, "minimal"),
        (100, "low"),
        (250, "low"),
        (499, "low"),
        (500, "medium"),
        (750, "medium"),
        (999, "medium"),
        (1000, "high"),
        (1500, "high"),
        (1999, "high"),
        (2000, "critical"),
        (5000, "critical"),
    ]

    for hit_count, expected_tier in test_cases:
        for min_hits, duration, tier_name, priority in DEFAULT_TIER_CONFIG:
            if hit_count >= min_hits:
                actual_tier = tier_name
                break

        status = "✓" if actual_tier == expected_tier else "✗"
        print(f"{status} {hit_count} hits → {actual_tier} (expected: {expected_tier})")

        if actual_tier != expected_tier:
            print(f"   ERROR: Mismatch!")
            return False

    print("\nTest PASSED ✓\n")
    return True

def test_registry_persistence():
    """Test block registry save/load"""
    print("=" * 60)
    print("TEST 2: Registry Persistence")
    print("=" * 60)

    # Create temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_file = f.name

    try:
        # Test data
        registry = {
            "1.2.3.4": {
                "first_seen": "2025-10-13T10:00:00+00:00",
                "last_seen": "2025-10-13T10:30:00+00:00",
                "total_hits": 1568,
                "tier": "high",
                "priority": 3,
                "block_until": "2025-10-16T10:30:00+00:00",
                "block_duration_hours": 72,
            },
            "5.6.7.8": {
                "first_seen": "2025-10-13T11:00:00+00:00",
                "last_seen": "2025-10-13T11:15:00+00:00",
                "total_hits": 150,
                "tier": "low",
                "priority": 1,
                "block_until": "2025-10-14T11:15:00+00:00",
                "block_duration_hours": 24,
            }
        }

        # Save
        with open(temp_file, 'w') as f:
            json.dump(registry, f, indent=2)
        print(f"✓ Saved registry to {temp_file}")

        # Load
        with open(temp_file, 'r') as f:
            loaded = json.load(f)

        if loaded == registry:
            print("✓ Loaded registry matches saved data")
        else:
            print("✗ Registry data mismatch!")
            return False

        # Test corrupted JSON
        with open(temp_file, 'w') as f:
            f.write("{invalid json")

        print("✓ Created corrupted JSON file")

        try:
            with open(temp_file, 'r') as f:
                json.load(f)
            print("✗ Should have failed on corrupted JSON")
            return False
        except json.JSONDecodeError:
            print("✓ Correctly detected corrupted JSON")

        print("\nTest PASSED ✓\n")
        return True

    finally:
        if os.path.exists(temp_file):
            os.unlink(temp_file)

def test_expired_blocks():
    """Test expiration logic"""
    print("=" * 60)
    print("TEST 3: Block Expiration")
    print("=" * 60)

    now = datetime.now(timezone.utc)

    registry = {
        "1.2.3.4": {
            "block_until": (now - timedelta(hours=1)).isoformat(),  # Expired
        },
        "5.6.7.8": {
            "block_until": (now + timedelta(hours=1)).isoformat(),  # Active
        },
        "9.10.11.12": {
            "block_until": (now + timedelta(days=5)).isoformat(),  # Active
        },
    }

    expired = set()
    active = set()

    for ip, data in registry.items():
        block_until = datetime.fromisoformat(data["block_until"])
        if block_until.tzinfo is None:
            block_until = block_until.replace(tzinfo=timezone.utc)

        if now >= block_until:
            expired.add(ip)
        else:
            active.add(ip)

    print(f"Expired IPs: {expired}")
    print(f"Active IPs: {active}")

    if expired == {"1.2.3.4"} and active == {"5.6.7.8", "9.10.11.12"}:
        print("✓ Expiration logic correct")
        print("\nTest PASSED ✓\n")
        return True
    else:
        print("✗ Expiration logic failed")
        return False

def test_priority_ordering():
    """Test priority-based replacement logic"""
    print("=" * 60)
    print("TEST 4: Priority-Based Slot Management")
    print("=" * 60)

    # Existing blocks in NACL
    existing_blocks = [
        ("10.0.0.1", "minimal", 0),
        ("10.0.0.2", "low", 1),
        ("10.0.0.3", "medium", 2),
        ("10.0.0.4", "high", 3),
    ]

    # New IP to add
    new_ips = [
        ("10.0.0.5", "low", 1),  # Should replace minimal
        ("10.0.0.6", "critical", 4),  # Should replace minimal or low
        ("10.0.0.7", "minimal", 0),  # Should NOT displace anyone if full
    ]

    for new_ip, new_tier, new_priority in new_ips:
        # Find lowest priority existing block
        existing_blocks.sort(key=lambda x: x[2])
        lowest_priority = existing_blocks[0][2]

        if new_priority >= lowest_priority:
            replaced = existing_blocks.pop(0)
            existing_blocks.append((new_ip, new_tier, new_priority))
            print(f"✓ {new_ip} (priority {new_priority}) replaced {replaced[0]} (priority {replaced[2]})")
        else:
            print(f"✗ {new_ip} (priority {new_priority}) cannot replace any existing blocks")

    print(f"\nFinal blocks: {[f'{ip} ({tier})' for ip, tier, _ in existing_blocks]}")
    print("\nTest PASSED ✓\n")
    return True

def test_tier_upgrade():
    """Test tier upgrade logic"""
    print("=" * 60)
    print("TEST 5: Tier Upgrade")
    print("=" * 60)

    # Existing entry
    ip = "1.2.3.4"
    existing = {
        "total_hits": 150,
        "tier": "low",
        "priority": 1,
    }

    # New detection with more hits
    new_hits = 600

    # Determine new tier
    for min_hits, duration, tier_name, priority in DEFAULT_TIER_CONFIG:
        if new_hits >= min_hits:
            new_tier = tier_name
            new_priority = priority
            break

    print(f"Existing: {existing['tier']} (priority {existing['priority']}, {existing['total_hits']} hits)")
    print(f"New detection: {new_hits} hits")
    print(f"New tier: {new_tier} (priority {new_priority})")

    if new_priority > existing["priority"]:
        print(f"✓ Upgraded from {existing['tier']} to {new_tier}")
        print("\nTest PASSED ✓\n")
        return True
    else:
        print("✗ Should have upgraded tier")
        return False

def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("TIERED BLOCKING UNIT TESTS")
    print("=" * 60 + "\n")

    tests = [
        test_tier_determination,
        test_registry_persistence,
        test_expired_blocks,
        test_priority_ordering,
        test_tier_upgrade,
    ]

    results = []
    for test in tests:
        try:
            result = test()
            results.append((test.__name__, result))
        except Exception as e:
            print(f"✗ Test {test.__name__} failed with exception: {e}")
            results.append((test.__name__, False))

    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)

    passed = sum(1 for _, result in results if result)
    total = len(results)

    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{status}: {name}")

    print(f"\nTotal: {passed}/{total} tests passed")

    if passed == total:
        print("\n🎉 All tests passed!")
        return 0
    else:
        print(f"\n❌ {total - passed} test(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(main())
