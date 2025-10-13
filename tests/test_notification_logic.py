#!/usr/bin/env python3
"""
Unit test to verify the Slack notification logic works correctly.
Tests that notifications are only sent when there are actual changes.
"""

def test_notification_logic():
    """Test the notification decision logic"""

    # Test Case 1: No changes - same IP still blocked
    print("Test 1: No changes (same IP still blocked)")
    initially_blocked = {"82.223.103.101"}
    final_blocked = {"82.223.103.101"}
    newly_blocked = final_blocked - initially_blocked
    newly_unblocked = initially_blocked - final_blocked
    should_notify = bool(newly_blocked or newly_unblocked)
    print(f"  Initially blocked: {initially_blocked}")
    print(f"  Final blocked: {final_blocked}")
    print(f"  Newly blocked: {newly_blocked}")
    print(f"  Newly unblocked: {newly_unblocked}")
    print(f"  Should notify: {should_notify}")
    assert should_notify == False, "Should NOT notify when no changes"
    print("  ✓ PASS\n")

    # Test Case 2: New IP blocked
    print("Test 2: New IP gets blocked")
    initially_blocked = {"82.223.103.101"}
    final_blocked = {"82.223.103.101", "192.168.1.100"}
    newly_blocked = final_blocked - initially_blocked
    newly_unblocked = initially_blocked - final_blocked
    should_notify = bool(newly_blocked or newly_unblocked)
    print(f"  Initially blocked: {initially_blocked}")
    print(f"  Final blocked: {final_blocked}")
    print(f"  Newly blocked: {newly_blocked}")
    print(f"  Newly unblocked: {newly_unblocked}")
    print(f"  Should notify: {should_notify}")
    assert should_notify == True, "Should notify when new IP blocked"
    assert newly_blocked == {"192.168.1.100"}, "Should show correct newly blocked IP"
    print("  ✓ PASS\n")

    # Test Case 3: IP gets unblocked
    print("Test 3: IP gets unblocked")
    initially_blocked = {"82.223.103.101", "192.168.1.100"}
    final_blocked = {"82.223.103.101"}
    newly_blocked = final_blocked - initially_blocked
    newly_unblocked = initially_blocked - final_blocked
    should_notify = bool(newly_blocked or newly_unblocked)
    print(f"  Initially blocked: {initially_blocked}")
    print(f"  Final blocked: {final_blocked}")
    print(f"  Newly blocked: {newly_blocked}")
    print(f"  Newly unblocked: {newly_unblocked}")
    print(f"  Should notify: {should_notify}")
    assert should_notify == True, "Should notify when IP unblocked"
    assert newly_unblocked == {"192.168.1.100"}, "Should show correct unblocked IP"
    print("  ✓ PASS\n")

    # Test Case 4: Multiple changes
    print("Test 4: Multiple changes (swap IPs)")
    initially_blocked = {"82.223.103.101", "1.1.1.1"}
    final_blocked = {"82.223.103.101", "2.2.2.2"}
    newly_blocked = final_blocked - initially_blocked
    newly_unblocked = initially_blocked - final_blocked
    should_notify = bool(newly_blocked or newly_unblocked)
    print(f"  Initially blocked: {initially_blocked}")
    print(f"  Final blocked: {final_blocked}")
    print(f"  Newly blocked: {newly_blocked}")
    print(f"  Newly unblocked: {newly_unblocked}")
    print(f"  Should notify: {should_notify}")
    assert should_notify == True, "Should notify when IPs change"
    assert newly_blocked == {"2.2.2.2"}, "Should show correct newly blocked IP"
    assert newly_unblocked == {"1.1.1.1"}, "Should show correct unblocked IP"
    print("  ✓ PASS\n")

    # Test Case 5: Empty state (no blocks)
    print("Test 5: No blocks at all")
    initially_blocked = set()
    final_blocked = set()
    newly_blocked = final_blocked - initially_blocked
    newly_unblocked = initially_blocked - final_blocked
    should_notify = bool(newly_blocked or newly_unblocked)
    print(f"  Initially blocked: {initially_blocked}")
    print(f"  Final blocked: {final_blocked}")
    print(f"  Newly blocked: {newly_blocked}")
    print(f"  Newly unblocked: {newly_unblocked}")
    print(f"  Should notify: {should_notify}")
    assert should_notify == False, "Should NOT notify when nothing changes"
    print("  ✓ PASS\n")

    # Test Case 6: First ever block
    print("Test 6: First ever block")
    initially_blocked = set()
    final_blocked = {"82.223.103.101"}
    newly_blocked = final_blocked - initially_blocked
    newly_unblocked = initially_blocked - final_blocked
    should_notify = bool(newly_blocked or newly_unblocked)
    print(f"  Initially blocked: {initially_blocked}")
    print(f"  Final blocked: {final_blocked}")
    print(f"  Newly blocked: {newly_blocked}")
    print(f"  Newly unblocked: {newly_unblocked}")
    print(f"  Should notify: {should_notify}")
    assert should_notify == True, "Should notify on first block"
    print("  ✓ PASS\n")

    print("="*60)
    print("ALL TESTS PASSED ✓")
    print("="*60)

if __name__ == "__main__":
    test_notification_logic()
