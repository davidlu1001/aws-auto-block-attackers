# Utility Scripts

This directory contains helper scripts for maintaining the AWS Auto Block Attackers system.

## Available Scripts

### `update_aws_ip_ranges.sh`

Downloads and updates the AWS IP ranges file used to exclude AWS service IPs from blocking.

**Purpose**: AWS publishes their IP ranges in a JSON file that changes periodically. This script keeps your local copy up-to-date to ensure AWS service IPs (health checks, CloudFront, etc.) are never blocked.

**Usage**:

```bash
# Download to default location (./ip-ranges.json)
./scripts/update_aws_ip_ranges.sh

# Download to custom location
./scripts/update_aws_ip_ranges.sh /path/to/ip-ranges.json
```

**Features**:
- Downloads from official AWS endpoint
- Validates JSON format before updating
- Creates backup of old file
- Logs all operations
- Falls back to existing file on download failure
- Atomic file updates (temp file + move)

**Automated Deployment**:

**Option 1: Cron Job** (Recommended)
```bash
# Edit crontab
crontab -e

# Add this line to update daily at 2 AM
0 2 * * * /opt/aws-auto-block-attackers/scripts/update_aws_ip_ranges.sh >> /var/log/aws-ip-update.log 2>&1
```

**Option 2: Systemd Timer**

Create `/etc/systemd/system/update-aws-ip-ranges.service`:
```ini
[Unit]
Description=Update AWS IP Ranges
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/opt/aws-auto-block-attackers/scripts/update_aws_ip_ranges.sh
StandardOutput=journal
StandardError=journal
```

Create `/etc/systemd/system/update-aws-ip-ranges.timer`:
```ini
[Unit]
Description=Update AWS IP Ranges Daily

[Timer]
OnCalendar=daily
OnBootSec=5min
Persistent=true

[Install]
WantedBy=timers.target
```

Enable and start:
```bash
sudo systemctl enable update-aws-ip-ranges.timer
sudo systemctl start update-aws-ip-ranges.timer
```

**Monitoring**:

```bash
# View logs
tail -f /var/log/auto-block-attackers.log | grep aws-ip-update

# Or with systemd
journalctl -u update-aws-ip-ranges.service -f

# Check file metadata
python3 -c "import json; data=json.load(open('ip-ranges.json')); print(f\"SyncToken: {data['syncToken']}\nCreateDate: {data['createDate']}\nPrefixes: {len(data['prefixes'])}\")"
```

**Error Handling**:
- Invalid JSON: Keeps old file, exits with error
- Download failure: Falls back to existing file if available
- Creates backups before each update

## Adding New Scripts

When adding new utility scripts to this directory:

1. **Name**: Use descriptive names with underscores (e.g., `cleanup_old_logs.sh`)
2. **Shebang**: Start with `#!/bin/bash` or `#!/usr/bin/env python3`
3. **Header**: Include purpose, usage, and examples
4. **Error Handling**: Use `set -euo pipefail` for bash scripts
5. **Logging**: Log to `/var/log/auto-block-attackers.log` or journal
6. **Documentation**: Update this README with script details
7. **Permissions**: Make executable with `chmod +x script_name.sh`

## Future Script Ideas

Consider adding these utility scripts:

- `cleanup_old_registry_entries.sh` - Remove expired entries from block registry
- `export_blocked_ips.sh` - Export current blocked IPs to CSV
- `verify_nacl_rules.sh` - Validate NACL rules match registry
- `rotate_logs.sh` - Manual log rotation helper
- `test_attack_patterns.sh` - Test regex patterns against sample logs
- `backup_config.sh` - Backup configuration and registry files

## Testing Scripts

Always test scripts in dry-run mode or staging environment first:

```bash
# Test download without overwriting
./update_aws_ip_ranges.sh /tmp/test-ip-ranges.json

# Verify the file
python3 -m json.tool /tmp/test-ip-ranges.json > /dev/null && echo "Valid JSON"
```
