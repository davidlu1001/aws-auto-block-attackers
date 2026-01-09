# CLI Reference Guide

## AWS Auto Block Attackers - Command Line Interface

This guide provides comprehensive documentation for all command-line options with real-world examples.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Basic Options](#basic-options)
3. [Storage Backends](#storage-backends)
4. [IPv6 Configuration](#ipv6-configuration)
5. [AWS WAF Integration](#aws-waf-integration)
6. [Observability Options](#observability-options)
7. [Multi-Signal Detection](#multi-signal-detection)
8. [Athena Integration](#athena-integration)
9. [Slack Notifications](#slack-notifications)
10. [Common Use Cases](#common-use-cases)
11. [Environment Variables](#environment-variables)

---

## Quick Start

### Minimal Dry-Run

```bash
python3 auto_block_attackers.py
```

This runs with all defaults:
- Pattern: `alb-*`
- Region: `ap-southeast-2`
- Lookback: `60m`
- Threshold: `50`
- Dry-run mode (no actual changes)

### Minimal Production Run

```bash
python3 auto_block_attackers.py \
  --lb-name-pattern "prod-alb-*" \
  --live-run
```

---

## Basic Options

### `--lb-name-pattern`

**Description:** Glob pattern to match Application Load Balancer names.

**Default:** `alb-*`

**Examples:**

```bash
# Match all ALBs starting with "prod-"
--lb-name-pattern "prod-*"

# Match specific ALB
--lb-name-pattern "prod-api-alb"

# Match multiple patterns (run separately)
--lb-name-pattern "prod-web-*"
--lb-name-pattern "prod-api-*"

# Match ALBs with specific suffix
--lb-name-pattern "*-public-alb"
```

---

### `--region`

**Description:** AWS region where ALBs are located.

**Default:** `ap-southeast-2`

**Examples:**

```bash
--region us-east-1
--region eu-west-1
--region ap-northeast-1
```

---

### `--lookback`

**Description:** How far back to analyze logs. Supports minutes (m), hours (h), and days (d).

**Default:** `60m`

**Examples:**

```bash
# Last 30 minutes (quick scan)
--lookback 30m

# Last 2 hours (standard)
--lookback 2h

# Last 6 hours (extended)
--lookback 6h

# Last 1 day (full day analysis)
--lookback 1d

# Last 90 minutes (custom)
--lookback 90m
```

**Recommendations:**

| Use Case | Lookback | Rationale |
|----------|----------|-----------|
| Frequent runs (every 5 min) | `15m` | Minimize overlap |
| Standard cron (every 15 min) | `30m-60m` | Catch missed runs |
| Hourly runs | `90m` | Buffer for delays |
| Daily analysis | `24h` | Full day coverage |

---

### `--threshold`

**Description:** Minimum number of malicious requests required to trigger blocking.

**Default:** `50`

**Examples:**

```bash
# Aggressive (block quickly)
--threshold 20

# Standard
--threshold 50

# Conservative (reduce false positives)
--threshold 100

# Very conservative (only major attackers)
--threshold 500
```

**Guidelines:**

| Traffic Volume | Recommended Threshold |
|----------------|----------------------|
| Low (<1000 req/hr) | 20-30 |
| Medium (1000-10000 req/hr) | 50-100 |
| High (>10000 req/hr) | 100-200 |

---

### `--start-rule`

**Description:** Starting NACL rule number for IPv4 DENY rules.

**Default:** `80`

**Range:** Rules 80-99 are managed by default.

```bash
# Default (rules 80-99)
--start-rule 80

# Higher range (rules 100-119)
--start-rule 100 --limit 20

# Lower range (rules 50-69)
--start-rule 50 --limit 20
```

**Important:** Ensure the rule range doesn't conflict with existing NACL rules.

---

### `--limit`

**Description:** Maximum number of IPv4 DENY rules to manage.

**Default:** `20`

**Examples:**

```bash
# Fewer rules (conservative)
--limit 10

# Standard
--limit 20

# More rules (if NACL space available)
--limit 30 --start-rule 70
```

---

### `--whitelist-file`

**Description:** Path to file containing whitelisted IPs/CIDRs.

**Default:** `whitelist.txt`

**File Format:**

```text
# Office IP
203.0.113.50

# Partner network
198.51.100.0/24

# Monitoring service
192.0.2.10

# IPv6 addresses work too
2001:db8::1
2001:db8::/32
```

**Examples:**

```bash
--whitelist-file /etc/auto-block/whitelist.txt
--whitelist-file ./config/trusted-ips.txt
--whitelist-file ""  # Disable whitelist
```

---

### `--aws-ip-ranges-file`

**Description:** Path to AWS ip-ranges.json file for automatic AWS IP exclusion.

**Default:** `ip-ranges.json`

**Download:**

```bash
curl -o ip-ranges.json https://ip-ranges.amazonaws.com/ip-ranges.json
```

**Examples:**

```bash
--aws-ip-ranges-file /var/cache/aws-ip-ranges.json
--aws-ip-ranges-file ""  # Disable AWS IP exclusion (not recommended)
```

---

### `--registry-file`

**Description:** Path to block registry JSON file.

**Default:** `./block_registry.json`

```bash
--registry-file /var/lib/auto-block/registry.json
--registry-file ./data/blocks.json
```

---

### `--live-run`

**Description:** Actually create/modify NACL rules. Without this flag, runs in dry-run mode.

**Default:** `False` (dry-run)

```bash
# Dry-run (see what would happen)
python3 auto_block_attackers.py

# Live run (make changes)
python3 auto_block_attackers.py --live-run
```

---

### `--debug`

**Description:** Enable verbose debug logging.

```bash
python3 auto_block_attackers.py --debug 2>&1 | tee debug.log
```

---

## Storage Backends

### `--storage-backend`

**Description:** Choose where to persist block registry state.

**Options:** `local`, `dynamodb`, `s3`

**Default:** `local`

### Local File Storage (Default)

```bash
--storage-backend local
--registry-file ./block_registry.json
```

### DynamoDB Storage

```bash
# Use existing table
--storage-backend dynamodb
--dynamodb-table my-block-registry

# Auto-create table if missing
--storage-backend dynamodb
--dynamodb-table my-block-registry
--create-dynamodb-table
```

**DynamoDB Benefits:**
- Multi-AZ durability
- Supports concurrent access from multiple instances
- Automatic scaling with on-demand capacity

### S3 Storage

```bash
--storage-backend s3
--s3-state-bucket my-security-bucket
--s3-state-key auto-block/registry.json
```

**S3 Benefits:**
- 11 9's durability
- Version history
- Cross-region replication possible

---

## IPv6 Configuration

### `--start-rule-ipv6`

**Description:** Starting NACL rule number for IPv6 DENY rules.

**Default:** `180`

```bash
--start-rule-ipv6 180  # Rules 180-199
--start-rule-ipv6 200  # Rules 200-219
```

### `--limit-ipv6`

**Description:** Maximum number of IPv6 DENY rules.

**Default:** `20`

```bash
--limit-ipv6 20
--limit-ipv6 10  # Fewer IPv6 rules
```

### `--disable-ipv6`

**Description:** Disable IPv6 blocking entirely.

```bash
--disable-ipv6
```

### Full IPv6 Example

```bash
python3 auto_block_attackers.py \
  --lb-name-pattern "prod-*" \
  --start-rule 80 \
  --limit 20 \
  --start-rule-ipv6 180 \
  --limit-ipv6 20 \
  --live-run
```

---

## AWS WAF Integration

### `--waf-ip-set-name`

**Description:** Name of WAF IP Set to synchronize.

```bash
--waf-ip-set-name "blocked-attackers"
--waf-ip-set-name "auto-block-prod"
```

### `--waf-ip-set-scope`

**Description:** WAF scope for IP Set.

**Options:** `REGIONAL`, `CLOUDFRONT`

**Default:** `REGIONAL`

```bash
--waf-ip-set-scope REGIONAL    # For regional WAF (ALB, API Gateway)
--waf-ip-set-scope CLOUDFRONT  # For CloudFront distributions
```

### `--waf-ip-set-id`

**Description:** Specific IP Set ID (optional, will find by name if not provided).

```bash
--waf-ip-set-id "a1b2c3d4-5678-90ab-cdef-EXAMPLE11111"
```

### `--create-waf-ip-set`

**Description:** Create the WAF IP Set if it doesn't exist.

```bash
--waf-ip-set-name "blocked-attackers" \
--create-waf-ip-set
```

### Full WAF Example

```bash
python3 auto_block_attackers.py \
  --lb-name-pattern "prod-*" \
  --waf-ip-set-name "auto-blocked-ips" \
  --waf-ip-set-scope REGIONAL \
  --create-waf-ip-set \
  --live-run
```

---

## Observability Options

### `--json-logging`

**Description:** Output logs in JSON format for CloudWatch Logs ingestion.

```bash
python3 auto_block_attackers.py --json-logging 2>&1 | tee /var/log/auto-block.json
```

**Sample Output:**

```json
{"timestamp": "2026-01-09T10:30:00Z", "level": "INFO", "message": "Processing 150 log files..."}
{"timestamp": "2026-01-09T10:30:05Z", "level": "WARNING", "message": "Blocking IP 1.2.3.4 (1523 hits)"}
```

### `--enable-cloudwatch-metrics`

**Description:** Publish metrics to CloudWatch.

```bash
--enable-cloudwatch-metrics
```

### `--cloudwatch-namespace`

**Description:** CloudWatch namespace for metrics.

**Default:** `AutoBlockAttackers`

```bash
--enable-cloudwatch-metrics \
--cloudwatch-namespace "Security/AutoBlock"
```

### Full Observability Example

```bash
python3 auto_block_attackers.py \
  --lb-name-pattern "prod-*" \
  --json-logging \
  --enable-cloudwatch-metrics \
  --cloudwatch-namespace "Production/Security/AutoBlock" \
  --live-run
```

---

## Multi-Signal Detection

### `--disable-multi-signal`

**Description:** Disable multi-signal threat detection (use pattern matching only).

```bash
--disable-multi-signal
```

### `--min-threat-score`

**Description:** Minimum threat score to confirm an IP as malicious.

**Default:** `40`

**Range:** `0-100`

```bash
# More aggressive (lower score = more blocks)
--min-threat-score 30

# Standard
--min-threat-score 40

# More conservative (higher score = fewer blocks)
--min-threat-score 60
```

### Understanding Threat Scores

| Score | Interpretation |
|-------|----------------|
| 0-20 | Low threat (likely false positive) |
| 20-40 | Moderate threat (borderline) |
| 40-60 | Confirmed threat (standard) |
| 60-80 | High confidence threat |
| 80-100 | Definite attacker |

### Full Multi-Signal Example

```bash
python3 auto_block_attackers.py \
  --lb-name-pattern "prod-*" \
  --min-threat-score 45 \
  --debug \
  --live-run
```

---

## Athena Integration

### `--athena`

**Description:** Enable Athena for large-scale log analysis.

### `--athena-database`

**Description:** Athena database name.

**Default:** `alb_logs`

```bash
--athena-database security_logs
--athena-database prod_alb_analysis
```

### `--athena-output-location`

**Description:** S3 location for Athena query results. **Required when using Athena.**

```bash
--athena-output-location "s3://my-bucket/athena-results/"
```

### Full Athena Example

```bash
python3 auto_block_attackers.py \
  --lb-name-pattern "prod-*" \
  --athena \
  --athena-database "security_logs" \
  --athena-output-location "s3://my-bucket/athena-results/" \
  --lookback 24h \
  --live-run
```

**When to Use Athena:**
- More than 1000 log files to process
- Historical analysis (multiple days)
- Complex filtering requirements

---

## Slack Notifications

### `--slack-token`

**Description:** Slack bot token for notifications.

```bash
--slack-token "xoxb-1234567890-abcdefghijk"
```

**Prefer environment variable:** `SLACK_BOT_TOKEN`

### `--slack-channel`

**Description:** Slack channel ID or name.

```bash
--slack-channel "C04ABCDEFG"
--slack-channel "#security-alerts"
```

**Prefer environment variable:** `SLACK_CHANNEL`

### `--enhanced-slack`

**Description:** Enable enhanced Slack notifications with:
- Severity-based color coding
- Block Kit formatting
- Incident threading
- Structured fields

```bash
--enhanced-slack
```

### Slack Setup

1. Create a Slack App at https://api.slack.com/apps
2. Add Bot Token Scopes: `chat:write`, `files:write`
3. Install to workspace
4. Copy Bot User OAuth Token

### Full Slack Example

```bash
export SLACK_BOT_TOKEN="xoxb-your-token"
export SLACK_CHANNEL="C04SECURITY"

python3 auto_block_attackers.py \
  --lb-name-pattern "prod-*" \
  --enhanced-slack \
  --live-run
```

---

## Common Use Cases

### 1. Development/Testing

```bash
python3 auto_block_attackers.py \
  --lb-name-pattern "dev-*" \
  --lookback 30m \
  --threshold 10 \
  --debug
```

### 2. Production - Hourly Cron

```bash
# crontab entry
0 * * * * /opt/auto-block/run.sh >> /var/log/auto-block.log 2>&1

# run.sh
#!/bin/bash
cd /opt/auto-block
python3 auto_block_attackers.py \
  --lb-name-pattern "prod-*" \
  --region us-east-1 \
  --lookback 90m \
  --threshold 75 \
  --storage-backend dynamodb \
  --dynamodb-table prod-block-registry \
  --enable-cloudwatch-metrics \
  --enhanced-slack \
  --live-run
```

### 3. Multi-Region Deployment

```bash
# Region 1
python3 auto_block_attackers.py \
  --lb-name-pattern "prod-*" \
  --region us-east-1 \
  --dynamodb-table global-block-registry \
  --live-run

# Region 2
python3 auto_block_attackers.py \
  --lb-name-pattern "prod-*" \
  --region eu-west-1 \
  --dynamodb-table global-block-registry \
  --live-run
```

### 4. High-Security Environment

```bash
python3 auto_block_attackers.py \
  --lb-name-pattern "prod-*" \
  --threshold 25 \
  --min-threat-score 35 \
  --waf-ip-set-name "blocked-ips" \
  --create-waf-ip-set \
  --storage-backend dynamodb \
  --dynamodb-table secure-block-registry \
  --json-logging \
  --enable-cloudwatch-metrics \
  --enhanced-slack \
  --live-run
```

### 5. Large-Scale with Athena

```bash
python3 auto_block_attackers.py \
  --lb-name-pattern "prod-*" \
  --athena \
  --athena-database "security_analysis" \
  --athena-output-location "s3://analytics-bucket/athena/" \
  --lookback 24h \
  --threshold 100 \
  --live-run
```

### 6. Conservative/Low False Positive

```bash
python3 auto_block_attackers.py \
  --lb-name-pattern "prod-*" \
  --threshold 200 \
  --min-threat-score 60 \
  --lookback 2h \
  --live-run
```

---

## Environment Variables

All sensitive values can be provided via environment variables:

| Variable | CLI Equivalent | Description |
|----------|---------------|-------------|
| `SLACK_BOT_TOKEN` | `--slack-token` | Slack bot token |
| `SLACK_CHANNEL` | `--slack-channel` | Slack channel |
| `IPINFO_TOKEN` | `--ipinfo-token` | IPInfo API token |
| `STORAGE_BACKEND` | `--storage-backend` | Storage type |
| `DYNAMODB_TABLE` | `--dynamodb-table` | DynamoDB table name |
| `S3_STATE_BUCKET` | `--s3-state-bucket` | S3 bucket for state |
| `S3_STATE_KEY` | `--s3-state-key` | S3 key for state |
| `DISABLE_MULTI_SIGNAL` | `--disable-multi-signal` | Set to "true" to disable |
| `MIN_THREAT_SCORE` | `--min-threat-score` | Threat score threshold |
| `AWS_DEFAULT_REGION` | `--region` | AWS region |

### Example .env File

```bash
# AWS (if not using IAM role)
AWS_DEFAULT_REGION=us-east-1

# Slack
SLACK_BOT_TOKEN=xoxb-your-token-here
SLACK_CHANNEL=C04SECURITY

# IPInfo (optional)
IPINFO_TOKEN=your-ipinfo-token

# Storage
STORAGE_BACKEND=dynamodb
DYNAMODB_TABLE=auto-block-registry

# Threat Detection
MIN_THREAT_SCORE=40
```

### Loading Environment

```bash
# Load from file
source .env && python3 auto_block_attackers.py --live-run

# Or use direnv
echo "dotenv" > .envrc
direnv allow
python3 auto_block_attackers.py --live-run
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Runtime error |
| 2 | Configuration error |

---

## Help

```bash
python3 auto_block_attackers.py --help
```
