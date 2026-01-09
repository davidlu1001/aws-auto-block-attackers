# AWS Auto Block Attackers

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Tests](https://img.shields.io/badge/tests-197%20passing-brightgreen.svg)]()

Automated AWS security tool that analyzes Application Load Balancer (ALB) access logs, detects malicious traffic patterns using multi-signal analysis, and implements tiered time-based IP blocking via Network ACLs (NACLs) and AWS WAF IP Sets.

## What's New in v2.0

- **Cloud-Native Storage**: DynamoDB and S3 backends for distributed deployments
- **IPv6 Support**: Full dual-stack blocking with separate rule ranges
- **AWS WAF Integration**: Parallel blocking via WAF IP Sets for edge protection
- **Multi-Signal Detection**: Reduces false positives by correlating multiple threat indicators
- **O(log N) AWS IP Lookup**: Fast binary search for AWS IP exclusion with auto-download of ip-ranges.json
- **Athena Integration**: SQL-based analysis for large-scale log processing
- **Enhanced Slack Notifications**: Color-coded severity, threading, Block Kit formatting
- **CloudWatch Metrics**: Built-in observability with custom namespace support
- **Structured JSON Logging**: CloudWatch Logs compatible output

## Features

### Core Capabilities

- **Tiered Blocking System**: 5-tier classification (Critical→Minimal) with proportional block durations
- **Multi-Signal Threat Detection**: Correlates attack patterns, scanner signatures, error rates, and path diversity
- **IPv4 + IPv6 Support**: Dual-stack blocking with independent rule management
- **Priority-Based Slot Management**: Critical attackers won't be displaced by lower-priority threats

### Attack Detection

- **30+ Attack Patterns**: LFI, XSS, SQL injection, command injection, path traversal, etc.
- **Scanner Detection**: Known scanner user-agent identification (Nikto, sqlmap, etc.)
- **Behavioral Analysis**: Error rate and path diversity scoring

### Integration Options

- **AWS WAF IP Sets**: Parallel blocking at edge (CloudFront, ALB, API Gateway)
- **Slack Notifications**: Real-time alerts with severity-based color coding
- **CloudWatch Metrics**: Operational metrics for dashboards and alarms
- **Athena Queries**: SQL-based analysis for historical data

### Operational Features

- **Cloud-Native Storage**: DynamoDB, S3, or local file persistence
- **Incremental Processing**: Skip already-analyzed log files
- **Circuit Breakers**: Graceful degradation on external service failures
- **Dry-Run Mode**: Test blocking logic without making changes

## Table of Contents

- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Tier System](#tier-system)
- [Storage Backends](#storage-backends)
- [AWS WAF Integration](#aws-waf-integration)
- [Multi-Signal Detection](#multi-signal-detection)
- [Athena Integration](#athena-integration)
- [Observability](#observability)
- [Architecture](#architecture)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Prerequisites

### Required

- **Python**: 3.8 or higher
- **AWS Account**: With ALB access logs enabled to S3
- **IAM Permissions**: See [IAM Policy](#iam-permissions)

### Optional

- **Slack Bot Token**: For notifications
- **IPInfo API Token**: For IP geolocation
- **DynamoDB/S3**: For cloud-native state storage
- **Athena**: For large-scale log analysis

## Installation

### Using uv (Recommended)

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
git clone https://github.com/davidlu1001/aws-auto-block-attackers.git
cd aws-auto-block-attackers
uv sync
```

### Using pip

```bash
git clone https://github.com/davidlu1001/aws-auto-block-attackers.git
cd aws-auto-block-attackers
python3 -m venv venv
source venv/bin/activate
pip install -e .
```

### Using Docker

```bash
docker pull davidlu1001/aws-auto-block-attackers:latest
docker run -v $(pwd)/config:/app/config aws-auto-block-attackers --live-run
```

## Quick Start

### 1. Configure AWS Credentials

```bash
# Option A: AWS CLI
aws configure

# Option B: Environment variables
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_DEFAULT_REGION="us-east-1"

# Option C: IAM Role (recommended for EC2/ECS)
```

### 2. Run Dry-Run Scan

```bash
python3 auto_block_attackers.py \
  --lb-name-pattern "alb-*" \
  --lookback 1h \
  --threshold 50 \
  --debug
```

### 3. Run Live Blocking

```bash
python3 auto_block_attackers.py \
  --lb-name-pattern "prod-*" \
  --lookback 1h \
  --threshold 50 \
  --live-run
```

### 4. Production Deployment (Cron)

```bash
# Run every 15 minutes
*/15 * * * * cd /opt/auto-block && python3 auto_block_attackers.py \
  --lb-name-pattern "prod-*" \
  --threshold 75 \
  --lookback 90m \
  --storage-backend dynamodb \
  --dynamodb-table block-registry \
  --enable-cloudwatch-metrics \
  --enhanced-slack \
  --live-run >> /var/log/auto-block.log 2>&1
```

## Configuration

### Command-Line Arguments

| Argument | Default | Description |
|----------|---------|-------------|
| `--lb-name-pattern` | `alb-*` | Pattern to match load balancer names |
| `--region` | `ap-southeast-2` | AWS region |
| `--lookback` | `60m` | Lookback period (30m, 2h, 1d) |
| `--threshold` | `50` | Minimum hits to trigger block |
| `--start-rule` | `80` | Starting NACL rule number (IPv4) |
| `--limit` | `20` | Maximum DENY rules (IPv4) |
| `--start-rule-ipv6` | `180` | Starting NACL rule number (IPv6) |
| `--limit-ipv6` | `20` | Maximum DENY rules (IPv6) |
| `--live-run` | `False` | Actually make changes |
| `--debug` | `False` | Verbose logging |

### Storage Options

| Argument | Default | Description |
|----------|---------|-------------|
| `--storage-backend` | `local` | Storage type: local, dynamodb, s3 |
| `--dynamodb-table` | - | DynamoDB table name |
| `--create-dynamodb-table` | `False` | Auto-create DynamoDB table |
| `--s3-state-bucket` | - | S3 bucket for state |
| `--s3-state-key` | - | S3 key for state |

### WAF Options

| Argument | Default | Description |
|----------|---------|-------------|
| `--waf-ip-set-name` | - | WAF IP Set name |
| `--waf-ip-set-scope` | `REGIONAL` | REGIONAL or CLOUDFRONT |
| `--create-waf-ip-set` | `False` | Auto-create IP Set |

### Observability Options

| Argument | Default | Description |
|----------|---------|-------------|
| `--json-logging` | `False` | JSON log format |
| `--enable-cloudwatch-metrics` | `False` | Publish metrics |
| `--cloudwatch-namespace` | `AutoBlockAttackers` | Metrics namespace |
| `--enhanced-slack` | `False` | Rich Slack notifications |

### Multi-Signal Options

| Argument | Default | Description |
|----------|---------|-------------|
| `--disable-multi-signal` | `False` | Disable multi-signal detection |
| `--min-threat-score` | `40` | Minimum score (0-100) |

### Athena Options

| Argument | Default | Description |
|----------|---------|-------------|
| `--athena` | `False` | Enable Athena queries |
| `--athena-database` | `alb_logs` | Athena database name |
| `--athena-output-location` | - | S3 path for results |

### Environment Variables

```bash
SLACK_BOT_TOKEN="xoxb-your-token"
SLACK_CHANNEL="C04ABCDEFG"
IPINFO_TOKEN="your-ipinfo-token"
STORAGE_BACKEND="dynamodb"
DYNAMODB_TABLE="block-registry"
```

See [docs/CLI_GUIDE.md](docs/CLI_GUIDE.md) for complete reference.

## Tier System

Attackers are classified into tiers based on malicious request volume:

| Tier | Hit Count | Block Duration | Priority |
|------|-----------|----------------|----------|
| **Critical** | 2000+ | 7 days | 4 |
| **High** | 1000-1999 | 3 days | 3 |
| **Medium** | 500-999 | 48 hours | 2 |
| **Low** | 100-499 | 24 hours | 1 |
| **Minimal** | <100 | 1 hour | 0 |

### Tier Upgrade

When an IP reoffends, its tier is upgraded and block duration extended:

```
T+0:  IP sends 150 requests → Blocked as "Low" (24 hours)
T+2h: Same IP returns with 600 more → Upgraded to "Medium" (48 hours from T+2h)
```

## Storage Backends

### Local File (Default)

```bash
--storage-backend local
--registry-file ./block_registry.json
```

### DynamoDB

```bash
--storage-backend dynamodb
--dynamodb-table my-block-registry
--create-dynamodb-table
```

**Benefits**: Multi-AZ, concurrent access, automatic scaling

### S3

```bash
--storage-backend s3
--s3-state-bucket my-bucket
--s3-state-key security/registry.json
```

**Benefits**: 11 9's durability, versioning, cross-region replication

## AWS WAF Integration

Block attackers at the edge in addition to VPC-level NACL blocking:

```bash
python3 auto_block_attackers.py \
  --lb-name-pattern "prod-*" \
  --waf-ip-set-name "blocked-attackers" \
  --waf-ip-set-scope REGIONAL \
  --create-waf-ip-set \
  --live-run
```

**Use Cases**:
- Block at CloudFront edge before requests reach origin
- Consistent blocking across multiple ALBs
- Complement NACL blocking for defense in depth

## Multi-Signal Detection

Reduces false positives by correlating multiple threat indicators:

| Signal | Weight | Description |
|--------|--------|-------------|
| Attack Patterns | 50% | ATTACK_PATTERNS regex matches |
| Scanner UA | 20% | Known scanner user-agents |
| Error Rate | 15% | 4xx/5xx response percentage |
| Path Diversity | 15% | Unique paths (scanner behavior) |

**Threat Score Calculation**:

```
Score = (0.5 × attack_rate) + (0.2 × scanner_rate) +
        (0.15 × error_rate) + (0.15 × diversity_score)
```

IPs with score < `--min-threat-score` are considered false positives.

## Athena Integration

For large-scale log analysis (>1000 files), use Athena:

```bash
python3 auto_block_attackers.py \
  --lb-name-pattern "prod-*" \
  --athena \
  --athena-database "security_logs" \
  --athena-output-location "s3://my-bucket/athena-results/" \
  --lookback 24h \
  --live-run
```

**Benefits**:
- SQL-based filtering at scale
- Historical analysis across days/weeks
- Cost-effective for large datasets

## Observability

### Structured Logging

```bash
python3 auto_block_attackers.py --json-logging 2>&1 | tee logs.json
```

Output:
```json
{"timestamp": "2026-01-09T10:30:00Z", "level": "INFO", "message": "Blocked 5 IPs"}
```

### CloudWatch Metrics

```bash
--enable-cloudwatch-metrics
--cloudwatch-namespace "Security/AutoBlock"
```

**Metrics Published**:
- `LogFilesProcessed`
- `MaliciousIPsDetected`
- `IPsBlocked`
- `IPsUnblocked`
- `ProcessingTimeMs`
- `AverageThreatScore`

### Enhanced Slack Notifications

```bash
--enhanced-slack
```

Features:
- Severity-based color coding (green→red)
- Incident threading
- Tier breakdown fields
- Top offenders by tier

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    AWS Auto Block Attackers                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────────┐                        ┌──────────────┐       │
│  │   S3 Logs    │───────┬───────────────▶│  CloudWatch  │       │
│  └──────────────┘       │                │   Metrics    │       │
│                         ▼                └──────────────┘       │
│  ┌──────────────┐  ┌──────────────┐                             │
│  │    Athena    │──│    Threat    │                             │
│  │   (Optional) │  │   Detection  │                             │
│  └──────────────┘  └──────┬───────┘                             │
│                          │                                       │
│                          ▼                                       │
│                   ┌──────────────┐                               │
│                   │    Tier      │                               │
│                   │Classification│                               │
│                   └──────┬───────┘                               │
│                          │                                       │
│          ┌───────────────┼───────────────┐                      │
│          ▼               ▼               ▼                      │
│   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐              │
│   │    NACL     │ │   WAF IP    │ │   Storage   │              │
│   │   Manager   │ │    Sets     │ │   Backend   │              │
│   └──────┬──────┘ └──────┬──────┘ └──────┬──────┘              │
│          │               │               │                      │
└──────────┼───────────────┼───────────────┼──────────────────────┘
           │               │               │
           ▼               ▼               ▼
    ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
    │  EC2 NACLs  │ │  AWS WAF    │ │ DynamoDB/S3 │
    │  (IPv4/v6)  │ │  IP Sets    │ │   /Local    │
    └─────────────┘ └─────────────┘ └─────────────┘
```

See [docs/TECHNICAL_DESIGN.md](docs/TECHNICAL_DESIGN.md) for detailed architecture.

## Troubleshooting

### No IPs Being Blocked

```bash
# Lower threshold and enable debug
python3 auto_block_attackers.py --threshold 10 --debug

# Verify logs exist
aws s3 ls s3://your-bucket/your-prefix/ --recursive | tail -20
```

### Multi-Signal Filtering Too Aggressive

```bash
# Lower the minimum threat score
--min-threat-score 30

# Or disable multi-signal entirely
--disable-multi-signal
```

### NACL Slots Full

```bash
# Increase limit (ensure rule range is available)
--start-rule 70 --limit 30
```

### DynamoDB Throttling

```bash
# Use on-demand capacity mode
aws dynamodb update-table \
  --table-name my-block-registry \
  --billing-mode PAY_PER_REQUEST
```

## IAM Permissions

Minimum required policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeLoadBalancerAttributes",
        "ec2:DescribeNetworkAcls",
        "ec2:CreateNetworkAclEntry",
        "ec2:DeleteNetworkAclEntry",
        "s3:GetObject",
        "s3:ListBucket",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

See [docs/TECHNICAL_DESIGN.md](docs/TECHNICAL_DESIGN.md#10-security-considerations) for full IAM policies including optional features.

## Documentation

- [CLI Reference Guide](docs/CLI_GUIDE.md) - Complete command-line reference
- [Technical Design](docs/TECHNICAL_DESIGN.md) - Architecture and implementation details
- [Contributing Guide](CONTRIBUTING.md) - How to contribute
- [Security Policy](SECURITY.md) - Security practices and reporting

## Contributing

```bash
# Clone and setup
git clone https://github.com/davidlu1001/aws-auto-block-attackers.git
cd aws-auto-block-attackers
uv sync --all-extras

# Run tests
uv run pytest tests/ -v

# Run linting
uv run black auto_block_attackers.py slack_client.py
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/davidlu1001/aws-auto-block-attackers/issues)
- **Discussions**: [GitHub Discussions](https://github.com/davidlu1001/aws-auto-block-attackers/discussions)

---

**Made with security in mind**
