# AWS Auto Block Attackers

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

Automated AWS Network ACL (NACL) management tool that analyzes Application Load Balancer (ALB) access logs, detects malicious traffic patterns, and implements tiered time-based IP blocking with persistent storage.

## 🚀 Features

- **Tiered Blocking System**: Automatically categorizes attackers into 5 tiers (Critical, High, Medium, Low, Minimal) based on attack volume
- **Time-Based Persistence**: Blocks persist for hours to days depending on severity, with expiration tracking via JSON registry
- **Priority-Based Slot Management**: Critical attackers won't be displaced by lower-priority threats when NACL slots are full
- **Attack Pattern Detection**: Comprehensive regex patterns detect LFI, XSS, SQL injection, command injection, and more
- **Smart API Caching**: Built-in IPInfo API caching reduces rate limit concerns
- **Slack Integration**: Real-time notifications with detailed attack context and tier information
- **AWS IP Exclusion**: Automatically excludes AWS service IPs from blocking
- **Dry-Run Mode**: Test blocking logic without making actual changes
- **Self-Healing**: Handles corrupted registry files, missing configurations, and API failures gracefully

## 📋 Table of Contents

- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Configuration](#-configuration)
- [Usage](#-usage)
- [Tier System](#-tier-system)
- [Architecture](#-architecture)
- [Monitoring](#-monitoring)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)
- [Security](#-security)

## 📦 Prerequisites

### Required

- **Python**: 3.8 or higher
- **AWS Account**: With ALB access logs enabled
- **IAM Permissions**: See [IAM Policy](#iam-permissions) below
- **ALB Logging**: Must be enabled and configured to S3

### Optional

- **Slack Bot Token**: For notifications (recommended)
- **IPInfo API Token**: For IP geolocation (optional)

## 🔧 Installation

### Option 1: Using uv (Recommended)

[uv](https://github.com/astral-sh/uv) is a fast Python package installer and resolver.

```bash
# Install uv (if not already installed)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/davidlu1001/aws-auto-block-attackers.git
cd aws-auto-block-attackers

# Install dependencies with uv
uv sync

# Copy example configuration files
cp examples/whitelist.example.txt whitelist.txt
cp examples/.env.example .env

# Edit configuration files with your settings
vim .env
vim whitelist.txt
```

### Option 2: Using pip

```bash
# Clone the repository
git clone https://github.com/davidlu1001/aws-auto-block-attackers.git
cd aws-auto-block-attackers

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -e .

# Copy example configuration
cp examples/whitelist.example.txt whitelist.txt
cp examples/.env.example .env
```

### Option 3: Using Docker

```bash
docker pull davidlu1001/aws-auto-block-attackers:latest
docker run -v $(pwd)/config.yaml:/app/config.yaml aws-auto-block-attackers
```

### Option 4: Manual Installation

```bash
# Install dependencies
pip install boto3 ipinfo slack-sdk requests

# Download the scripts
wget https://raw.githubusercontent.com/davidlu1001/aws-auto-block-attackers/main/auto_block_attackers.py
wget https://raw.githubusercontent.com/davidlu1001/aws-auto-block-attackers/main/slack_client.py

# Make them executable
chmod +x auto_block_attackers.py
```

## 🚀 Quick Start

### 1. Configure AWS Credentials

```bash
# Option A: AWS CLI
aws configure

# Option B: Environment variables
export AWS_ACCESS_KEY_ID="your-access-key"
export AWS_SECRET_ACCESS_KEY="your-secret-key"
export AWS_DEFAULT_REGION="ap-southeast-2"

# Option C: IAM Role (recommended for EC2)
# Attach IAM role to EC2 instance
```

### 2. Enable ALB Access Logs

```bash
# Via AWS CLI
aws elbv2 modify-load-balancer-attributes \
  --load-balancer-arn arn:aws:elasticloadbalancing:region:account-id:loadbalancer/app/my-alb/... \
  --attributes Key=access_logs.s3.enabled,Value=true Key=access_logs.s3.bucket,Value=my-bucket
```

### 3. Run Your First Scan (Dry-Run)

```bash
# Using uv (recommended)
uv run python3 auto_block_attackers.py \
  --lb-name-pattern "alb-*" \
  --region ap-southeast-2 \
  --lookback 1h \
  --threshold 50 \
  --debug

# Or directly with python (if using pip install)
python3 auto_block_attackers.py \
  --lb-name-pattern "alb-*" \
  --region ap-southeast-2 \
  --lookback 1h \
  --threshold 50 \
  --debug
```

### 4. Deploy to Production

```bash
# Add to crontab for automated execution every 15 minutes
crontab -e

# Using uv (recommended):
*/15 * * * * cd /opt/aws-auto-block-attackers && /usr/local/bin/uv run python3 auto_block_attackers.py \
  --lb-name-pattern "alb-prod-*" \
  --threshold 75 \
  --lookback 90m \
  --live-run \
  >> /var/log/auto-block-attackers.log 2>&1

# Or using systemd timer (see examples/systemd-timer-example.timer)
```

## ⚙️ Configuration

### Environment Variables

```bash
# Slack (optional but recommended)
export SLACK_BOT_TOKEN="xoxb-your-token"
export SLACK_CHANNEL="C04ABCDEFG"

# IPInfo (optional)
export IPINFO_TOKEN="your-ipinfo-token"

# AWS (if not using IAM role)
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AWS_DEFAULT_REGION="ap-southeast-2"
```

### Command-Line Arguments

| Argument               | Default               | Description                                     |
| ---------------------- | --------------------- | ----------------------------------------------- |
| `--lb-name-pattern`    | `alb-*`               | Pattern to match load balancer names            |
| `--region`             | `ap-southeast-2`      | AWS region                                      |
| `--lookback`           | `60m`                 | Lookback period (format: 30m, 2h, 1d)           |
| `--threshold`          | `50`                  | Minimum malicious requests to trigger block     |
| `--start-rule`         | `80`                  | Starting NACL rule number                       |
| `--limit`              | `20`                  | Maximum number of DENY rules to manage          |
| `--whitelist-file`     | `whitelist.txt`       | Path to whitelist file                          |
| `--aws-ip-ranges-file` | `ip-ranges.json`      | Path to AWS IP ranges JSON                      |
| `--registry-file`      | `block_registry.json` | Path to block registry                          |
| `--live-run`           | `False`               | Actually create NACL rules (default is dry-run) |
| `--debug`              | `False`               | Enable verbose debug logging                    |

### Whitelist File Format

```text
# Comments start with #
203.0.113.1
203.0.113.2
# Corporate office
198.51.100.0/24
```

## 🎯 Tier System

The script automatically categorizes attackers into tiers based on request volume:

| Tier         | Hit Count | Block Duration | Priority | Description               |
| ------------ | --------- | -------------- | -------- | ------------------------- |
| **Critical** | 2000+     | 7 days         | 4        | Major coordinated attacks |
| **High**     | 1000-1999 | 3 days         | 3        | Severe automated scanning |
| **Medium**   | 500-999   | 48 hours       | 2        | Moderate attack attempts  |
| **Low**      | 100-499   | 24 hours       | 1        | Light scanning activity   |
| **Minimal**  | <100      | 1 hour         | 0        | Minor probes              |

### Example Scenarios

#### Scenario 1: High-Volume Attacker
```
IP: 1.2.3.4 sends 1,568 malicious requests
→ Classified as "High" tier
→ Blocked for 3 days
→ Entry saved to registry with expiration
→ Slack notification: "Blocked 1.2.3.4 (1568 hits, tier: HIGH, blocked for 3d)"
```

#### Scenario 2: Tier Upgrade
```
T+0:  IP sends 150 requests → Blocked as "Low" (24 hours)
T+2h: Same IP returns with 600 more → Upgraded to "Medium" (48 hours)
      → Block duration extended from T+2h
```

#### Scenario 3: Priority Protection
```
NACL Full: 20 IPs blocked (5 High, 10 Medium, 5 Low)
New Critical attacker (2500 hits) arrives
→ Replaces lowest priority IP (one of the "Low" tier)
→ High/Medium tier IPs remain protected
```

## 🏗️ Architecture

### System Flow

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Scan ALB Logs (S3)                                        │
│    └─> Date-based filtering (fast!)                          │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 2. Detect Malicious Patterns                                 │
│    └─> Regex: LFI, XSS, SQLi, Command Injection, etc.       │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 3. Apply Filters                                             │
│    ├─> Whitelist check                                       │
│    ├─> AWS IP exclusion                                      │
│    └─> Threshold validation                                  │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 4. Tier Classification                                       │
│    └─> Determine block duration based on hit count          │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 5. Registry Management                                       │
│    ├─> Load existing blocks                                  │
│    ├─> Check expirations                                     │
│    ├─> Update/merge new blocks                               │
│    └─> Save to JSON                                          │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 6. NACL Updates                                              │
│    ├─> Remove expired blocks                                 │
│    ├─> Add new blocks (priority-based)                       │
│    └─> Handle slot exhaustion                                │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│ 7. Notifications                                             │
│    └─> Slack summary with tier breakdown                    │
└─────────────────────────────────────────────────────────────┘
```

### File Structure

```
aws-auto-block-attackers/
├── .github/
│   └── workflows/
│       └── ci.yml                      # CI/CD pipeline with uv
├── examples/
│   ├── .env.example                    # Environment variables template
│   ├── config.example.yaml             # Full configuration reference
│   ├── cron-example.txt                # Cron job examples
│   ├── systemd-example.service         # Systemd service file
│   ├── systemd-timer-example.timer     # Systemd timer
│   └── whitelist.example.txt           # IP whitelist template
├── scripts/
│   ├── README.md                       # Scripts documentation
│   └── update_aws_ip_ranges.sh         # AWS IP ranges updater
├── tests/
│   ├── test_auto_block_attackers.py    # Main script tests
│   ├── test_integration.py             # Integration tests
│   ├── test_ipinfo_integration.py      # IPInfo tests
│   ├── test_notification_logic.py      # Notification tests
│   ├── test_slack_client.py            # Slack client tests
│   ├── test_tiered_blocking.py         # Tiered blocking tests
│   └── test_timestamp_fix.py           # Timestamp tests
├── .gitignore                          # Git ignore patterns
├── auto_block_attackers.py             # Main script
├── CONTRIBUTING.md                     # Contribution guidelines
├── LICENSE                             # MIT License
├── pyproject.toml                      # Project configuration (uv)
├── README.md                           # This file
├── SECURITY.md                         # Security policy
├── slack_client.py                     # Slack integration module
└── uv.lock                             # Dependency lock file
```

## 📊 Monitoring

### Log Files

```bash
# View real-time logs
tail -f /var/log/auto-block-attackers.log

# Check for errors
grep -i error /var/log/auto-block-attackers.log

# View blocked IPs
grep "ACTIVE BLOCK" /var/log/auto-block-attackers.log
```

### Registry File

```bash
# View current blocks
cat ./block_registry.json | jq '.'

# Check when an IP will be unblocked
cat block_registry.json | jq '.["1.2.3.4"]'

# Count active blocks by tier
cat block_registry.json | jq '[.[] | .tier] | group_by(.) | map({tier: .[0], count: length})'
```

### CloudWatch Metrics (Optional)

```bash
# Send custom metrics
aws cloudwatch put-metric-data \
  --namespace "Security/AutoBlock" \
  --metric-name "IPsBlocked" \
  --value 5 \
  --dimensions Tier=High
```

## 🔍 Troubleshooting

### Common Issues

#### 1. No IPs Being Blocked

**Symptoms**: Script runs but no blocks created

**Possible Causes**:
- Threshold too high
- All IPs whitelisted
- ALB logs not recent
- Attack patterns not matched

**Solutions**:
```bash
# Lower threshold temporarily
--threshold 10

# Check what's being detected
--debug

# Verify ALB logs exist
aws s3 ls s3://your-bucket/your-prefix/ --recursive | tail -20
```

#### 2. Registry File Growing Large

**Symptoms**: block_registry.json is several MB

**Solution**: Script auto-cleans entries >30 days old. If still large:
```bash
# Backup and reset
cp block_registry.json block_registry.json.bak
echo "{}" > block_registry.json
```

#### 3. IPInfo Rate Limit

**Symptoms**: Warnings about IPInfo API failures

**Solution**: Script has built-in caching. For high volume:
- Upgrade IPInfo plan
- Disable IPInfo: Don't set `IPINFO_TOKEN`

#### 4. NACL Slots Full

**Symptoms**: "Cannot add IP: all existing rules have higher priority"

**Solutions**:
- Increase `--limit` (max 20 with default start-rule 80)
- Manually remove low-priority blocks
- Adjust tier thresholds

### Debug Mode

```bash
# Enable detailed logging
uv run python3 auto_block_attackers.py --debug

# Check what patterns are matching
uv run python3 auto_block_attackers.py --debug 2>&1 | grep "malicious"
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

### Quick Contribution Guide

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/aws-auto-block-attackers.git
cd aws-auto-block-attackers

# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Install all dependencies including dev extras
uv sync --all-extras

# Run tests
uv run pytest tests/ -v

# Run linting
uv run black auto_block_attackers.py slack_client.py
uv run pylint auto_block_attackers.py slack_client.py

# Run type checking
uv run mypy auto_block_attackers.py slack_client.py
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🔒 Security

### IAM Permissions

Minimum required IAM policy:

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

### Security Best Practices

- ✅ Use IAM roles instead of access keys when possible
- ✅ Enable CloudTrail logging for audit trails
- ✅ Regularly review blocked IPs and patterns
- ✅ Keep whitelist updated with legitimate IPs
- ✅ Use separate AWS accounts for dev/prod
- ✅ Rotate Slack tokens regularly
- ✅ Monitor script execution logs

### Reporting Security Issues

Please report security vulnerabilities to: security@yourorg.com

**Do not** open public issues for security vulnerabilities.

## 📚 Additional Resources

- [AWS Network ACL Documentation](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
- [ALB Access Logs](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html)
- [IPInfo API Documentation](https://ipinfo.io/developers)

## 💬 Support

- **Issues**: [GitHub Issues](https://github.com/davidlu1001/aws-auto-block-attackers/issues)
- **Discussions**: [GitHub Discussions](https://github.com/davidlu1001/aws-auto-block-attackers/discussions)
- **Email**: support@yourorg.com

## 🌟 Star History

[![Star History Chart](https://api.star-history.com/svg?repos=davidlu1001/aws-auto-block-attackers&type=Date)](https://star-history.com/#davidlu1001/aws-auto-block-attackers&Date)

---

**Made with ❤️ for the security community**
