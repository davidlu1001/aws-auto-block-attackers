# Technical Design Document

## AWS Auto Block Attackers v2.0

### Document Version: 2.0
### Last Updated: January 2026

---

## Table of Contents

1. [Overview](#1-overview)
2. [Architecture](#2-architecture)
3. [Core Components](#3-core-components)
4. [Storage Backends](#4-storage-backends)
5. [IPv6 Support](#5-ipv6-support)
6. [AWS WAF Integration](#6-aws-waf-integration)
7. [Multi-Signal Threat Detection](#7-multi-signal-threat-detection)
8. [Athena Integration](#8-athena-integration)
9. [Observability](#9-observability)
10. [Security Considerations](#10-security-considerations)

---

## 1. Overview

### 1.1 Purpose

AWS Auto Block Attackers is an automated security tool that analyzes Application Load Balancer (ALB) access logs to detect malicious traffic patterns and implement tiered, time-based IP blocking via AWS Network ACLs (NACLs) and optionally AWS WAF IP Sets.

### 1.2 Key Capabilities

| Capability | Description |
|------------|-------------|
| **Pattern Detection** | Regex-based detection of LFI, XSS, SQLi, command injection, path traversal |
| **Tiered Blocking** | 5-tier system (Critical→Minimal) with proportional block durations |
| **Multi-Signal Analysis** | Reduces false positives by correlating multiple threat indicators |
| **Dual-Stack Support** | Full IPv4 and IPv6 blocking capabilities |
| **Cloud-Native Storage** | DynamoDB, S3, or local file storage for state persistence |
| **AWS WAF Integration** | Parallel blocking via WAF IP Sets for edge protection |
| **Athena Integration** | SQL-based log analysis for large-scale deployments |
| **Observable** | Structured JSON logging, CloudWatch metrics, enhanced Slack notifications |

### 1.3 Design Principles

1. **Fail-Safe**: Security tool must never crash; graceful degradation on errors
2. **Idempotent**: Multiple executions with same input produce same result
3. **Observable**: Comprehensive logging and metrics for operational visibility
4. **Configurable**: Sensible defaults with extensive customization options
5. **Backward Compatible**: New features don't break existing deployments

---

## 2. Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AWS Auto Block Attackers                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                   │
│  │   S3 Logs    │    │   Athena     │    │  CloudWatch  │                   │
│  │   (Input)    │    │  (Optional)  │    │   (Metrics)  │                   │
│  └──────┬───────┘    └──────┬───────┘    └──────▲───────┘                   │
│         │                   │                   │                            │
│         ▼                   ▼                   │                            │
│  ┌────────────────────────────────────────┐    │                            │
│  │         Log Processing Engine          │    │                            │
│  │  ┌─────────────┐  ┌─────────────┐      │    │                            │
│  │  │   Direct    │  │   Athena    │      │    │                            │
│  │  │  S3 Fetch   │  │   Query     │      │    │                            │
│  │  └─────────────┘  └─────────────┘      │    │                            │
│  └────────────────┬───────────────────────┘    │                            │
│                   │                            │                            │
│                   ▼                            │                            │
│  ┌────────────────────────────────────────┐    │                            │
│  │         Threat Detection Engine        │────┘                            │
│  │  ┌─────────────┐  ┌─────────────┐      │                                 │
│  │  │   Pattern   │  │Multi-Signal │      │                                 │
│  │  │   Matching  │  │  Analysis   │      │                                 │
│  │  └─────────────┘  └─────────────┘      │                                 │
│  └────────────────┬───────────────────────┘                                 │
│                   │                                                          │
│                   ▼                                                          │
│  ┌────────────────────────────────────────┐                                 │
│  │         Blocking Decision Engine       │                                 │
│  │  ┌─────────────┐  ┌─────────────┐      │                                 │
│  │  │    Tier     │  │  Priority   │      │                                 │
│  │  │Classification│ │  Ordering   │      │                                 │
│  │  └─────────────┘  └─────────────┘      │                                 │
│  └────────────────┬───────────────────────┘                                 │
│                   │                                                          │
│         ┌─────────┴─────────┐                                               │
│         ▼                   ▼                                               │
│  ┌─────────────┐     ┌─────────────┐     ┌─────────────┐                   │
│  │    NACL     │     │   WAF IP    │     │   Storage   │                   │
│  │   Manager   │     │    Sets     │     │   Backend   │                   │
│  └──────┬──────┘     └──────┬──────┘     └──────┬──────┘                   │
│         │                   │                   │                            │
└─────────┼───────────────────┼───────────────────┼────────────────────────────┘
          │                   │                   │
          ▼                   ▼                   ▼
   ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
   │  AWS EC2    │     │  AWS WAF    │     │ DynamoDB/S3 │
   │   NACLs     │     │  IP Sets    │     │   /Local    │
   └─────────────┘     └─────────────┘     └─────────────┘
```

### 2.2 Execution Flow

```
START
  │
  ▼
┌─────────────────────────────────────┐
│ 1. Initialize                        │
│    - Load configuration              │
│    - Initialize AWS clients          │
│    - Load block registry             │
│    - Load processed files cache      │
└─────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────┐
│ 2. Discover Load Balancers          │
│    - Match LB name pattern          │
│    - Extract S3 log locations       │
│    - Find associated NACLs          │
└─────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────┐
│ 3. Process Logs                     │
│    - List S3 objects in window      │
│    - Skip already-processed files   │
│    - Parse logs (parallel/Athena)   │
│    - Extract malicious IPs          │
└─────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────┐
│ 4. Apply Filters                    │
│    - Remove whitelisted IPs         │
│    - Remove AWS IPs (v4 + v6)       │
│    - Apply threshold filter         │
│    - Multi-signal validation        │
└─────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────┐
│ 5. Update Block Registry            │
│    - Classify tiers                  │
│    - Handle tier upgrades           │
│    - Calculate expiration times     │
│    - Merge with existing blocks     │
└─────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────┐
│ 6. Apply Blocks                     │
│    - Update NACL rules (v4 + v6)    │
│    - Sync WAF IP Sets               │
│    - Respect priority ordering      │
│    - Handle slot exhaustion         │
└─────────────────────────────────────┘
  │
  ▼
┌─────────────────────────────────────┐
│ 7. Finalize                         │
│    - Save block registry            │
│    - Save processed files cache     │
│    - Emit CloudWatch metrics        │
│    - Send Slack notification        │
└─────────────────────────────────────┘
  │
  ▼
END
```

---

## 3. Core Components

### 3.1 NaclAutoBlocker Class

The main orchestrator class that coordinates all operations.

```python
class NaclAutoBlocker:
    """
    Main class for automated IP blocking based on ALB log analysis.

    Attributes:
        lb_name_pattern (str): Glob pattern to match load balancer names
        region (str): AWS region
        lookback_delta (timedelta): How far back to analyze logs
        threshold (int): Minimum hits to trigger blocking
        dry_run (bool): If True, don't make actual changes
    """
```

**Key Methods:**

| Method | Purpose |
|--------|---------|
| `run()` | Main entry point, orchestrates entire flow |
| `_download_and_parse_log()` | Fetch and parse single log file |
| `_process_logs_in_parallel()` | Parallel log processing with ThreadPoolExecutor |
| `_filter_by_multi_signal()` | Apply multi-signal threat detection |
| `_determine_tier()` | Classify IP into threat tier |
| `_sync_nacl_rules()` | Update NACL deny rules |
| `_sync_waf_ip_set()` | Update WAF IP Set |

### 3.2 Attack Pattern Detection

Comprehensive regex patterns for common attack vectors:

```python
ATTACK_PATTERNS = re.compile(
    r"(?:"
    r"(?:\.\./|\.\.\\)"           # Path traversal
    r"|/etc/passwd"               # Unix file access
    r"|/proc/self"                # Linux proc filesystem
    r"|<script[^>]*>"             # XSS script tags
    r"|javascript:"               # JavaScript protocol
    r"|UNION\s+SELECT"            # SQL injection
    r"|SELECT\s+.*\s+FROM"        # SQL queries
    r"|eval\s*\("                 # Code injection
    r"|wp-login\.php"             # WordPress targeting
    r"|/\.env"                    # Environment file exposure
    r"|/\.git"                    # Git repository exposure
    r"|phpMyAdmin"                # Admin panel scanning
    r")",
    re.IGNORECASE
)
```

### 3.3 Tier Classification System

```python
DEFAULT_TIERS = [
    # (min_hits, tier_name, block_hours, priority)
    (2000, "critical", 168, 4),  # 7 days
    (1000, "high", 72, 3),       # 3 days
    (500, "medium", 48, 2),      # 2 days
    (100, "low", 24, 1),         # 1 day
    (0, "minimal", 1, 0),        # 1 hour
]
```

**Tier Selection Algorithm:**
```python
def _determine_tier(self, hit_count: int) -> Tuple[str, int, int]:
    for min_hits, tier_name, block_hours, priority in self.tier_config:
        if hit_count >= min_hits:
            return tier_name, block_hours, priority
    return "minimal", 1, 0
```

---

## 4. Storage Backends

### 4.1 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    StorageBackend (ABC)                      │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  + get(key: str) -> Optional[Dict]                   │    │
│  │  + put(key: str, data: Dict) -> bool                │    │
│  │  + delete(key: str) -> bool                         │    │
│  │  + exists(key: str) -> bool                         │    │
│  │  + list_keys(prefix: str) -> List[str]              │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│LocalFileBack│      │DynamoDBBack │      │  S3Backend  │
│    end      │      │    end      │      │             │
└─────────────┘      └─────────────┘      └─────────────┘
```

### 4.2 Backend Comparison

| Feature | Local File | DynamoDB | S3 |
|---------|------------|----------|-----|
| **Latency** | ~1ms | ~10ms | ~50ms |
| **Durability** | Single host | Multi-AZ | 11 9's |
| **Concurrency** | Lock file | Conditional writes | Versioning |
| **Cost** | Free | Pay per request | Pay per request |
| **Use Case** | Dev/single instance | Multi-instance | Archival/large state |

### 4.3 Configuration

```bash
# Local (default)
--storage-backend local
--registry-file ./block_registry.json

# DynamoDB
--storage-backend dynamodb
--dynamodb-table auto-block-attackers-state
--create-dynamodb-table  # Auto-create table

# S3
--storage-backend s3
--s3-state-bucket my-state-bucket
--s3-state-key security/block-registry.json
```

### 4.4 DynamoDB Table Schema

```
Table: auto-block-attackers-state
├── Primary Key: pk (String) - Partition key
├── Attributes:
│   ├── data (Map) - JSON data
│   ├── updated_at (String) - ISO8601 timestamp
│   └── ttl (Number) - Unix timestamp for TTL
└── GSI: None (single key access pattern)
```

---

## 5. IPv6 Support

### 5.1 Dual-Stack Architecture

```
                    ┌─────────────────────────────────┐
                    │        Log Processing           │
                    │   ┌─────────┐   ┌─────────┐    │
                    │   │  IPv4   │   │  IPv6   │    │
                    │   │ Parsing │   │ Parsing │    │
                    │   └────┬────┘   └────┬────┘    │
                    │        │             │         │
                    │        ▼             ▼         │
                    │   ┌─────────────────────┐      │
                    │   │   IP Validation     │      │
                    │   │  (Public only)      │      │
                    │   └──────────┬──────────┘      │
                    └──────────────┼──────────────────┘
                                   │
              ┌────────────────────┴────────────────────┐
              │                                         │
              ▼                                         ▼
     ┌─────────────────┐                       ┌─────────────────┐
     │   NACL IPv4     │                       │   NACL IPv6     │
     │  Rules 80-99    │                       │  Rules 180-199  │
     │  (CidrBlock)    │                       │ (Ipv6CidrBlock) │
     └─────────────────┘                       └─────────────────┘
```

### 5.2 IPv6 Address Handling

```python
def is_valid_public_ip(ip_str: str) -> Tuple[bool, int]:
    """
    Validate if an IP address is a public (routable) address.

    Returns:
        Tuple[bool, int]: (is_valid, ip_version)
        - ip_version: 4 for IPv4, 6 for IPv6
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_global and not ip.is_private:
            return True, ip.version
        return False, ip.version
    except ValueError:
        return False, 0
```

### 5.3 NACL Rule Structure

**IPv4 Rule:**
```python
ec2.create_network_acl_entry(
    NetworkAclId=nacl_id,
    RuleNumber=85,  # 80-99 range
    Protocol="-1",
    RuleAction="deny",
    CidrBlock="1.2.3.4/32",  # IPv4 CIDR
    Egress=False,
)
```

**IPv6 Rule:**
```python
ec2.create_network_acl_entry(
    NetworkAclId=nacl_id,
    RuleNumber=185,  # 180-199 range
    Protocol="-1",
    RuleAction="deny",
    Ipv6CidrBlock="2001:db8::1/128",  # IPv6 CIDR
    Egress=False,
)
```

---

## 6. AWS WAF Integration

### 6.1 Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   WAF IP Set Manager                         │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐     │
│  │ IP Set      │    │  LockToken  │    │  Batch      │     │
│  │ Discovery   │───▶│  Management │───▶│  Updates    │     │
│  └─────────────┘    └─────────────┘    └─────────────┘     │
│                                                              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │   AWS WAFv2     │
                    │   IP Sets       │
                    │                 │
                    │  ┌───────────┐  │
                    │  │ IPv4 Set  │  │
                    │  │ /32 CIDRs │  │
                    │  └───────────┘  │
                    │  ┌───────────┐  │
                    │  │ IPv6 Set  │  │
                    │  │/128 CIDRs │  │
                    │  └───────────┘  │
                    └─────────────────┘
```

### 6.2 Optimistic Locking

WAF IP Sets use optimistic locking via `LockToken`:

```python
def _update_waf_ip_set_addresses(
    self, ip_set_id: str, addresses: Set[str], lock_token: str
) -> bool:
    """
    Update WAF IP Set with new addresses using optimistic locking.

    The LockToken prevents concurrent modifications:
    1. Get current IP Set (includes LockToken)
    2. Modify addresses
    3. Update with LockToken
    4. If LockToken mismatch, retry with new token
    """
    try:
        self.waf.update_ip_set(
            Name=self._waf_ip_set_name,
            Scope=self._waf_ip_set_scope,
            Id=ip_set_id,
            Addresses=list(addresses),
            LockToken=lock_token,
        )
        return True
    except self.waf.exceptions.WAFOptimisticLockException:
        # Retry with fresh LockToken
        return self._retry_waf_update(ip_set_id, addresses)
```

### 6.3 Configuration

```bash
# Enable WAF IP Set synchronization
--waf-ip-set-name "blocked-attackers"
--waf-ip-set-scope "REGIONAL"  # or "CLOUDFRONT"
--waf-ip-set-id "abc123-..."   # Optional, will find by name
--create-waf-ip-set            # Create if doesn't exist
```

---

## 7. Multi-Signal Threat Detection

### 7.1 Purpose

Reduce false positives by correlating multiple threat indicators beyond simple pattern matching.

### 7.2 Threat Signals

```python
class ThreatSignals:
    """Aggregates multiple threat indicators for an IP."""

    attack_pattern_hits: int  # ATTACK_PATTERNS matches
    scanner_ua_hits: int      # Known scanner user agents
    error_responses: int      # 4xx/5xx responses
    total_requests: int       # Total request count
    unique_paths: Set[str]    # Path diversity
```

### 7.3 Scoring Algorithm

```python
def calculate_threat_score(self, config: Dict) -> Tuple[float, Dict[str, float]]:
    """
    Calculate weighted threat score.

    Score = (attack_weight * attack_rate) +
            (scanner_weight * scanner_rate) +
            (error_weight * error_rate) +
            (diversity_weight * path_diversity_score)
    """
    weights = config["signal_weights"]

    # Attack pattern rate (0-100)
    attack_rate = min(100, (self.attack_pattern_hits / max(1, self.total_requests)) * 100)

    # Scanner user agent rate (0-100)
    scanner_rate = min(100, (self.scanner_ua_hits / max(1, self.total_requests)) * 100)

    # Error rate (0-100)
    error_rate = min(100, (self.error_responses / max(1, self.total_requests)) * 100)

    # Path diversity (many unique paths = scanner behavior)
    diversity = min(100, len(self.unique_paths) * 2)

    score = (
        weights["attack_pattern"] * attack_rate +
        weights["scanner_ua"] * scanner_rate +
        weights["error_rate"] * error_rate +
        weights["path_diversity"] * diversity
    )

    return score, breakdown
```

### 7.4 Default Configuration

```python
DEFAULT_THREAT_SIGNALS_CONFIG = {
    "min_threat_score": 40,  # Minimum score to confirm as malicious
    "signal_weights": {
        "attack_pattern": 0.5,   # 50% weight
        "scanner_ua": 0.2,       # 20% weight
        "error_rate": 0.15,      # 15% weight
        "path_diversity": 0.15,  # 15% weight
    },
}
```

---

## 8. Athena Integration

### 8.1 When to Use Athena

| Scenario | Recommended Approach |
|----------|---------------------|
| < 100 log files | Direct S3 fetch |
| 100-1000 log files | Direct S3 fetch (parallel) |
| > 1000 log files | Athena query |
| Historical analysis | Athena query |
| Real-time blocking | Direct S3 fetch |

### 8.2 Table Schema

```sql
CREATE EXTERNAL TABLE alb_logs (
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
    -- ... additional fields
)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.RegexSerDe'
LOCATION 's3://your-bucket/alb-logs/'
```

### 8.3 Query Strategy

```sql
SELECT
    client_ip,
    COUNT(*) as hit_count
FROM alb_logs
WHERE
    time >= '2026-01-08T00:00:00'
    AND (
        request_url LIKE '%../%'
        OR request_url LIKE '%.env%'
        OR request_url LIKE '%<script%'
        -- Additional patterns
    )
GROUP BY client_ip
HAVING COUNT(*) >= 50
ORDER BY hit_count DESC
LIMIT 10000
```

### 8.4 Configuration

```bash
--athena                           # Enable Athena mode
--athena-database "security_logs"  # Athena database
--athena-output-location "s3://my-bucket/athena-results/"
```

---

## 9. Observability

### 9.1 Structured Logging

```python
class JsonFormatter(logging.Formatter):
    """JSON log formatter for CloudWatch Logs ingestion."""

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

        return json.dumps(log_dict)
```

**Enable with:** `--json-logging`

### 9.2 CloudWatch Metrics

```python
class CloudWatchMetrics:
    """Buffered CloudWatch metrics publisher."""

    def put_metric(self, name: str, value: float, unit: str, dimensions: Dict):
        self._buffer.append({
            "MetricName": name,
            "Value": value,
            "Unit": unit,
            "Dimensions": [
                {"Name": k, "Value": v} for k, v in dimensions.items()
            ],
        })

    def flush(self):
        """Batch publish metrics (max 20 per API call)."""
        for chunk in chunks(self._buffer, 20):
            self.cloudwatch.put_metric_data(
                Namespace=self.namespace,
                MetricData=chunk,
            )
```

**Metrics Emitted:**

| Metric | Unit | Description |
|--------|------|-------------|
| `LogFilesProcessed` | Count | Number of log files analyzed |
| `MaliciousIPsDetected` | Count | IPs matching attack patterns |
| `IPsBlocked` | Count | IPs added to block list |
| `IPsUnblocked` | Count | Expired blocks removed |
| `ProcessingTimeMs` | Milliseconds | Total execution time |
| `S3ProcessingErrors` | Count | S3 fetch failures |
| `AverageThreatScore` | None | Mean threat score of candidates |

### 9.3 Enhanced Slack Notifications

```python
class SlackSeverity(Enum):
    INFO = "#36a64f"      # Green
    WARNING = "#f2c744"   # Yellow
    LOW = "#ff9933"       # Orange
    MEDIUM = "#e07000"    # Dark orange
    HIGH = "#cc0000"      # Red
    CRITICAL = "#8b0000"  # Dark red
```

**Features:**
- Severity-based color coding
- Incident threading (related messages grouped)
- Block Kit formatting with fields
- Action buttons (informational)

---

## 10. Security Considerations

### 10.1 IAM Permissions (Minimum Required)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ELBAccess",
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeLoadBalancerAttributes"
      ],
      "Resource": "*"
    },
    {
      "Sid": "EC2NACLAccess",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeNetworkAcls",
        "ec2:CreateNetworkAclEntry",
        "ec2:DeleteNetworkAclEntry",
        "ec2:ReplaceNetworkAclEntry"
      ],
      "Resource": "*"
    },
    {
      "Sid": "S3LogAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::your-log-bucket",
        "arn:aws:s3:::your-log-bucket/*"
      ]
    },
    {
      "Sid": "STSIdentity",
      "Effect": "Allow",
      "Action": "sts:GetCallerIdentity",
      "Resource": "*"
    }
  ]
}
```

### 10.2 Additional Permissions (Optional Features)

```json
{
  "Sid": "WAFAccess",
  "Effect": "Allow",
  "Action": [
    "wafv2:GetIPSet",
    "wafv2:UpdateIPSet",
    "wafv2:CreateIPSet",
    "wafv2:ListIPSets"
  ],
  "Resource": "*"
},
{
  "Sid": "DynamoDBAccess",
  "Effect": "Allow",
  "Action": [
    "dynamodb:GetItem",
    "dynamodb:PutItem",
    "dynamodb:DeleteItem",
    "dynamodb:CreateTable",
    "dynamodb:DescribeTable"
  ],
  "Resource": "arn:aws:dynamodb:*:*:table/auto-block-*"
},
{
  "Sid": "CloudWatchMetrics",
  "Effect": "Allow",
  "Action": "cloudwatch:PutMetricData",
  "Resource": "*"
},
{
  "Sid": "AthenaAccess",
  "Effect": "Allow",
  "Action": [
    "athena:StartQueryExecution",
    "athena:GetQueryExecution",
    "athena:GetQueryResults"
  ],
  "Resource": "*"
}
```

### 10.3 Security Best Practices

1. **Use IAM Roles**: Avoid access keys; use EC2 instance profiles or ECS task roles
2. **Least Privilege**: Only grant permissions actually needed
3. **Encrypt State**: Use S3 server-side encryption or DynamoDB encryption
4. **Audit Trail**: Enable CloudTrail for NACL/WAF modifications
5. **Separate Environments**: Use different AWS accounts for dev/staging/prod
6. **Token Rotation**: Rotate Slack tokens and IPInfo tokens regularly
7. **Whitelist Review**: Regularly audit whitelist entries

---

## Appendix A: Configuration Reference

See [CLI_GUIDE.md](CLI_GUIDE.md) for complete command-line reference.

## Appendix B: Troubleshooting

See main [README.md](../README.md#troubleshooting) for common issues.

## Appendix C: Migration Guide

### From v1.x to v2.0

1. **Storage Backend**: Default remains `local`; no migration needed
2. **IPv6**: Enabled by default; use `--disable-ipv6` to disable
3. **Multi-Signal**: Enabled by default; use `--disable-multi-signal` to disable
4. **Registry Format**: Backward compatible; old registries load automatically
