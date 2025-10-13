# Security Policy

## Supported Versions

We release security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

We take security seriously. If you discover a security vulnerability, please follow these steps:

### 1. Contact Us Privately

Send details to: **security@yourorg.com** (or create a private security advisory on GitHub)

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### 2. What to Expect

- **Initial Response**: Within 48 hours
- **Status Update**: Within 7 days
- **Fix Timeline**: Depends on severity
  - **Critical**: 24-72 hours
  - **High**: 1-2 weeks
  - **Medium**: 2-4 weeks
  - **Low**: Next release cycle

### 3. Disclosure Policy

- We follow **coordinated disclosure**
- We'll work with you to understand and fix the issue
- We'll credit you in the security advisory (unless you prefer anonymity)
- Please allow us reasonable time to fix before public disclosure

## Security Best Practices

### For Users

#### 1. AWS Credentials
-  **Use IAM roles** on EC2 instances (recommended)
-  Follow **principle of least privilege**
-  Never commit AWS credentials to version control
-  Rotate access keys regularly (every 90 days)
-  Use AWS Secrets Manager or Parameter Store for production

#### 2. Slack Tokens
-  Use bot tokens (not user tokens)
-  Restrict bot permissions to chat:write only
-  Store tokens in environment variables or secrets management
-  Rotate tokens if compromised

#### 3. File Permissions
```bash
# Set restrictive permissions on sensitive files
chmod 600 .env
chmod 600 config.yaml
chmod 600 whitelist.txt
chown root:root .env config.yaml whitelist.txt
```

#### 4. Network Security
-  Run on private subnets when possible
-  Use VPC endpoints for AWS API calls
-  Implement egress filtering
-  Monitor outbound connections

#### 5. NACL Management
-  Test in dry-run mode first
-  Maintain a separate whitelist
-  Monitor blocked IPs regularly
-  Have rollback procedures ready
-  Use manual rules for critical overrides (rules 1-79)

#### 6. Log Security
-  Protect log files from unauthorized access
-  Implement log rotation
-  Redact sensitive data from logs
-  Monitor logs for suspicious activity

### For Contributors

#### 1. Code Review
- All changes require review before merging
- Security-sensitive changes require two reviewers
- Use automated security scanning (Dependabot, Snyk)

#### 2. Dependencies
- Keep dependencies up to date
- Review dependency changes in pull requests
- Use tools like `safety` to check for vulnerabilities

#### 3. Testing
- Write tests for security-critical functions
- Test with invalid/malicious inputs
- Use mocking for AWS API calls in tests

#### 4. Secrets Management
- Never commit secrets, even in examples
- Use placeholders in example files
- Scan commits for accidental secret exposure

## Known Security Considerations

### 1. NACL Rule Limits
- AWS NACLs have a limit of 20 rules per NACL (inbound/outbound)
- This script manages a subset (default: 20 rules from 80-99)
- Consider deploying multiple NACLs or using AWS WAF for larger deployments

### 2. S3 Access Logs
- ALB access logs may contain sensitive information
- Ensure S3 buckets have appropriate access controls
- Consider encrypting logs at rest

### 3. Block Registry
- Block registry file contains IP addresses and metadata
- Protect this file with appropriate permissions
- Consider encrypting if storing PII

### 4. False Positives
- Attack pattern detection may produce false positives
- Maintain a whitelist for legitimate traffic
- Monitor blocked IPs and adjust thresholds

### 5. Slack Notifications
- Notifications may contain IP addresses and attack details
- Ensure Slack workspace has appropriate security controls
- Consider data retention policies

## Security Features

### Built-in Protections

1. **Input Validation**
   - Validates IP addresses before blocking
   - Filters out private/reserved IPs
   - Checks whitelist before blocking

2. **AWS IP Exclusion**
   - Automatically excludes AWS service IPs
   - Prevents blocking AWS health checks

3. **Dry-Run Mode**
   - Test without making changes
   - Verify behavior before production deployment

4. **Graceful Error Handling**
   - Handles corrupted registry files
   - Recovers from API failures
   - Logs errors without exposing secrets

5. **Tiered Blocking**
   - Prioritizes high-severity threats
   - Prevents displacement of critical blocks
   - Time-based expiration

## Audit Trail

### What Gets Logged

- All block/unblock actions
- IP addresses and hit counts
- NACL rule modifications
- API errors and warnings
- Configuration changes

### Log Locations

- Application logs: `/var/log/auto-block-attackers.log`
- Systemd journal: `journalctl -u aws-auto-block-attackers`
- CloudTrail: AWS API calls (if enabled)

## Compliance

### Data Protection

- **IP Addresses**: May be considered PII in some jurisdictions
- **Retention**: Configure based on your compliance requirements
- **GDPR**: Implement data retention and deletion policies

### Recommended Controls

- Document your blocking policy
- Implement a process for unblocking requests
- Maintain audit logs for compliance
- Regular security reviews

## Incident Response

### If Your System is Compromised

1. **Immediate Actions**
   - Revoke compromised AWS credentials
   - Rotate Slack tokens
   - Review NACL rules for unauthorized changes
   - Check block registry for tampering

2. **Investigation**
   - Review CloudTrail logs
   - Check system logs for unauthorized access
   - Identify scope of compromise

3. **Recovery**
   - Deploy new credentials
   - Restore from known-good backups
   - Update security controls

4. **Post-Incident**
   - Document lessons learned
   - Update security procedures
   - Notify affected parties if required

## Security Checklist

Before deploying to production:

- [ ] Run in dry-run mode and verify behavior
- [ ] Configure whitelist with trusted IPs
- [ ] Set up Slack notifications for monitoring
- [ ] Implement log rotation and retention
- [ ] Use IAM roles (not access keys)
- [ ] Set restrictive file permissions
- [ ] Enable CloudTrail for audit logging
- [ ] Document rollback procedures
- [ ] Test emergency unblock process
- [ ] Schedule regular security reviews

## Resources

- [AWS VPC Security Best Practices](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-best-practices.html)
- [AWS Network ACL Documentation](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

## Contact

For security questions or concerns:
- Email: security@yourorg.com
- GitHub Security Advisories: [Create Advisory](https://github.com/davidlu1001/aws-auto-block-attackers/security/advisories/new)

---

**Last Updated**: 2025-01-XX
