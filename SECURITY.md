# Security Policy

## Overview

VulnGuard is an open-source Linux security compliance agent designed to help organizations identify and address security vulnerabilities. This document outlines our security practices, vulnerability reporting process, and responsible disclosure policy.

**Important**: VulnGuard is provided "AS IS" without warranty of any kind. See the [LICENSE](LICENSE) file for complete terms.

---

## Supported Versions

| Version | Status | Support Until |
|----------|---------|---------------|
| v0.1.0 | Current | Until v0.2.0 release or 6 months from release date |

**Note**: Only the latest version receives security updates. Users are strongly encouraged to upgrade to the most recent version.

---

## Vulnerability Reporting

### How to Report a Vulnerability

If you discover a security vulnerability in VulnGuard, please report it responsibly before disclosing it publicly.

**Primary Contact Method**:
- Email: security@nixsoft.com
- PGP Key: [Available on request]
- Subject Line: `SECURITY: VulnGuard Vulnerability Report`

**What to Include**:
1. **Description**: Clear description of the vulnerability
2. **Impact**: Potential security impact and severity
3. **Reproduction Steps**: Detailed steps to reproduce the issue
4. **Affected Versions**: Which versions are affected
5. **Proof of Concept**: If applicable, a safe demonstration
6. **Suggested Fix**: If you have a proposed solution

**Format**: Please use plain text or Markdown. Avoid including executable files or malicious code.

### What NOT to Report Publicly

**Do NOT**:
- Post vulnerability details on public issues, forums, or social media
- Create pull requests for security fixes without prior coordination
- Disclose vulnerabilities before receiving confirmation from the security team
- Exploit vulnerabilities in production environments
- Share proof-of-concept exploits publicly

**Why**: Responsible disclosure allows us to:
- Validate and understand the vulnerability
- Develop and test a comprehensive fix
- Coordinate release with downstream users
- Prevent exploitation before a patch is available

---

## Responsible Disclosure Policy

### Disclosure Timeline

We follow a coordinated disclosure process with the following timeline:

| Phase | Duration | Description |
|---------|-------------|-------------|
| Initial Response | Within 72 hours | Acknowledgment of report receipt |
| Initial Assessment | Within 7 business days | Initial triage and severity assessment |
| Detailed Assessment | Within 14 business days | Complete investigation and impact analysis |
| Fix Development | Within 30 business days | Development and testing of security fix |
| Release Coordination | Within 45 business days | Coordinated public disclosure and patch release |

**Total Timeline**: Approximately 6-8 weeks from report to public disclosure

### Severity Levels

We use the following severity classification:

| Severity | Definition | Response SLA |
|-----------|--------------|---------------|
| Critical | Exploitable without authentication, leads to complete system compromise | 72 hours |
| High | Exploitable with authentication, leads to significant data exposure | 7 business days |
| Medium | Limited exploitation, requires specific conditions | 14 business days |
| Low | Minor security impact, difficult to exploit | 30 business days |

### Disclosure Process

1. **Report Submission**: Security team receives vulnerability report
2. **Initial Triage**: Team confirms receipt and validates report
3. **Investigation**: Team investigates and assesses impact
4. **Fix Development**: Team develops and tests security patch
5. **Coordination**: Team works with reporter to validate fix
6. **Release**: Team publishes security advisory and patch
7. **Public Disclosure**: Team publishes CVE details after patch release

---

## AI-Assisted Security Tooling Disclaimer

**Important**: VulnGuard uses AI assistance for security analysis and remediation recommendations.

### AI Limitations

- **No Autonomous Execution**: AI never executes commands directly on target systems
- **Validation Required**: All AI recommendations must be reviewed before implementation
- **Deterministic First**: AI is only used when deterministic logic is insufficient
- **Safety Controls**: All AI output is validated against allow-lists and confidence thresholds
- **Audit Trail**: All AI interactions are logged for accountability

### Security Considerations for AI Features

- **Prompt Injection**: We implement strict input validation and sanitization
- **Model Poisoning**: We use fixed, vetted model configurations
- **Output Validation**: All AI outputs are validated against security policies
- **Confidence Thresholds**: Low-confidence recommendations require manual review
- **Command Allow-Lists**: Only approved commands can be suggested by AI

**Users are responsible for**:
- Reviewing all AI-generated recommendations
- Validating compliance results before production deployment
- Understanding the security implications of any remediation
- Maintaining proper backups before applying changes

---

## Security Best Practices for Users

### Deployment

- **Test Environment**: Always test in non-production environments first
- **Backup**: Maintain complete system backups before remediation
- **Review**: Carefully review all remediation commands before execution
- **Audit Logs**: Regularly review audit logs for suspicious activity
- **Access Control**: Restrict access to VulnGuard to authorized personnel

### Configuration

- **Dry-Run Mode**: Use dry-run mode to preview changes before applying
- **Command Validation**: Configure strict command allow-lists for your environment
- **Approval Gates**: Enable approval requirements for high-risk changes
- **Confidence Thresholds**: Set appropriate confidence thresholds for your risk tolerance

### Operational

- **Regular Updates**: Keep VulnGuard updated to the latest version
- **Benchmark Updates**: Regularly update CIS and STIG benchmark definitions
- **Monitoring**: Monitor system behavior after remediation
- **Rollback Plans**: Maintain rollback procedures for all applied changes

---

## Third-Party Dependencies

VulnGuard depends on the following third-party packages for security:

| Package | Purpose | Security Considerations |
|----------|---------|-------------------------|
| Python standard library | Core functionality | Follow Python security advisories |
| YAML parsers | Configuration parsing | Validate input to prevent injection |
| HTTP clients (httpx) | LLM API communication | Use HTTPS, validate certificates |
| Click | CLI interface | Sanitize user inputs |

**Maintenance**:
- Dependencies are regularly updated for security patches
- Vulnerability scanning is performed on dependencies
- Transitive dependencies are reviewed for security risks

---

## Incident Response

### Security Incident Categories

1. **Vulnerability in VulnGuard Code**
   - Report via: security@nixsoft.com
   - Follow: Vulnerability Reporting Process

2. **Vulnerability in AI/LLM Integration**
   - Report via: security@nixsoft.com
   - Include: Prompt used, model version, unexpected behavior

3. **Security Misconfiguration**
   - Report via: GitHub Issues (non-sensitive)
   - Include: Configuration details, expected behavior, actual behavior

4. **Compliance Failure**
   - Report via: GitHub Issues (non-sensitive)
   - Include: Rule ID, expected result, actual result

### Incident Response Team

The security team at Nixsoft Technologies Pvt. Ltd. is responsible for:
- Receiving and triaging security reports
- Coordinating vulnerability disclosure
- Developing and testing security patches
- Publishing security advisories
- Maintaining this security policy

---

## Legal Disclaimer

**This security policy is for informational purposes only and does not constitute legal advice.**

Users should:
- Consult with their legal and security teams
- Ensure compliance with applicable laws and regulations
- Understand their organization's security requirements
- Validate all security recommendations before implementation

Nixsoft Technologies Pvt. Ltd. accepts no liability for:
- Security incidents resulting from misuse of VulnGuard
- Compliance failures due to misconfiguration
- Damages from incorrect remediation actions
- Any other consequences of using this software

---

## Contact Information

### Security Team

- **Email**: security@nixsoft.com
- **PGP Key**: Available on request
- **Response Time**: Within 72 hours for initial acknowledgment

### General Inquiries

- **Repository**: https://github.com/praveenkore/nixsoftai
- **Issues**: https://github.com/praveenkore/nixsoftai/issues
- **Discussions**: https://github.com/praveenkore/nixsoftai/discussions

### License

VulnGuard is licensed under the GNU General Public License v3 (GPL-3.0). See the [LICENSE](LICENSE) file for complete terms.

---

## Acknowledgments

We thank security researchers and users who responsibly report vulnerabilities to help improve VulnGuard for everyone.

Responsible disclosure makes open-source software more secure for all users.
