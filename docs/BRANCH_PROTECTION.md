# GitHub Branch Protection Guide for VulnGuard

## Overview

This document provides step-by-step instructions for configuring branch protection rules for the `main` branch in the VulnGuard repository on GitHub.

**Purpose**: Ensure code quality, security, and proper review processes before code is merged into the main branch.

---

## Prerequisites

- GitHub repository administrator access
- Repository URL: `https://github.com/praveenkore/nixsoftai.git`
- Target branch: `main`

---

## Step-by-Step Configuration

### Step 1: Navigate to Repository Settings

1. Go to the repository on GitHub: `https://github.com/praveenkore/nixsoftai`
2. Click on the **Settings** tab (top navigation bar)
3. In the left sidebar, click on **Branches** under "Code and automation"

### Step 2: Add Branch Protection Rule for `main`

1. Click the **Add branch protection rule** button
2. In the "Branch name pattern" field, enter: `main`
3. Configure the following settings:

#### Required Settings

**Require a pull request before merging**

- ✅ **Check**: "Require a pull request before merging"
- **Require approvals**: Check this box
- **Number of required approving reviews**: Set to `1`
- **Dismiss stale PR approvals when new commits are pushed**: ✅ Check this box
- **Require review from CODEOWNERS**: ❌ Uncheck (not applicable yet)

**Require status checks to pass before merging**

- ✅ **Check**: "Require status checks to pass before merging"
- **Require branches to be up to date before merging**: ✅ Check this box
- **Search for status checks in the last**: Select `1 month`

**Required status checks**

Add the following status checks (if available):
- `tests` (or your CI test job name)
- `lint` (if you have linting checks)
- `security-scan` (if you have security scanning)
- `license-check` (if you have license header validation)

**Do not allow bypassing the above settings**

- ❌ **Uncheck**: "Allow administrators to bypass the above settings"

**Restrict who can push to matching branches**

- ✅ **Check**: "Restrict who can push to matching branches"
- Select: **Only users with bypass permission**
- **Add teams/people**: Add repository administrators only

**Allow force pushes**

- ❌ **Uncheck**: "Allow force pushes"

**Allow deletions**

- ❌ **Uncheck**: "Allow deletions"

**Require signed commits**

- ✅ **Check**: "Require signed commits" (recommended for security compliance tools)

**Require linear history**

- ✅ **Check**: "Require linear history" (prevents merge commits, ensures clean history)

### Step 3: Save the Rule

1. Click the **Create** or **Save changes** button
2. Confirm the rule is applied to the `main` branch

---

## Summary of Configured Protections

| Protection | Status | Description |
|-------------|----------|-------------|
| Required PR before merging | ✅ Enabled | All changes must go through pull requests |
| Required approvals | ✅ Enabled (1 reviewer) | At least 1 approval required |
| Dismiss stale approvals | ✅ Enabled | Approvals dismissed on new commits |
| Status checks required | ✅ Enabled | CI checks must pass |
| Branches up-to-date | ✅ Enabled | PR must be updated with latest main |
| Admin bypass disabled | ❌ Disabled | No one can bypass protections |
| Push restrictions | ✅ Enabled | Only admins can push directly |
| Force push disabled | ❌ Disabled | Prevents history rewriting |
| Deletions disabled | ❌ Disabled | Prevents branch deletion |
| Signed commits | ✅ Enabled | Requires commit signatures |
| Linear history | ✅ Enabled | Prevents merge commits |

---

## Who Can Bypass Protections

**None** - With the configuration above, no users can bypass branch protection rules.

If you need to allow specific individuals or teams to bypass:

1. In the branch protection rule settings
2. Under "Restrict who can push to matching branches"
3. Add specific users or teams with bypass permission
4. **Recommendation**: Keep this list minimal and document all bypass permissions

---

## Additional Recommendations

### 1. CODEOWNERS File

Create a `.github/CODEOWNERS` file to define code ownership:

```markdown
# VulnGuard Code Owners

# Core modules
* @praveenkore

# Scanner module
vulnguard/pkg/scanner/ @praveenkore

# Engine module
vulnguard/pkg/engine/ @praveenkore

# Advisor module
vulnguard/pkg/advisor/ @praveenkore

# Remediation module
vulnguard/pkg/remediation/ @praveenkore

# Logging module
vulnguard/pkg/logging/ @praveenkore
```

### 2. Required Status Checks

Ensure your CI/CD pipeline provides these status checks:

- **Tests**: All unit and integration tests pass
- **Lint**: Code formatting and style checks pass
- **Security**: No known vulnerabilities detected
- **License**: All source files have proper GPL v3 headers

### 3. Pull Request Templates

Create `.github/PULL_REQUEST_TEMPLATE.md`:

```markdown
## Description
<!-- Describe the changes in this PR -->

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
<!-- Describe how you tested this change -->

## Checklist
- [ ] Code follows project style guidelines
- [ ] Tests have been added/updated
- [ ] All tests pass
- [ ] License headers are present on all new files
- [ ] Documentation has been updated (if applicable)

## Security Considerations
<!-- Note any security implications of this change -->
```

### 4. Issue Templates

Create `.github/ISSUE_TEMPLATE/bug_report.md` and `security_report.md` for structured issue reporting.

---

## Verification

To verify branch protection is working:

1. Create a new branch: `git checkout -b test-branch`
2. Make a change and commit: `git commit -am "test"`
3. Push to GitHub: `git push origin test-branch`
4. Create a pull request to `main`
5. Verify that:
   - You cannot merge without approval
   - You cannot merge if status checks fail
   - You cannot push directly to `main`

---

## Troubleshooting

### Issue: Cannot create branch protection rule

**Cause**: Insufficient permissions

**Solution**: Ensure you have repository administrator access

### Issue: Status checks not appearing

**Cause**: CI/CD pipeline not configured or not running

**Solution**: Configure GitHub Actions or external CI to report status checks

### Issue: Cannot merge despite approval

**Cause**: Status checks failing or branch not up-to-date

**Solution**: Update PR with latest `main` branch and fix any failing checks

---

## Security Considerations

- **No force pushes**: Prevents malicious history rewriting
- **No deletions**: Prevents accidental or intentional branch removal
- **Signed commits**: Ensures commit authenticity (critical for security tools)
- **Linear history**: Maintains clean, auditable git history
- **Required approvals**: Ensures code review before integration
- **No bypass**: Enforces consistent security posture

---

## Compliance Notes

These branch protection rules align with:

- **GPL v3 best practices**: Ensures proper attribution and review
- **Security tool requirements**: Maintains integrity of security-sensitive code
- **Enterprise standards**: Meets typical corporate governance requirements
- **Audit requirements**: All changes are reviewed and traceable

---

## Contact

For questions about branch protection configuration:

- Repository: https://github.com/praveenkore/nixsoftai
- Maintainer: praveenkore
- License: GPL v3
