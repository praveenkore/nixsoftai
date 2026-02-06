# Canonical Rule Format Implementation Summary

## Date: 2026-02-03

## Overview

VulnGuard scanner now supports canonical STIG rule format that enables a single rule file to support multiple Linux distributions (RHEL family and Debian family) with OS-specific implementations through the `implementations` map.

## Changes Made

### 1. Scanner Schema Update (`vulnguard/pkg/scanner/scanner.py`)

Updated `RULE_SCHEMA` to support both legacy and canonical formats:

**Legacy Format:**
- `check`, `remediation`, `rollback` at root level
- Single OS family implementation

**Canonical Format:**
- `implementations` map at root level
- OS family-specific implementations (`rhel_family`, `debian_family`)
- Each implementation contains: `os` list, `check`, `remediation`, `rollback`

**Key Schema Changes:**
- Added `implementations` field with patternProperties for `rhel_family` and `debian_family`
- Added `oneOf` validation to support both legacy and canonical formats
- Updated check fields to support both:
  - Legacy: `command` (string), `service_name`, `key`, `expected_content`
  - Canonical: `command` (list), `service`, `sysctl`, `pattern`

### 2. OS Family Selection Function (`_select_os_family_implementation`)

Added new function to select appropriate OS family implementation:

```python
def _select_os_family_implementation(
    rule: Dict[str, Any],
    os_name: str,
    os_family: Optional[str]
) -> Optional[Dict[str, Any]]
```

**Functionality:**
- Detects if rule uses canonical format (has `implementations` map)
- Selects implementation based on detected OS family:
  - `rhel_family`: for RHEL, CentOS, AlmaLinux, Rocky Linux
  - `debian_family`: for Debian, Ubuntu
- Verifies OS is in implementation's compatible OS list
- Returns selected implementation or None if not compatible

### 3. Scan Rule Update (`scan_rule` method)

Modified `scan_rule` to handle canonical format:

**Changes:**
- After OS detection, check for `implementations` map
- Call `_select_os_family_implementation()` to select OS family implementation
- If no implementation found, return ScanResult with `status='not_applicable'`
- Merge selected implementation's check/remediation/rollback into rule:
  - Preserves original values in `canonical_*` fields
  - Allows existing check execution code to work unchanged

### 4. Check Method Updates

All check methods now support both legacy and canonical field names:

#### `_check_command`
- Handles `command` as list (canonical) or string (legacy)
- Uses `shlex.quote()` for safe command construction

#### `_check_file`
- Supports `pattern` field (canonical) or `expected_content` (legacy)
- Uses unified `search_pattern` variable for both formats

#### `_check_service`
- Supports `service` field (canonical) or `service_name` (legacy)
- Uses OR operator to check both fields

#### `_check_sysctl`
- Supports `sysctl` field (canonical) or `key` (legacy)
- Uses OR operator to check both fields

### 5. Import Addition

Added `shlex` import for proper command quoting in canonical format.

## Canonical Rule Examples Created

Created 7 canonical STIG rule examples from AlmaLinux OS 9 STIG:

1. **`stig_alma_09_001010_canonical.yaml`** - Max concurrent sessions (10)
   - Check type: command
   - RHEL family implementation

2. **`stig_alma_09_001890_canonical.yaml`** - Shell session timeout (10 min)
   - Check type: command
   - RHEL family implementation

3. **`stig_alma_09_002770_canonical.yaml`** - SSH logging (VERBOSE)
   - Check type: command
   - RHEL family implementation
   - Service restart required

4. **`stig_alma_09_002880_canonical.yaml`** - Remote access monitoring
   - Check type: command
   - RHEL family implementation
   - Service restart required

5. **`stig_alma_09_003100_canonical.yaml`** - SSH crypto policies
   - Check type: file
   - RHEL family implementation

6. **`stig_alma_09_003320_canonical.yaml`** - FIPS mode
   - Check type: command
   - RHEL family implementation
   - Reboot required

7. **`stig_ubuntu_2204_ssh_canonical.yaml`** - SSH ciphers (Debian family example)
   - Check type: command
   - Debian family implementation

## Documentation

Created comprehensive guide in [`vulnguard/configs/benchmarks/CANONICAL_RULES_GUIDE.md`](vulnguard/configs/benchmarks/CANONICAL_RULES_GUIDE.md):

**Contents:**
- Canonical schema specification
- OS family mapping (RHEL family, Debian family)
- Check type documentation (command, file, service, sysctl)
- Remediation fields and requirements
- AlmaLinux STIG rules quick reference
- Additional rules to convert list
- Conversion process and examples
- Command mapping: RHEL → Debian

## Backward Compatibility

The implementation maintains full backward compatibility:

**Legacy Rules:**
- Continue to work without modification
- Schema validates `check`, `remediation`, `rollback` at root level
- All existing check methods work with legacy field names

**Canonical Rules:**
- New `implementations` map structure
- OS family selection and merging
- Check methods updated to support both field naming conventions

## Testing Recommendations

### Manual Testing Steps:

```bash
# Test canonical rule on AlmaLinux
python -m vulnguard.main scan --rule stig_alma_09_001010_canonical.yaml

# Test canonical rule on Ubuntu (if Debian family implementation exists)
python -m vulnguard.main scan --rule stig_ubuntu_2204_ssh_canonical.yaml

# Test all rules (both canonical and legacy)
python -m vulnguard.main scan
```

### Expected Behavior:

**On AlmaLinux (RHEL family):**
- Canonical rules with `rhel_family` implementation should execute
- Legacy rules should continue to work
- OS compatibility check should skip rules without `rhel_family` implementation

**On Ubuntu (Debian family):**
- Canonical rules with `debian_family` implementation should execute
- Legacy rules should continue to work
- OS compatibility check should skip rules without `debian_family` implementation

## Next Steps

1. **Test canonical rules** on actual AlmaLinux and Ubuntu systems
2. **Update remediation module** to handle canonical format's `service_restart` field
3. **Convert remaining AlmaLinux STIG rules** from `Alma-linux-stig-rules.txt` to canonical format
4. **Add Debian family implementations** to applicable rules
5. **Create comprehensive test suite** for canonical format

## Files Modified

| File | Changes |
|-------|----------|
| `vulnguard/pkg/scanner/scanner.py` | Updated RULE_SCHEMA, added `_select_os_family_implementation()`, modified `scan_rule()`, updated all check methods |

## Files Created

| File | Purpose |
|-------|----------|
| `vulnguard/configs/benchmarks/stig_alma_09_001010_canonical.yaml` | Max sessions limit |
| `vulnguard/configs/benchmarks/stig_alma_09_001890_canonical.yaml` | Shell timeout |
| `vulnguard/configs/benchmarks/stig_alma_09_002770_canonical.yaml` | SSH logging |
| `vulnguard/configs/benchmarks/stig_alma_09_002880_canonical.yaml` | Remote monitoring |
| `vulnguard/configs/benchmarks/stig_alma_09_003100_canonical.yaml` | SSH crypto policies |
| `vulnguard/configs/benchmarks/stig_alma_09_003320_canonical.yaml` | FIPS mode |
| `vulnguard/configs/benchmarks/stig_ubuntu_2204_ssh_canonical.yaml` | SSH ciphers (Debian) |
| `vulnguard/configs/benchmarks/CANONICAL_RULES_GUIDE.md` | Canonical format documentation |

## Technical Notes

### Canonical Rule Format Benefits:

1. **Single Rule File**: One file supports multiple distributions
2. **OS Family Abstraction**: Implementation details separated from rule definition
3. **Easier Maintenance**: Changes to implementation only affect specific OS family
4. **Better Extensibility**: Adding new distributions is straightforward
5. **Clear Mapping**: OS family → implementation is explicit in schema

### Implementation Details:

- **No Breaking Changes**: Legacy rules continue to work
- **Graceful Degradation**: Rules without matching OS implementation are marked `not_applicable`
- **Schema Validation**: JSON schema validates both formats
- **Field Mapping**: Check methods handle both field naming conventions

## Known Limitations

1. **Remediation Module**: Not yet updated for canonical format
   - `service_restart` field not supported
   - `requires_reboot` field handling may need review

2. **Rule Coverage**: Only 7 canonical rules created from ~50 AlmaLinux STIG rules
   - Many more rules can be converted
   - Debian family implementations mostly missing

3. **Testing**: No automated tests created for canonical format
   - Manual testing required on AlmaLinux and Ubuntu
   - Integration tests recommended

## References

- Original AlmaLinux STIG: `Alma-linux-stig-rules.txt`
- Implementation Plan: `vulnguard/CANONICAL_REFACTOR_PLAN.md`
- Documentation: `vulnguard/configs/benchmarks/CANONICAL_RULES_GUIDE.md`
