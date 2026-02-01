# VulnGuard - Linux Security Compliance Agent
# Copyright (c) Nixsoft Technologies Pvt. Ltd.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
Command Validation Module - Centralized Command Validation Patterns

Provides centralized command validation patterns for allow-lists and block-lists.
This module eliminates duplication of command validation patterns across the codebase.
"""

from typing import List, Optional, Tuple


# Default command allow-list (regex patterns)
# These patterns define which commands are allowed to execute
DEFAULT_COMMAND_ALLOWLIST = [
    r'^systemctl\s+(enable|disable|start|stop|restart|status)\s+[a-zA-Z0-9_-]+$',
    r'^sysctl\s+-w\s+[a-zA-Z0-9._-]+=[a-zA-Z0-9._/-]+$',
    r'^chmod\s+[0-7]{3,4}\s+[a-zA-Z0-9_./-]+$',
    r'^chown\s+[a-zA-Z0-9_:.-]+\s+[a-zA-Z0-9_./-]+$',
    # Restrict sed pattern to avoid shell metacharacters like ; | & $ `
    r'^sed\s+-i\s+[\'"][^\'";|&$`]+[\'"]\s+[a-zA-Z0-9_./-]+$',
    # Restrict echo content to avoid shell metacharacters
    r'^echo\s+[^\'";|&$`]+\s*>>?\s*[a-zA-Z0-9_./-]+$'
]

# Command block-list (regex patterns)
# These patterns define which commands are explicitly forbidden
COMMAND_BLOCKLIST = [
    r'rm\s+-rf',
    r'chmod\s+777',
    r'userdel',
    r'groupdel',
    r'passwd\s+-l\s+root',
    r'setenforce\s+0'
]

# Additional dangerous argument patterns
# These patterns are used for detecting dangerous command arguments
DANGEROUS_ARG_PATTERNS = [
    r';\s*\w+',  # Command chaining
    r'&&\s*\w+',  # Command chaining
    r'\|\|\s*\w+',  # Command chaining
    r'\|\s*\w+',  # Pipe to arbitrary command
    r'\$\(',  # Command substitution
    r'`[^`]*`',  # Backtick command substitution
    r'\$\{[^}]*\}',  # Variable expansion
    r'\\x[0-9a-fA-F]{2}',  # Hex encoding
    r'\\[0-7]{3}',  # Octal encoding
    r'\n',  # Newline injection
    r'\r',  # Carriage return injection
    r'\t',  # Tab injection
]


def get_default_command_allowlist() -> List[str]:
    """
    Get the default command allow-list.
    
    Returns:
        List of regex patterns for allowed commands
    """
    return DEFAULT_COMMAND_ALLOWLIST.copy()


def get_command_blocklist() -> List[str]:
    """
    Get the command block-list.
    
    Returns:
        List of regex patterns for blocked commands
    """
    return COMMAND_BLOCKLIST.copy()


def get_dangerous_arg_patterns() -> List[str]:
    """
    Get the dangerous argument patterns.
    
    Returns:
        List of regex patterns for dangerous arguments
    """
    return DANGEROUS_ARG_PATTERNS.copy()


def merge_command_patterns(
    custom_allowlist: Optional[List[str]] = None,
    custom_blocklist: Optional[List[str]] = None
) -> Tuple[List[str], List[str]]:
    """
    Merge custom command patterns with defaults.
    
    Args:
        custom_allowlist: Optional custom command allow-list
        custom_blocklist: Optional custom command block-list
        
    Returns:
        Tuple of (allowlist, blocklist)
    """
    # Start with defaults
    allowlist = get_default_command_allowlist()
    blocklist = get_command_blocklist()
    
    # Merge custom patterns if provided
    if custom_allowlist:
        allowlist.extend(custom_allowlist)
    
    if custom_blocklist:
        blocklist.extend(custom_blocklist)
    
    return allowlist, blocklist


def validate_command_list(
    commands: List[str],
    allowlist: List[str],
    blocklist: List[str]
) -> Tuple[bool, List[str]]:
    """
    Validate a list of commands against allow-list and block-list.
    
    Args:
        commands: List of commands to validate
        allowlist: List of regex patterns for allowed commands
        blocklist: List of regex patterns for blocked commands
        
    Returns:
        Tuple of (all_valid, error_messages)
    """
    import re
    
    all_valid = True
    error_messages = []
    
    for cmd in commands:
        # Check block-list first
        blocked = False
        for block_pattern in blocklist:
            if re.search(block_pattern, cmd, re.IGNORECASE):
                error_messages.append(
                    f"Command blocked by block-list pattern: {block_pattern}"
                )
                blocked = True
                break
        
        if blocked:
            all_valid = False
            continue
        
        # Check allow-list
        allowed = False
        for allow_pattern in allowlist:
            if re.match(allow_pattern, cmd):
                allowed = True
                break
        
        if not allowed:
            error_messages.append(f"Command not in allow-list: {cmd}")
            all_valid = False
    
    return all_valid, error_messages
