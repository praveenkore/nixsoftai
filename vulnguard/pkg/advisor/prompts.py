"""
Prompt Engineering Module - Security Compliance Prompts

Provides specialized prompts for security compliance analysis and remediation.
"""

from typing import Dict, Any


class CompliancePrompts:
    """
    Collection of prompts for security compliance analysis.
    """
    
    # System prompt that defines the AI's role and constraints
    SYSTEM_PROMPT = """You are VulnGuard AI, an expert security compliance assistant specializing in Linux system security. Your role is to analyze security compliance findings and provide safe, accurate remediation recommendations.

CRITICAL SAFETY RULES:
1. NEVER suggest commands that could cause data loss or system instability
2. ALWAYS validate that commands are safe for production environments
3. ONLY suggest commands that are reversible or have clear rollback procedures
4. NEVER suggest disabling security features (e.g., SELinux, firewalls)
5. ALWAYS prefer the most secure configuration option
6. NEVER suggest commands that bypass security controls

OUTPUT FORMAT:
You must respond with a valid JSON object containing the following fields:
- rule_id: The rule identifier
- compliance_status: One of "compliant", "non_compliant", or "requires_manual_review"
- risk_level: One of "low", "medium", "high", or "critical"
- analysis: Detailed analysis of the security issue
- recommended_action: Clear description of what action should be taken
- commands: List of shell commands to fix the issue (empty if manual review needed)
- rollback_commands: List of commands to revert the changes
- requires_restart: Boolean - whether a service restart is needed
- requires_reboot: Boolean - whether a system reboot is needed
- confidence: Float between 0.0 and 1.0 indicating confidence in the recommendation

COMMAND GUIDELINES:
- Commands must be specific and complete
- Include only safe, well-tested commands
- Each command must be reversible
- Commands should follow best practices for the target OS
- Avoid commands that could have unintended side effects

ANALYSIS GUIDELINES:
- Explain the security risk clearly
- Reference the specific CIS or STIG requirement
- Consider the impact on system functionality
- Identify any dependencies or prerequisites
- Note any exceptions or special cases"""

    @staticmethod
    def get_analysis_prompt(
        rule_id: str,
        rule_title: str,
        benchmark: str,
        severity: str,
        description: str,
        rationale: str,
        check_output: str,
        expected_state: str,
        actual_state: str,
        os_info: Dict[str, Any] = None
    ) -> str:
        """
        Generate a prompt for analyzing a compliance finding.
        
        Args:
            rule_id: Rule identifier
            rule_title: Rule title
            benchmark: Benchmark type (CIS or STIG)
            severity: Severity level
            description: Rule description
            rationale: Rule rationale
            check_output: Output from the compliance check
            expected_state: Expected state
            actual_state: Actual state found
            os_info: Optional OS information
            
        Returns:
            Analysis prompt string
        """
        os_section = ""
        if os_info:
            os_section = f"""
Operating System Information:
- OS: {os_info.get('os', 'Unknown')}
- OS Version: {os_info.get('os_version', 'Unknown')}
- Hostname: {os_info.get('hostname', 'Unknown')}
"""
        
        prompt = f"""Analyze the following security compliance finding and provide a safe, accurate remediation recommendation.

RULE INFORMATION:
- Rule ID: {rule_id}
- Title: {rule_title}
- Benchmark: {benchmark}
- Severity: {severity}
- Description: {description}
- Rationale: {rationale}
{os_section}
COMPLIANCE CHECK RESULTS:
- Expected State: {expected_state}
- Actual State: {actual_state}
- Check Output: {check_output}

ANALYSIS REQUIREMENTS:
1. Determine if the system is compliant, non-compliant, or requires manual review
2. Assess the risk level based on severity and the deviation from expected state
3. Provide a detailed analysis explaining the security implications
4. Recommend appropriate remediation actions
5. If commands are suggested, ensure they are safe and reversible
6. Provide rollback commands for any suggested changes
7. Indicate if a service restart or system reboot is required
8. Provide a confidence score (0.0 to 1.0) for your recommendation

IMPORTANT CONSIDERATIONS:
- Consider the specific operating system and version
- Ensure commands are appropriate for the target environment
- Prioritize security while maintaining system functionality
- Avoid commands that could cause service disruption
- Provide clear, actionable recommendations

Respond with a valid JSON object following the specified format."""
        
        return prompt
    
    @staticmethod
    def get_remediation_prompt(
        rule_id: str,
        rule_title: str,
        benchmark: str,
        existing_remediation: Dict[str, Any],
        check_output: str
    ) -> str:
        """
        Generate a prompt for refining remediation recommendations.
        
        Args:
            rule_id: Rule identifier
            rule_title: Rule title
            benchmark: Benchmark type (CIS or STIG)
            existing_remediation: Existing remediation configuration
            check_output: Output from the compliance check
            
        Returns:
            Remediation prompt string
        """
        existing_commands = existing_remediation.get('commands', [])
        existing_rollback = existing_remediation.get('rollback', {}).get('commands', [])
        
        prompt = f"""Review and refine the following remediation recommendation for a security compliance issue.

RULE INFORMATION:
- Rule ID: {rule_id}
- Title: {rule_title}
- Benchmark: {benchmark}

EXISTING REMEDIATION:
- Commands: {existing_commands}
- Rollback Commands: {existing_rollback}

CHECK OUTPUT:
{check_output}

REVIEW REQUIREMENTS:
1. Evaluate if the existing remediation is appropriate and safe
2. Suggest improvements or alternatives if needed
3. Ensure all commands are safe and reversible
4. Verify rollback commands will correctly revert changes
5. Consider edge cases and potential issues
6. Provide confidence in the recommendation

Respond with a valid JSON object containing:
- rule_id: The rule identifier
- compliance_status: One of "compliant", "non_compliant", or "requires_manual_review"
- risk_level: One of "low", "medium", "high", or "critical"
- analysis: Your review and analysis of the remediation
- recommended_action: Recommended action (use existing if appropriate)
- commands: List of refined commands (or existing if no changes needed)
- rollback_commands: List of refined rollback commands
- requires_restart: Boolean - whether a service restart is needed
- requires_reboot: Boolean - whether a system reboot is needed
- confidence: Float between 0.0 and 1.0"""
        
        return prompt
    
    @staticmethod
    def get_ambiguous_case_prompt(
        rule_id: str,
        rule_title: str,
        check_output: str,
        error_message: str
    ) -> str:
        """
        Generate a prompt for handling ambiguous or error cases.
        
        Args:
            rule_id: Rule identifier
            rule_title: Rule title
            check_output: Output from the compliance check
            error_message: Error message if any
            
        Returns:
            Ambiguous case prompt string
        """
        prompt = f"""The compliance check for this rule encountered an ambiguous situation or error. Please analyze and provide guidance.

RULE INFORMATION:
- Rule ID: {rule_id}
- Title: {rule_title}

CHECK OUTPUT:
{check_output}

ERROR MESSAGE:
{error_message if error_message else "None"}

ANALYSIS REQUIREMENTS:
1. Determine the cause of the ambiguity or error
2. Assess if manual review is required
3. Provide guidance on how to resolve the issue
4. If appropriate, suggest safe diagnostic commands
5. Recommend whether to proceed with remediation or require manual intervention

Respond with a valid JSON object following the standard format. Set commands to an empty list if manual review is required."""
        
        return prompt
    
    @staticmethod
    def get_command_validation_prompt(
        commands: list,
        rule_context: Dict[str, Any]
    ) -> str:
        """
        Generate a prompt for validating commands.
        
        Args:
            commands: List of commands to validate
            rule_context: Context about the rule
            
        Returns:
            Validation prompt string
        """
        prompt = f"""Validate the following commands for safety and appropriateness.

RULE CONTEXT:
- Rule ID: {rule_context.get('rule_id', 'Unknown')}
- Title: {rule_context.get('title', 'Unknown')}
- Benchmark: {rule_context.get('benchmark', 'Unknown')}
- Severity: {rule_context.get('severity', 'Unknown')}

COMMANDS TO VALIDATE:
{chr(10).join(f'{i+1}. {cmd}' for i, cmd in enumerate(commands))}

VALIDATION CRITERIA:
1. Safety: Commands should not cause data loss or system instability
2. Reversibility: Each command should be reversible
3. Appropriateness: Commands should address the security issue
4. Completeness: Commands should fully remediate the issue
5. Side Effects: Consider potential unintended consequences

Respond with a JSON object containing:
- is_safe: Boolean indicating if commands are safe
- issues: List of any safety issues found
- recommendations: List of recommendations for improvement
- confidence: Float between 0.0 and 1.0"""
        
        return prompt


class PromptTemplates:
    """
    Template-based prompts for common scenarios.
    """
    
    SSH_CONFIG_TEMPLATE = """The SSH configuration does not meet security requirements.

ISSUE: {issue}
EXPECTED: {expected}
ACTUAL: {actual}

Provide remediation commands to fix the SSH configuration safely."""

    SERVICE_CONFIG_TEMPLATE = """The service configuration is not compliant with security requirements.

SERVICE: {service_name}
ISSUE: {issue}
EXPECTED STATE: {expected}
ACTUAL STATE: {actual}

Provide remediation commands to fix the service configuration safely."""

    SYSCTL_CONFIG_TEMPLATE = """The kernel parameter configuration is not compliant with security requirements.

PARAMETER: {sysctl_key}
ISSUE: {issue}
EXPECTED VALUE: {expected}
ACTUAL VALUE: {actual}

Provide remediation commands to fix the kernel parameter safely."""

    FILE_PERMISSIONS_TEMPLATE = """File permissions do not meet security requirements.

FILE: {file_path}
ISSUE: {issue}
EXPECTED PERMISSIONS: {expected}
ACTUAL PERMISSIONS: {actual}

Provide remediation commands to fix file permissions safely."""

    @staticmethod
    def get_ssh_config_prompt(issue: str, expected: str, actual: str) -> str:
        """Get SSH configuration prompt."""
        return PromptTemplates.SSH_CONFIG_TEMPLATE.format(
            issue=issue,
            expected=expected,
            actual=actual
        )
    
    @staticmethod
    def get_service_config_prompt(service_name: str, issue: str, expected: str, actual: str) -> str:
        """Get service configuration prompt."""
        return PromptTemplates.SERVICE_CONFIG_TEMPLATE.format(
            service_name=service_name,
            issue=issue,
            expected=expected,
            actual=actual
        )
    
    @staticmethod
    def get_sysctl_config_prompt(sysctl_key: str, issue: str, expected: str, actual: str) -> str:
        """Get sysctl configuration prompt."""
        return PromptTemplates.SYSCTL_CONFIG_TEMPLATE.format(
            sysctl_key=sysctl_key,
            issue=issue,
            expected=expected,
            actual=actual
        )
    
    @staticmethod
    def get_file_permissions_prompt(file_path: str, issue: str, expected: str, actual: str) -> str:
        """Get file permissions prompt."""
        return PromptTemplates.FILE_PERMISSIONS_TEMPLATE.format(
            file_path=file_path,
            issue=issue,
            expected=expected,
            actual=actual
        )
