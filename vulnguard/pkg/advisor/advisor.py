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
Advisor Module - AI Gateway & Safety Validator

Provides AI assistance for ambiguous findings with strict safety validation.
All AI output is validated against allow-lists and confidence thresholds.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional
from vulnguard.pkg.scanner.scanner import ScanResult
from vulnguard.pkg.engine.engine import EvaluationResult
from vulnguard.pkg.logging.logger import AuditLogger
from vulnguard.pkg.advisor.llm_client import create_llm_client, BaseLLMClient
from vulnguard.pkg.advisor.prompts import CompliancePrompts


class AIAdvisory:
    """
    Represents an AI advisory output.
    """
    
    def __init__(
        self,
        rule_id: str,
        compliance_status: str,
        risk_level: str,
        analysis: str,
        recommended_action: str,
        commands: List[str],
        rollback_commands: List[str],
        requires_restart: bool,
        requires_reboot: bool,
        confidence: float
    ):
        """
        Initialize an AI advisory.
        
        Args:
            rule_id: Rule identifier
            compliance_status: Compliance status
            risk_level: Risk level
            analysis: AI analysis
            recommended_action: Recommended action
            commands: List of recommended commands
            rollback_commands: List of rollback commands
            requires_restart: Whether service restart is required
            requires_reboot: Whether system reboot is required
            confidence: Confidence score (0.0 - 1.0)
        """
        self.rule_id = rule_id
        self.compliance_status = compliance_status
        self.risk_level = risk_level
        self.analysis = analysis
        self.recommended_action = recommended_action
        self.commands = commands
        self.rollback_commands = rollback_commands
        self.requires_restart = requires_restart
        self.requires_reboot = requires_reboot
        self.confidence = confidence
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert AI advisory to dictionary."""
        return {
            "rule_id": self.rule_id,
            "compliance_status": self.compliance_status,
            "risk_level": self.risk_level,
            "analysis": self.analysis,
            "recommended_action": self.recommended_action,
            "commands": self.commands,
            "rollback_commands": self.rollback_commands,
            "requires_restart": self.requires_restart,
            "requires_reboot": self.requires_reboot,
            "confidence": self.confidence
        }


class AIAdvisor:
    """
    AI gateway and safety validator.
    
    Provides AI assistance for ambiguous findings with strict validation
    of all output against allow-lists and confidence thresholds.
    """
    
    # Default command allow-list (regex patterns)
    DEFAULT_COMMAND_ALLOWLIST = [
        r'^systemctl\s+(enable|disable|start|stop|restart|status)\s+[a-zA-Z0-9_-]+$',
        r'^sysctl\s+-w\s+[a-zA-Z0-9._-]+=.+$',
        r'^chmod\s+[0-7]{3,4}\s+[a-zA-Z0-9_./-]+$',
        r'^chown\s+[a-zA-Z0-9_:.-]+\s+[a-zA-Z0-9_./-]+$',
        r'^sed\s+-i\s+.+\s+[a-zA-Z0-9_./-]+$',
        r'^echo\s+.+\s*>>?\s*[a-zA-Z0-9_./-]+$'
    ]
    
    # Command block-list (regex patterns)
    COMMAND_BLOCKLIST = [
        r'rm\s+-rf',
        r'chmod\s+777',
        r'userdel',
        r'groupdel',
        r'passwd\s+-l\s+root',
        r'setenforce\s+0'
    ]
    
    def __init__(
        self,
        logger: Optional[AuditLogger] = None,
        min_confidence_threshold: float = 0.7,
        command_allowlist: Optional[List[str]] = None,
        command_blocklist: Optional[List[str]] = None,
        llm_config: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize the AI advisor.
        
        Args:
            logger: Optional audit logger instance
            min_confidence_threshold: Minimum confidence threshold
            command_allowlist: Optional custom command allow-list
            command_blocklist: Optional custom command block-list
            llm_config: Optional LLM provider configuration
        """
        self.logger = logger or AuditLogger()
        self.min_confidence_threshold = min_confidence_threshold
        self.command_allowlist = command_allowlist or self.DEFAULT_COMMAND_ALLOWLIST
        self.command_blocklist = command_blocklist or self.COMMAND_BLOCKLIST
        
        # Initialize LLM client if configuration is provided
        self.llm_client: Optional[BaseLLMClient] = None
        self.llm_enabled = False
        
        if llm_config:
            self._init_llm_client(llm_config)
    
    def _init_llm_client(self, llm_config: Dict[str, Any]) -> None:
        """
        Initialize the LLM client based on configuration.
        
        Args:
            llm_config: LLM provider configuration dictionary
        """
        try:
            provider = llm_config.get('provider', 'mock')
            enabled = llm_config.get('enabled', True)
            
            if not enabled:
                self.logger.log_info("AI advisor is disabled in configuration")
                return
            
            # Get provider-specific configuration
            provider_config = {}
            if provider == 'openai':
                provider_config = llm_config.get('openai', {})
            elif provider == 'anthropic':
                provider_config = llm_config.get('anthropic', {})
            elif provider == 'local':
                provider_config = llm_config.get('local', {})
            elif provider == 'mock':
                provider_config = llm_config.get('mock', {})
            
            # Add timeout from general config
            provider_config['timeout'] = llm_config.get('timeout_seconds', 30)
            
            # Create LLM client
            self.llm_client = create_llm_client(
                provider=provider,
                config=provider_config,
                logger=self.logger
            )
            
            self.llm_enabled = True
            self.logger.log_info(
                f"Initialized LLM client: {self.llm_client.get_model_name()}"
            )
            
        except Exception as e:
            self.logger.log_error(
                "ai_advisor",
                f"Failed to initialize LLM client: {str(e)}",
                {"llm_config": llm_config}
            )
            self.llm_enabled = False
    
    def _validate_command(self, command: str) -> tuple[bool, str]:
        """
        Validate a command against allow-list and block-list.
        
        Args:
            command: Command to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        # Check block-list first
        for block_pattern in self.command_blocklist:
            if re.search(block_pattern, command, re.IGNORECASE):
                return False, f"Command blocked by block-list pattern: {block_pattern}"
        
        # Check allow-list
        is_allowed = False
        for allow_pattern in self.command_allowlist:
            if re.match(allow_pattern, command):
                is_allowed = True
                break
        
        if not is_allowed:
            return False, "Command not in allow-list"
        
        return True, ""
    
    def _validate_json_output(self, json_output: str) -> tuple[bool, Any, str]:
        """
        Validate AI output as JSON and check required fields.
        
        Args:
            json_output: JSON string from AI
            
        Returns:
            Tuple of (is_valid, parsed_data, error_message)
        """
        try:
            data = json.loads(json_output)
        except json.JSONDecodeError as e:
            return False, None, f"Invalid JSON: {str(e)}"
        
        # Check required fields
        required_fields = [
            'rule_id',
            'compliance_status',
            'risk_level',
            'analysis',
            'recommended_action',
            'commands',
            'rollback_commands',
            'requires_restart',
            'requires_reboot',
            'confidence'
        ]
        
        for field in required_fields:
            if field not in data:
                return False, None, f"Missing required field: {field}"
        
        # Validate confidence
        confidence = data.get('confidence', 0.0)
        if not isinstance(confidence, (int, float)) or confidence < 0.0 or confidence > 1.0:
            return False, None, f"Invalid confidence value: {confidence}"
        
        # Validate commands
        commands = data.get('commands', [])
        if not isinstance(commands, list):
            return False, None, "commands must be a list"
        
        for cmd in commands:
            is_valid, error = self._validate_command(cmd)
            if not is_valid:
                return False, None, f"Invalid command: {cmd} - {error}"
        
        # Validate rollback commands
        rollback_commands = data.get('rollback_commands', [])
        if not isinstance(rollback_commands, list):
            return False, None, "rollback_commands must be a list"
        
        for cmd in rollback_commands:
            is_valid, error = self._validate_command(cmd)
            if not is_valid:
                return False, None, f"Invalid rollback command: {cmd} - {error}"
        
        # Validate compliance_status
        valid_statuses = ['compliant', 'non_compliant', 'requires_manual_review']
        if data.get('compliance_status') not in valid_statuses:
            return False, None, f"Invalid compliance_status: {data.get('compliance_status')}"
        
        # Validate risk_level
        valid_risk_levels = ['low', 'medium', 'high', 'critical']
        if data.get('risk_level') not in valid_risk_levels:
            return False, None, f"Invalid risk_level: {data.get('risk_level')}"
        
        # Validate boolean fields
        for field in ['requires_restart', 'requires_reboot']:
            if not isinstance(data.get(field), bool):
                return False, None, f"{field} must be a boolean"
        
        return True, data, ""
    
    def _get_ai_response(
        self,
        rule_id: str,
        scan_result: ScanResult,
        evaluation_result: EvaluationResult,
        rule_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Get AI response from configured LLM provider.
        
        Args:
            rule_id: Rule identifier
            scan_result: Scan result from the scanner
            evaluation_result: Evaluation result from the engine
            rule_data: Optional rule configuration data
            
        Returns:
            JSON string representing AI output
        """
        # Use LLM client if enabled
        if self.llm_enabled and self.llm_client:
            return self._call_llm_for_advisory(
                rule_id=rule_id,
                scan_result=scan_result,
                evaluation_result=evaluation_result,
                rule_data=rule_data
            )
        
        # Fallback to simulated response
        return self._simulate_ai_response(
            rule_id=rule_id,
            scan_result=scan_result,
            evaluation_result=evaluation_result
        )
    
    def _call_llm_for_advisory(
        self,
        rule_id: str,
        scan_result: ScanResult,
        evaluation_result: EvaluationResult,
        rule_data: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Call LLM to generate advisory for a compliance finding.
        
        Args:
            rule_id: Rule identifier
            scan_result: Scan result from the scanner
            evaluation_result: Evaluation result from the engine
            rule_data: Optional rule configuration data
            
        Returns:
            JSON string representing AI output
        """
        # Prepare rule information
        rule_title = rule_data.get('title', 'Unknown') if rule_data else 'Unknown'
        rule_description = rule_data.get('description', '') if rule_data else ''
        rule_rationale = rule_data.get('rationale', '') if rule_data else ''
        
        # Get OS information
        import platform
        os_info = {
            'os': platform.system(),
            'os_version': platform.version(),
            'hostname': platform.node()
        }
        
        # Determine prompt type based on situation
        if scan_result.error or scan_result.actual_state == 'error':
            # Use ambiguous case prompt for errors
            prompt = CompliancePrompts.get_ambiguous_case_prompt(
                rule_id=rule_id,
                rule_title=rule_title,
                check_output=scan_result.check_output,
                error_message=scan_result.error or ''
            )
        else:
            # Use standard analysis prompt
            prompt = CompliancePrompts.get_analysis_prompt(
                rule_id=rule_id,
                rule_title=rule_title,
                benchmark=scan_result.benchmark,
                severity=evaluation_result.severity,
                description=rule_description,
                rationale=rule_rationale,
                check_output=scan_result.check_output,
                expected_state=scan_result.expected_state,
                actual_state=scan_result.actual_state,
                os_info=os_info
            )
        
        try:
            # Call LLM
            response = self.llm_client.generate_response(
                prompt=prompt,
                system_prompt=CompliancePrompts.SYSTEM_PROMPT
            )
            
            self.logger.log_info(
                f"LLM response received for rule {rule_id}: "
                f"{len(response)} characters"
            )
            
            return response
            
        except Exception as e:
            self.logger.log_error(
                "llm_client",
                f"Failed to get LLM response: {str(e)}",
                {"rule_id": rule_id}
            )
            # Fallback to simulated response on error
            return self._simulate_ai_response(
                rule_id=rule_id,
                scan_result=scan_result,
                evaluation_result=evaluation_result
            )
    
    def _simulate_ai_response(
        self,
        rule_id: str,
        scan_result: ScanResult,
        evaluation_result: EvaluationResult
    ) -> str:
        """
        Simulate AI response (fallback when LLM is not available).
        
        Args:
            rule_id: Rule identifier
            scan_result: Scan result from the scanner
            evaluation_result: Evaluation result from the engine
            
        Returns:
            JSON string representing AI output
        """
        if scan_result.compliant:
            compliance_status = "compliant"
            risk_level = "low"
            analysis = f"System is compliant with {rule_id}. No action required."
            recommended_action = "No action required"
            commands = []
            rollback_commands = []
            requires_restart = False
            requires_reboot = False
            confidence = 0.95
        else:
            compliance_status = "non_compliant"
            risk_level = evaluation_result.risk_level
            analysis = f"System is non-compliant with {rule_id}. {scan_result.check_output}"
            recommended_action = "Apply remediation to achieve compliance"
            
            # Generate placeholder commands based on rule type
            if "sshd" in rule_id.lower():
                commands = [
                    f"sed -i 's/{scan_result.actual_state}/{scan_result.expected_state}/g' /etc/ssh/sshd_config",
                    "systemctl restart sshd"
                ]
                rollback_commands = [
                    "cp /var/lib/vulnguard/backups/sshd_config /etc/ssh/sshd_config",
                    "systemctl restart sshd"
                ]
                requires_restart = True
                requires_reboot = False
            elif "sysctl" in rule_id.lower():
                commands = [
                    f"sysctl -w {scan_result.expected_state}",
                    f"echo '{scan_result.expected_state}' >> /etc/sysctl.conf"
                ]
                rollback_commands = [
                    f"sysctl -w {scan_result.actual_state}"
                ]
                requires_restart = False
                requires_reboot = False
            else:
                commands = []
                rollback_commands = []
                requires_restart = False
                requires_reboot = False
            
            confidence = 0.85 if risk_level in ['high', 'critical'] else 0.90
        
        ai_output = {
            "rule_id": rule_id,
            "compliance_status": compliance_status,
            "risk_level": risk_level,
            "analysis": analysis,
            "recommended_action": recommended_action,
            "commands": commands,
            "rollback_commands": rollback_commands,
            "requires_restart": requires_restart,
            "requires_reboot": requires_reboot,
            "confidence": confidence
        }
        
        return json.dumps(ai_output)
    
    def get_advisory(
        self,
        rule_id: str,
        scan_result: ScanResult,
        evaluation_result: EvaluationResult,
        rule_data: Optional[Dict[str, Any]] = None
    ) -> tuple[Optional[AIAdvisory], str]:
        """
        Get AI advisory for a rule.
        
        Args:
            rule_id: Rule identifier
            scan_result: Scan result from the scanner
            evaluation_result: Evaluation result from the engine
            rule_data: Optional rule configuration data
            
        Returns:
            Tuple of (AIAdvisory object or None, error message)
        """
        # Check if AI assist is required
        if not evaluation_result.ai_assist_required:
            return None, "AI assist not required for this rule"
        
        # Get AI response
        try:
            ai_json_output = self._get_ai_response(
                rule_id=rule_id,
                scan_result=scan_result,
                evaluation_result=evaluation_result,
                rule_data=rule_data
            )
        except Exception as e:
            self.logger.log_error(
                "ai_advisory",
                f"Failed to get AI response: {str(e)}",
                {"rule_id": rule_id}
            )
            return None, f"Failed to get AI response: {str(e)}"
        
        # Validate AI output
        is_valid, parsed_data, error_message = self._validate_json_output(ai_json_output)
        
        if not is_valid:
            self.logger.log_error(
                "ai_advisory",
                f"AI output validation failed: {error_message}",
                {"rule_id": rule_id, "ai_output": ai_json_output}
            )
            return None, f"AI output validation failed: {error_message}"
        
        # Check confidence threshold
        confidence = parsed_data.get('confidence', 0.0)
        if confidence < self.min_confidence_threshold:
            self.logger.log_error(
                "ai_advisory",
                f"AI confidence below threshold: {confidence} < {self.min_confidence_threshold}",
                {"rule_id": rule_id}
            )
            return None, f"AI confidence below threshold: {confidence} < {self.min_confidence_threshold}"
        
        # Create AI advisory
        advisory = AIAdvisory(
            rule_id=parsed_data['rule_id'],
            compliance_status=parsed_data['compliance_status'],
            risk_level=parsed_data['risk_level'],
            analysis=parsed_data['analysis'],
            recommended_action=parsed_data['recommended_action'],
            commands=parsed_data['commands'],
            rollback_commands=parsed_data['rollback_commands'],
            requires_restart=parsed_data['requires_restart'],
            requires_reboot=parsed_data['requires_reboot'],
            confidence=parsed_data['confidence']
        )
        
        # Log AI advisory
        self.logger.log_ai_advisory(
            rule_id=rule_id,
            confidence=confidence,
            recommendation=parsed_data['recommended_action'],
            commands=parsed_data['commands']
        )
        
        return advisory, ""
    
    def requires_manual_review(
        self,
        evaluation_result: EvaluationResult,
        ai_advisory: Optional[AIAdvisory] = None
    ) -> bool:
        """
        Determine if manual review is required.
        
        Args:
            evaluation_result: Evaluation result from the engine
            ai_advisory: Optional AI advisory
            
        Returns:
            True if manual review is required, False otherwise
        """
        # Check if approval is required
        if evaluation_result.approval_required:
            return True
        
        # Check AI confidence if advisory exists
        if ai_advisory and ai_advisory.confidence < self.min_confidence_threshold:
            return True
        
        # Check for critical risk level
        if evaluation_result.risk_level == 'critical':
            return True
        
        return False
