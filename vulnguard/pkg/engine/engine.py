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
Engine Module - Compliance & Risk Decision Engine

Evaluates compliance status and determines risk levels based on scan results.
Normalizes severities across different benchmark standards.
"""

from typing import Any, Dict, List, Optional
from vulnguard.pkg.scanner.scanner import ScanResult
from vulnguard.pkg.logging.logger import AuditLogger


class EvaluationResult:
    """
    Represents the result of a compliance evaluation.
    """
    
    def __init__(
        self,
        rule_id: str,
        benchmark: str,
        compliant: bool,
        severity: str,
        risk_level: str,
        ai_assist_required: bool,
        approval_required: bool,
        exception_allowed: bool
    ):
        """
        Initialize an evaluation result.
        
        Args:
            rule_id: Rule identifier
            benchmark: Benchmark type (CIS or STIG)
            compliant: Whether the system is compliant
            severity: Normalized severity level
            risk_level: Risk level (low, medium, high, critical)
            ai_assist_required: Whether AI assistance is required
            approval_required: Whether approval is required
            exception_allowed: Whether exception is allowed
        """
        self.rule_id = rule_id
        self.benchmark = benchmark
        self.compliant = compliant
        self.severity = severity
        self.risk_level = risk_level
        self.ai_assist_required = ai_assist_required
        self.approval_required = approval_required
        self.exception_allowed = exception_allowed
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert evaluation result to dictionary."""
        return {
            "rule_id": self.rule_id,
            "benchmark": self.benchmark,
            "compliant": self.compliant,
            "severity": self.severity,
            "risk_level": self.risk_level,
            "ai_assist_required": self.ai_assist_required,
            "approval_required": self.approval_required,
            "exception_allowed": self.exception_allowed
        }


class ComplianceEngine:
    """
    Compliance and risk decision engine.
    
    Evaluates scan results, normalizes severities, and determines
    risk levels and approval requirements.
    """
    
    # Severity normalization mapping
    SEVERITY_MAPPING = {
        'CIS': {
            'Level1': 'high',
            'Level2': 'medium',
            'Level3': 'low'
        },
        'STIG': {
            'CAT_I': 'critical',
            'CAT_II': 'high',
            'CAT_III': 'medium'
        }
    }
    
    # Risk level mapping based on normalized severity
    RISK_LEVEL_MAPPING = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low'
    }
    
    def __init__(
        self,
        logger: Optional[AuditLogger] = None,
        severity_mapping: Optional[Dict[str, Dict[str, str]]] = None
    ):
        """
        Initialize the compliance engine.
        
        Args:
            logger: Optional audit logger instance
            severity_mapping: Optional custom severity mapping
        """
        self.logger = logger or AuditLogger()
        
        if severity_mapping:
            self.severity_mapping = severity_mapping
        else:
            self.severity_mapping = self.SEVERITY_MAPPING.copy()
    
    def _normalize_severity(
        self,
        benchmark: str,
        original_severity: str
    ) -> str:
        """
        Normalize severity from benchmark-specific to standard format.
        
        Args:
            benchmark: Benchmark type (CIS or STIG)
            original_severity: Original severity from the rule
            
        Returns:
            Normalized severity (critical, high, medium, low)
        """
        benchmark_upper = benchmark.upper()
        severity_upper = original_severity.upper().replace(' ', '_')
        
        if benchmark_upper in self.severity_mapping:
            mapping = self.severity_mapping[benchmark_upper]
            if severity_upper in mapping:
                return mapping[severity_upper]
        
        # Default to medium if no mapping found
        return 'medium'
    
    def _determine_risk_level(
        self,
        normalized_severity: str,
        compliant: bool
    ) -> str:
        """
        Determine risk level based on severity and compliance status.
        
        Args:
            normalized_severity: Normalized severity level
            compliant: Whether the system is compliant
            
        Returns:
            Risk level (critical, high, medium, low)
        """
        if compliant:
            return 'low'
        
        return self.RISK_LEVEL_MAPPING.get(normalized_severity, 'medium')
    
    def _determine_ai_assist_required(
        self,
        rule_data: Dict[str, Any],
        scan_result: ScanResult
    ) -> bool:
        """
        Determine if AI assistance is required for this rule.
        
        Args:
            rule_data: Rule configuration data
            scan_result: Scan result from the scanner
            
        Returns:
            True if AI assistance is required, False otherwise
        """
        # Check if rule explicitly requests AI assist
        if rule_data.get('ai_assist', False):
            return True
        
        # Check if scan result indicates ambiguity
        if scan_result.error:
            return True
        
        # Check if actual state doesn't match expected state in a clear way
        if scan_result.actual_state == 'error':
            return True
        
        return False
    
    def _determine_approval_required(
        self,
        benchmark: str,
        normalized_severity: str,
        rule_data: Dict[str, Any]
    ) -> bool:
        """
        Determine if approval is required for remediation.
        
        Args:
            benchmark: Benchmark type (CIS or STIG)
            normalized_severity: Normalized severity level
            rule_data: Rule configuration data
            
        Returns:
            True if approval is required, False otherwise
        """
        # Check if rule explicitly requires approval
        if rule_data.get('approval_required', False):
            return True
        
        # STIG rules always require approval for CAT I and II
        if benchmark.upper() == 'STIG':
            if normalized_severity in ('critical', 'high'):
                return True
        
        # Critical severity always requires approval
        if normalized_severity == 'critical':
            return True
        
        return False
    
    def _load_rule_data(self, rule_id: str, benchmark: str) -> Optional[Dict[str, Any]]:
        """
        Load rule data from benchmark file.
        
        Args:
            rule_id: Rule identifier
            benchmark: Benchmark type
            
        Returns:
            Rule data dictionary, or None if loading fails
        """
        import yaml
        from pathlib import Path
        
        benchmark_dir = Path("vulnguard/configs/benchmarks")
        
        for ext in ['.yaml', '.yml']:
            rule_file = benchmark_dir / f"{rule_id}{ext}"
            if rule_file.exists():
                try:
                    with open(rule_file, 'r') as f:
                        return yaml.safe_load(f)
                except Exception as e:
                    self.logger.log_error(
                        "rule_load",
                        f"Failed to load rule data: {str(e)}",
                        {"rule_id": rule_id, "benchmark": benchmark}
                    )
                    return None
        
        return None
    
    def evaluate(
        self,
        scan_result: ScanResult,
        rule_data: Optional[Dict[str, Any]] = None
    ) -> EvaluationResult:
        """
        Evaluate a scan result and determine compliance status and risk level.
        
        Args:
            scan_result: Scan result from the scanner
            rule_data: Optional rule configuration data
            
        Returns:
            EvaluationResult object
        """
        # Load rule data if not provided
        if rule_data is None:
            rule_data = self._load_rule_data(scan_result.rule_id, scan_result.benchmark)
        
        if rule_data is None:
            # Default to basic evaluation if rule data not available
            normalized_severity = 'medium'
            risk_level = 'medium' if not scan_result.compliant else 'low'
            ai_assist_required = False
            approval_required = False
            exception_allowed = False
        else:
            # Normalize severity
            original_severity = rule_data.get('original_severity', 'medium')
            normalized_severity = self._normalize_severity(
                scan_result.benchmark,
                original_severity
            )
            
            # Determine risk level
            risk_level = self._determine_risk_level(
                normalized_severity,
                scan_result.compliant
            )
            
            # Determine if AI assist is required
            ai_assist_required = self._determine_ai_assist_required(
                rule_data,
                scan_result
            )
            
            # Determine if approval is required
            approval_required = self._determine_approval_required(
                scan_result.benchmark,
                normalized_severity,
                rule_data
            )
            
            # Check if exception is allowed
            exception_allowed = rule_data.get('exception_allowed', False)
        
        # Create evaluation result
        result = EvaluationResult(
            rule_id=scan_result.rule_id,
            benchmark=scan_result.benchmark,
            compliant=scan_result.compliant,
            severity=normalized_severity,
            risk_level=risk_level,
            ai_assist_required=ai_assist_required,
            approval_required=approval_required,
            exception_allowed=exception_allowed
        )
        
        # Log evaluation
        self.logger.log_evaluation(
            scan_result.benchmark,
            scan_result.rule_id,
            normalized_severity,
            risk_level,
            ai_assist_required
        )
        
        return result
    
    def evaluate_batch(
        self,
        scan_results: List[ScanResult]
    ) -> List[EvaluationResult]:
        """
        Evaluate multiple scan results.
        
        Args:
            scan_results: List of scan results
            
        Returns:
            List of evaluation results
        """
        evaluation_results = []
        
        for scan_result in scan_results:
            result = self.evaluate(scan_result)
            evaluation_results.append(result)
        
        return evaluation_results
    
    def generate_summary(
        self,
        evaluation_results: List[EvaluationResult]
    ) -> Dict[str, Any]:
        """
        Generate a summary of evaluation results.
        
        Args:
            evaluation_results: List of evaluation results
            
        Returns:
            Summary dictionary
        """
        total_rules = len(evaluation_results)
        compliant_count = sum(1 for r in evaluation_results if r.compliant)
        non_compliant_count = total_rules - compliant_count
        
        # Count by risk level
        risk_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for result in evaluation_results:
            risk_counts[result.risk_level] += 1
        
        # Count by benchmark
        benchmark_counts = {}
        for result in evaluation_results:
            benchmark_counts[result.benchmark] = benchmark_counts.get(result.benchmark, 0) + 1
        
        # Count by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        
        for result in evaluation_results:
            severity_counts[result.severity] += 1
        
        # Approval required count
        approval_required_count = sum(1 for r in evaluation_results if r.approval_required)
        
        # AI assist required count
        ai_assist_required_count = sum(1 for r in evaluation_results if r.ai_assist_required)
        
        summary = {
            'total_rules': total_rules,
            'compliant_count': compliant_count,
            'non_compliant_count': non_compliant_count,
            'compliance_percentage': round((compliant_count / total_rules * 100) if total_rules > 0 else 0, 2),
            'risk_distribution': risk_counts,
            'severity_distribution': severity_counts,
            'benchmark_distribution': benchmark_counts,
            'approval_required_count': approval_required_count,
            'ai_assist_required_count': ai_assist_required_count
        }
        
        return summary
