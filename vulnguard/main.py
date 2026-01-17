"""
VulnGuard Main Module - Orchestrator & CLI

Main entry point for the VulnGuard Linux Security Compliance Agent.
Provides CLI interface for scanning, evaluating, and remediating security issues.
"""

import json
import os
import platform
import sys
import yaml
from pathlib import Path
from typing import Any, Dict, List, Optional

import click

from vulnguard.pkg.scanner.scanner import Scanner, ScanResult
from vulnguard.pkg.engine.engine import ComplianceEngine, EvaluationResult
from vulnguard.pkg.advisor.advisor import AIAdvisor, AIAdvisory
from vulnguard.pkg.remediation.remediation import RemediationEngine, RemediationResult
from vulnguard.pkg.logging.logger import AuditLogger


class VulnGuardOrchestrator:
    """
    Main orchestrator for VulnGuard operations.
    
    Coordinates scanning, evaluation, AI advisory, and remediation
    operations with proper logging and error handling.
    """
    
    def __init__(
        self,
        config_path: str = "vulnguard/configs/agent/config.yaml",
        benchmark_dir: str = "vulnguard/configs/benchmarks",
        log_file: str = "/var/log/vulnguard/audit.log"
    ):
        """
        Initialize the VulnGuard orchestrator.
        
        Args:
            config_path: Path to the agent configuration file
            benchmark_dir: Directory containing benchmark rules
            log_file: Path to the audit log file
        """
        self.config_path = Path(config_path)
        self.benchmark_dir = benchmark_dir
        self.log_file = log_file
        self.config = self._load_config()
        
        # Initialize components
        self.logger = AuditLogger(
            log_file=self.log_file,
            log_level=self.config.get('logging', {}).get('level', 'INFO'),
            log_format=self.config.get('logging', {}).get('format', 'json'),
            max_size_mb=self.config.get('logging', {}).get('max_size_mb', 100),
            backup_count=self.config.get('logging', {}).get('backup_count', 10)
        )
        
        self.scanner = Scanner(
            benchmark_dir=self.benchmark_dir,
            logger=self.logger
        )
        
        self.engine = ComplianceEngine(
            logger=self.logger,
            severity_mapping=self.config.get('severity_mapping', {})
        )
        
        self.advisor = AIAdvisor(
            logger=self.logger,
            min_confidence_threshold=self.config.get('ai', {}).get('min_confidence_threshold', 0.7),
            command_allowlist=self.config.get('remediation', {}).get('command_allowlist', []),
            command_blocklist=self.config.get('remediation', {}).get('command_blocklist', []),
            llm_config=self.config.get('ai', {})
        )
        
        self.remediation = RemediationEngine(
            logger=self.logger,
            backup_directory=self.config.get('remediation', {}).get('backup_directory', '/var/lib/vulnguard/backups'),
            auto_backup=self.config.get('remediation', {}).get('auto_backup', True),
            rollback_on_failure=self.config.get('remediation', {}).get('rollback_on_failure', True),
            command_allowlist=self.config.get('remediation', {}).get('command_allowlist', []),
            command_blocklist=self.config.get('remediation', {}).get('command_blocklist', [])
        )
    
    def _load_config(self) -> Dict[str, Any]:
        """
        Load agent configuration from YAML file.
        
        Returns:
            Configuration dictionary
        """
        if not self.config_path.exists():
            # Return default configuration
            return {
                'agent': {
                    'name': 'VulnGuard',
                    'version': '1.0.0',
                    'mode': 'dry-run'
                },
                'logging': {
                    'level': 'INFO',
                    'format': 'json'
                },
                'ai': {
                    'enabled': True,
                    'min_confidence_threshold': 0.7
                },
                'remediation': {
                    'default_mode': 'dry-run',
                    'auto_backup': True,
                    'rollback_on_failure': True
                }
            }
        
        try:
            with open(self.config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Warning: Failed to load config: {e}", file=sys.stderr)
            return {}
    
    def _get_system_info(self) -> Dict[str, Any]:
        """
        Get system information for logging.
        
        Returns:
            Dictionary containing system information
        """
        return {
            'os': platform.system(),
            'os_version': platform.version(),
            'hostname': platform.node(),
            'architecture': platform.machine()
        }
    
    def run_scan(
        self,
        rule_ids: Optional[List[str]] = None
    ) -> tuple[List[ScanResult], List[EvaluationResult], List[AIAdvisory]]:
        """
        Run the complete VulnGuard pipeline: scan, evaluate, and optionally get AI advisory.
        
        Args:
            rule_ids: Optional list of rule IDs to scan. If None, scans all rules.
            
        Returns:
            Tuple of (scan_results, evaluation_results, ai_advisories)
        """
        # Log system info
        system_info = self._get_system_info()
        self.logger.log_system_info(
            os_name=system_info['os'],
            os_version=system_info['os_version'],
            hostname=system_info['hostname'],
            additional_info={'architecture': system_info['architecture']}
        )
        
        # Step 1: Scan
        click.echo("Step 1: Scanning system...")
        scan_results = self.scanner.scan_all(rule_ids)
        click.echo(f"  Scanned {len(scan_results)} rules")
        
        # Step 2: Evaluate
        click.echo("Step 2: Evaluating compliance...")
        evaluation_results = self.engine.evaluate_batch(scan_results)
        click.echo(f"  Evaluated {len(evaluation_results)} rules")
        
        # Step 3: Get AI advisories for rules that need them
        click.echo("Step 3: Getting AI advisories...")
        ai_advisories = []
        
        for scan_result, eval_result in zip(scan_results, evaluation_results):
            if eval_result.ai_assist_required:
                # Load rule data for AI analysis
                rule_data = self.scanner._load_rule(f"{scan_result.rule_id}.yaml")
                if not rule_data:
                    rule_data = self.scanner._load_rule(f"{scan_result.rule_id}.yml")
                
                advisory, error = self.advisor.get_advisory(
                    rule_id=scan_result.rule_id,
                    scan_result=scan_result,
                    evaluation_result=eval_result,
                    rule_data=rule_data
                )
                if advisory:
                    ai_advisories.append(advisory)
        
        click.echo(f"  Generated {len(ai_advisories)} AI advisories")
        
        return scan_results, evaluation_results, ai_advisories
    
    def run_remediation(
        self,
        scan_results: List[ScanResult],
        evaluation_results: List[EvaluationResult],
        ai_advisories: List[AIAdvisory],
        mode: str = "dry-run",
        force: bool = False
    ) -> List[RemediationResult]:
        """
        Run remediation for non-compliant rules.
        
        Args:
            scan_results: List of scan results
            evaluation_results: List of evaluation results
            ai_advisories: List of AI advisories
            mode: Remediation mode (dry-run or commit)
            force: Force remediation even if approval is required
            
        Returns:
            List of remediation results
        """
        click.echo(f"\nStep 4: Running remediation in {mode} mode...")
        
        remediation_results = self.remediation.remediate_batch(
            scan_results=scan_results,
            evaluation_results=evaluation_results,
            ai_advisories=ai_advisories,
            mode=mode,
            force=force
        )
        
        click.echo(f"  Remediated {len(remediation_results)} rules")
        
        return remediation_results
    
    def generate_report(
        self,
        scan_results: List[ScanResult],
        evaluation_results: List[EvaluationResult],
        remediation_results: Optional[List[RemediationResult]] = None,
        output_format: str = "json"
    ) -> str:
        """
        Generate a compliance report.
        
        Args:
            scan_results: List of scan results
            evaluation_results: List of evaluation results
            remediation_results: Optional list of remediation results
            output_format: Output format (json, yaml, text)
            
        Returns:
            Formatted report string
        """
        # Generate summary
        summary = self.engine.generate_summary(evaluation_results)
        
        # Build report data
        report_data = {
            'summary': summary,
            'scan_results': [r.to_dict() for r in scan_results],
            'evaluation_results': [r.to_dict() for r in evaluation_results]
        }
        
        if remediation_results:
            report_data['remediation_results'] = [r.to_dict() for r in remediation_results]
        
        # Format output
        if output_format == 'json':
            return json.dumps(report_data, indent=2)
        elif output_format == 'yaml':
            return yaml.dump(report_data, default_flow_style=False)
        else:
            # Text format
            lines = []
            lines.append("=" * 60)
            lines.append("VulnGuard Compliance Report")
            lines.append("=" * 60)
            lines.append("")
            lines.append("Summary:")
            lines.append(f"  Total Rules: {summary['total_rules']}")
            lines.append(f"  Compliant: {summary['compliant_count']}")
            lines.append(f"  Non-Compliant: {summary['non_compliant_count']}")
            lines.append(f"  Compliance: {summary['compliance_percentage']}%")
            lines.append("")
            lines.append("Risk Distribution:")
            for risk, count in summary['risk_distribution'].items():
                lines.append(f"  {risk}: {count}")
            lines.append("")
            lines.append("Detailed Results:")
            lines.append("-" * 60)
            
            for scan_result, eval_result in zip(scan_results, evaluation_results):
                lines.append(f"Rule: {scan_result.rule_id} ({scan_result.benchmark})")
                lines.append(f"  Compliant: {scan_result.compliant}")
                lines.append(f"  Severity: {eval_result.severity}")
                lines.append(f"  Risk Level: {eval_result.risk_level}")
                lines.append(f"  Expected: {scan_result.expected_state}")
                lines.append(f"  Actual: {scan_result.actual_state}")
                if not scan_result.compliant:
                    lines.append(f"  Check Output: {scan_result.check_output}")
                lines.append("")
            
            return '\n'.join(lines)


# CLI Interface
@click.group()
@click.version_option(version='1.0.0', prog_name='VulnGuard')
def cli():
    """
    VulnGuard - Linux Security Compliance Agent
    
    A production-grade security compliance agent that audits, evaluates,
    and remediates systems against CIS Benchmarks and DISA STIG standards.
    """
    pass


@cli.command()
@click.option(
    '--rule-id',
    '-r',
    multiple=True,
    help='Specific rule ID(s) to scan. Can be specified multiple times.'
)
@click.option(
    '--output',
    '-o',
    type=click.Path(),
    help='Output file path for the report.'
)
@click.option(
    '--format',
    '-f',
    type=click.Choice(['json', 'yaml', 'text']),
    default='json',
    help='Output format (default: json).'
)
def scan(rule_id: tuple, output: Optional[str], format: str):
    """
    Scan system for compliance issues.
    
    Scans the system against CIS and STIG benchmarks and generates
    a compliance report.
    """
    orchestrator = VulnGuardOrchestrator()
    
    # Run scan pipeline
    scan_results, evaluation_results, ai_advisories = orchestrator.run_scan(
        rule_ids=list(rule_id) if rule_id else None
    )
    
    # Generate report
    report = orchestrator.generate_report(
        scan_results=scan_results,
        evaluation_results=evaluation_results,
        output_format=format
    )
    
    # Output report
    if output:
        with open(output, 'w') as f:
            f.write(report)
        click.echo(f"Report saved to: {output}")
    else:
        click.echo(report)


@cli.command()
@click.option(
    '--rule-id',
    '-r',
    multiple=True,
    help='Specific rule ID(s) to remediate. Can be specified multiple times.'
)
@click.option(
    '--mode',
    '-m',
    type=click.Choice(['dry-run', 'commit']),
    default='dry-run',
    help='Remediation mode (default: dry-run).'
)
@click.option(
    '--force',
    is_flag=True,
    help='Force remediation even if approval is required.'
)
@click.option(
    '--output',
    '-o',
    type=click.Path(),
    help='Output file path for the report.'
)
@click.option(
    '--format',
    '-f',
    type=click.Choice(['json', 'yaml', 'text']),
    default='json',
    help='Output format (default: json).'
)
def remediate(rule_id: tuple, mode: str, force: bool, output: Optional[str], format: str):
    """
    Remediate non-compliant security issues.
    
    Scans, evaluates, and applies remediation for non-compliant rules.
    Default mode is dry-run for safety.
    """
    orchestrator = VulnGuardOrchestrator()
    
    # Run scan pipeline
    scan_results, evaluation_results, ai_advisories = orchestrator.run_scan(
        rule_ids=list(rule_id) if rule_id else None
    )
    
    # Run remediation
    remediation_results = orchestrator.run_remediation(
        scan_results=scan_results,
        evaluation_results=evaluation_results,
        ai_advisories=ai_advisories,
        mode=mode,
        force=force
    )
    
    # Generate report
    report = orchestrator.generate_report(
        scan_results=scan_results,
        evaluation_results=evaluation_results,
        remediation_results=remediation_results,
        output_format=format
    )
    
    # Output report
    if output:
        with open(output, 'w') as f:
            f.write(report)
        click.echo(f"Report saved to: {output}")
    else:
        click.echo(report)


@cli.command()
@click.option(
    '--benchmark-dir',
    '-b',
    type=click.Path(),
    default='vulnguard/configs/benchmarks',
    help='Directory containing benchmark rules.'
)
def list_rules(benchmark_dir: str):
    """
    List available benchmark rules.
    
    Displays all available CIS and STIG benchmark rules.
    """
    benchmark_path = Path(benchmark_dir)
    
    if not benchmark_path.exists():
        click.echo(f"Error: Benchmark directory not found: {benchmark_dir}", err=True)
        sys.exit(1)
    
    click.echo("Available Benchmark Rules:")
    click.echo("=" * 60)
    
    # List YAML files
    yaml_files = list(benchmark_path.glob('*.yaml')) + list(benchmark_path.glob('*.yml'))
    
    if not yaml_files:
        click.echo("No benchmark rules found.")
        return
    
    for yaml_file in sorted(yaml_files):
        try:
            with open(yaml_file, 'r') as f:
                rule_data = yaml.safe_load(f)
            
            click.echo(f"\nRule: {yaml_file.stem}")
            click.echo(f"  Benchmark: {rule_data.get('benchmark', 'N/A')}")
            click.echo(f"  Title: {rule_data.get('title', 'N/A')}")
            click.echo(f"  Severity: {rule_data.get('severity', 'N/A')}")
            click.echo(f"  OS Compatibility: {', '.join(rule_data.get('os_compatibility', []))}")
        except Exception as e:
            click.echo(f"\nRule: {yaml_file.stem}")
            click.echo(f"  Error loading: {e}")


@cli.command()
def version():
    """
    Display VulnGuard version information.
    """
    click.echo("VulnGuard v1.0.0")
    click.echo("Linux Security Compliance Agent")
    click.echo("")
    click.echo("Supported Benchmarks:")
    click.echo("  - CIS Benchmarks")
    click.echo("  - DISA STIG")


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == '__main__':
    main()
