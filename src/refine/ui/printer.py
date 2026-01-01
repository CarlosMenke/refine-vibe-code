"""Rich-based terminal output for Refine Vibe Code."""

import json
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn

from ..core.results import ScanResults, Finding, Severity


class Printer:
    """Handles terminal output formatting with Rich."""

    def __init__(self, output_format: str = "rich", verbose: bool = False, color: bool = True):
        self.output_format = output_format
        self.verbose = verbose
        self.color = color
        # Use responsive width with a reasonable minimum and maximum
        terminal_width = Console().size.width if hasattr(Console(), 'size') else 120
        width = min(max(terminal_width, 80), 140)  # Between 80 and 140 chars
        self.console = Console(force_terminal=color, width=width)

    def print_header(self, title: str) -> None:
        """Print application header."""
        if self.output_format == "rich":
            header = Panel.fit(
                f"[bold blue]{title}[/bold blue]\n[dim]Identify AI-generated code and bad coding patterns[/dim]",
                border_style="blue"
            )
            self.console.print(header)
        else:
            self.console.print(f"{title}")
            self.console.print("Identify AI-generated code and bad coding patterns")

    def print_status(self, message: str) -> None:
        """Print status message."""
        if self.output_format == "rich":
            self.console.print(f"[dim]{message}[/dim]")
        else:
            self.console.print(message)

    def print_warning(self, message: str) -> None:
        """Print warning message."""
        if self.output_format == "rich":
            self.console.print(f"[yellow]Warning:[/yellow] {message}")
        else:
            self.console.print(f"Warning: {message}")

    def print_error(self, message: str) -> None:
        """Print error message."""
        if self.output_format == "rich":
            self.console.print(f"[red]Error:[/red] {message}")
        else:
            self.console.print(f"Error: {message}")

    def print_results(self, results: ScanResults, fix: bool = False) -> None:
        """Print scan results."""
        if self.output_format == "json":
            self._print_json_results(results)
        elif self.output_format == "plain":
            self._print_plain_results(results)
        else:
            self._print_rich_results(results, fix)

    def _print_rich_results(self, results: ScanResults, fix: bool = False) -> None:
        """Print results using Rich formatting."""
        # Enhanced summary panel with icons and better colors
        self._print_enhanced_summary(results)

        # Findings display
        if results.findings:
            self._print_findings_cards(results.findings)
        else:
            self._print_success_message()

    def _print_enhanced_summary(self, results: ScanResults) -> None:
        """Print an enhanced summary with icons and better styling."""
        summary = results.summary()

        # Create a beautiful summary with icons
        summary_lines = [
            f"📁 [bold cyan]Files scanned:[/bold cyan] {results.files_scanned}",
            f"⏭️  [bold cyan]Files skipped:[/bold cyan] {results.files_skipped}",
            f"🔍 [bold cyan]Total findings:[/bold cyan] {len(results.findings)}",
            f"⚡ [bold cyan]Scan time:[/bold cyan] {results.scan_time:.2f}s"
        ]

        # Add severity breakdown with icons and colors
        severity_breakdown = summary.get("severity_breakdown", {})
        if severity_breakdown:
            severity_lines = []
            for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
                if severity.value in severity_breakdown:
                    count = severity_breakdown[severity.value]
                    icon = self._get_severity_icon(severity.value)
                    color = self._get_severity_color(severity.value)
                    severity_lines.append(f"{icon} [{color}]{severity.value.title()}: {count}[/{color}]")

            if severity_lines:
                summary_lines.append("")
                summary_lines.append("[bold]📊 Findings by severity:[/bold]")
                summary_lines.extend(severity_lines)

        summary_panel = Panel(
            "\n".join(summary_lines),
            title="[bold green]🚀 Scan Summary[/bold green]",
            border_style="green",
            title_align="left"
        )
        self.console.print(summary_panel)

    def _print_findings_cards(self, findings: List[Finding]) -> None:
        """Print findings as beautiful cards grouped by severity."""
        # Group findings by severity
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        grouped_findings = {}

        for finding in findings:
            severity = finding.severity.value
            if severity not in grouped_findings:
                grouped_findings[severity] = []
            grouped_findings[severity].append(finding)

        # Sort groups by severity (most severe first)
        sorted_groups = sorted(grouped_findings.keys(), key=lambda s: severity_order.get(Severity(s), 5))

        self.console.print("\n")  # Add some space

        for severity in sorted_groups:
            findings_in_group = grouped_findings[severity]
            self._print_severity_group(severity, findings_in_group)

    def _print_severity_group(self, severity: str, findings: List[Finding]) -> None:
        """Print all findings for a specific severity level."""
        severity_color = self._get_severity_color(severity)
        severity_icon = self._get_severity_icon(severity)

        # Group header
        group_title = f"{severity_icon} {severity.upper()} ISSUES ({len(findings)})"
        self.console.print(f"\n[bold {severity_color}]{group_title}[/bold {severity_color}]")
        self.console.print(f"[dim {severity_color}]{'─' * len(group_title)}[/dim {severity_color}]")

        # Print each finding as a card
        for i, finding in enumerate(findings, 1):
            self._print_finding_card(finding, i)

    def _print_finding_card(self, finding: Finding, index: int) -> None:
        """Print a single finding as a beautiful card."""
        severity_color = self._get_severity_color(finding.severity.value)
        type_icon = self._get_type_icon(finding.type.value)

        # Card content
        card_lines = [
            f"[bold]{finding.title}[/bold]",
            f"[dim]📍 Location:[/dim] [cyan]{finding.location.file.name}[/cyan]:[yellow]{finding.location.line_start}[/yellow]",
            f"[dim]{type_icon} Type:[/dim] {finding.type.value.replace('_', ' ').title()}",
            f"[dim]🔧 Checker:[/dim] [magenta]{finding.checker_name}[/magenta]",
        ]

        # Add confidence if available
        confidence = finding.confidence_score()
        if confidence > 0:
            confidence_color = "green" if confidence >= 0.8 else "yellow" if confidence >= 0.6 else "red"
            card_lines.append(f"[dim]🎯 Confidence:[/dim] [{confidence_color}]{confidence:.1%}[/{confidence_color}]")

        # Add description (full, no truncation)
        if finding.description:
            card_lines.append(f"[dim]📝 Description:[/dim] {finding.description}")

        # Add evidence if available
        if finding.evidence and self.verbose:
            evidence = finding.evidence[0]  # Show primary evidence
            card_lines.append(f"[dim]🔍 Evidence:[/dim] {evidence.description}")

        # Add fix suggestion if available
        if finding.fixes and self.verbose:
            fix = finding.fixes[0]  # Show primary fix
            card_lines.append(f"[dim]💡 Suggestion:[/dim] {fix.prompt}")

        # Create the card panel
        card_content = "\n".join(card_lines)
        card_panel = Panel(
            card_content,
            border_style=severity_color,
            title=f"[bold]{index}[/bold]",
            title_align="left",
            padding=(0, 1)
        )

        self.console.print(card_panel)
        self.console.print()  # Add space between cards

    def _print_success_message(self) -> None:
        """Print a success message when no issues are found."""
        success_panel = Panel(
            "[bold green]🎉 Excellent! No issues found in your codebase.[/bold green]\n\n"
            "[dim]Your code looks clean and follows good practices. Keep up the great work![/dim]",
            title="[bold green]✅ All Clear[/bold green]",
            border_style="green",
            title_align="center"
        )
        self.console.print("\n")
        self.console.print(success_panel)

    def _print_detailed_findings(self, findings: List[Finding]) -> None:
        """Print detailed information about each finding."""
        for i, finding in enumerate(findings, 1):
            self.console.print(f"\n[bold]{i}. {finding.title}[/bold]")
            self.console.print(f"   [dim]Location:[/dim] {finding.location}")
            self.console.print(f"   [dim]Checker:[/dim] {finding.checker_name}")
            self.console.print(f"   [dim]Confidence:[/dim] {finding.confidence_score():.2f}")

            if finding.evidence:
                evidence = finding.evidence[0]  # Show primary evidence
                self.console.print(f"   [dim]Evidence:[/dim] {evidence.description}")

            if finding.fixes:
                fix = finding.fixes[0]  # Show primary fix
                self.console.print(f"   [dim]Suggestion:[/dim] {fix.prompt}")

    def _print_recommendations(self, recommendations: List[str]) -> None:
        """Print recommendations panel."""
        if not recommendations:
            return

        rec_text = "\n".join(f"• {rec}" for rec in recommendations)
        rec_panel = Panel(rec_text, title="Recommendations", border_style="yellow")
        self.console.print("\n")
        self.console.print(rec_panel)

    def _print_json_results(self, results: ScanResults) -> None:
        """Print results in JSON format."""
        # Convert results to dict
        results_dict = {
            "summary": results.summary(),
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "type": f.type.value,
                    "location": {
                        "file": str(f.location.file),
                        "line_start": f.location.line_start,
                        "line_end": f.location.line_end,
                    },
                    "checker_name": f.checker_name,
                    "confidence": f.confidence_score(),
                    "fixes": [
                        {
                            "type": fix.type.value,
                            "description": fix.description,
                            "prompt": fix.prompt,
                        } for fix in f.fixes
                    ]
                } for f in results.findings
            ],
            "timestamp": results.timestamp.isoformat(),
        }

        self.console.print(json.dumps(results_dict, indent=2, ensure_ascii=False))

    def _print_plain_results(self, results: ScanResults) -> None:
        """Print results in plain text format."""
        summary = results.summary()

        self.console.print("SCAN SUMMARY")
        self.console.print("=" * 50)
        self.console.print(f"Files scanned: {results.files_scanned}")
        self.console.print(f"Files skipped: {results.files_skipped}")
        self.console.print(f"Total findings: {len(results.findings)}")
        self.console.print(f"Scan time: {results.scan_time:.2f}s")

        if summary.get("severity_breakdown"):
            self.console.print("\nFindings by severity:")
            for severity, count in summary["severity_breakdown"].items():
                self.console.print(f"  {severity.title()}: {count}")

        if results.findings:
            self.console.print("\nFINDINGS")
            self.console.print("=" * 50)

            severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
            sorted_findings = sorted(results.findings, key=lambda f: severity_order.get(f.severity, 5))

            for i, finding in enumerate(sorted_findings, 1):
                self.console.print(f"{i}. [{finding.severity.value.upper()}] {finding.title}")
                self.console.print(f"   File: {finding.location.file}")
                self.console.print(f"   Line: {finding.location.line_start}")
                self.console.print(f"   Type: {finding.type.value.replace('_', ' ').title()}")
                self.console.print(f"   Checker: {finding.checker_name}")
                self.console.print(f"   Description: {finding.description}")

                if finding.fixes:
                    self.console.print(f"   Suggestion: {finding.fixes[0].prompt}")

                self.console.print()

    def _get_severity_color(self, severity: str) -> str:
        """Get Rich color for severity level."""
        color_map = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "dim blue",
        }
        return color_map.get(severity.lower(), "white")

    def _get_severity_icon(self, severity: str) -> str:
        """Get icon for severity level."""
        icon_map = {
            "critical": "🚨",
            "high": "🔴",
            "medium": "🟡",
            "low": "🔵",
            "info": "ℹ️",
        }
        return icon_map.get(severity.lower(), "❓")

    def _get_type_icon(self, finding_type: str) -> str:
        """Get icon for finding type."""
        icon_map = {
            "ai_generated": "🤖",
            "bad_practice": "👎",
            "code_smell": "🦨",
            "security_issue": "🔒",
            "performance_issue": "⚡",
            "style_issue": "🎨",
        }
        return icon_map.get(finding_type.lower(), "⚠️")

    def create_progress(self) -> Progress:
        """Create a progress bar for long operations."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True,
        )


