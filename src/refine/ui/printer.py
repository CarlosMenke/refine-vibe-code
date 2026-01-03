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

    def __init__(self, output_format: str = "rich", verbose: bool = False, color: bool = True, debug: bool = False, root_path: Optional[Path] = None):
        self.output_format = output_format
        self.verbose = verbose
        self.color = color
        self.debug = debug
        self.root_path = root_path or Path.cwd()
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

    def print_file_status(self, message: str, file_path: Path) -> None:
        """Print status message with a file path, converting to relative path."""
        relative_path = self._get_relative_path(file_path)
        full_message = f"{message} {relative_path}"
        self.print_status(full_message)

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

    def print_debug(self, message: str) -> None:
        """Print debug message."""
        if self.debug:
            if self.output_format == "rich":
                self.console.print(f"[dim cyan]Debug:[/dim cyan] {message}")
            else:
                self.console.print(f"Debug: {message}")

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

        # For clean scans (no findings), use compact one-line summary
        if not results.findings:
            compact_summary = f"📁 [bold cyan]{results.files_scanned}[/bold cyan] files scanned, ⏭️ [bold cyan]{results.files_skipped}[/bold cyan] skipped, ⚡ [bold green]{results.scan_time:.2f}s[/bold green]"
            compact_panel = Panel(
                compact_summary,
                title="[bold green]✅ Clean Scan[/bold green]",
                border_style="green",
                title_align="center"
            )
            self.console.print(compact_panel)
            return

        # For scans with findings, use compact table format
        from rich.table import Table

        # Create compact table
        table = Table(show_header=True, header_style="bold cyan", show_edge=False, pad_edge=False)
        table.add_column("📁 Files", style="cyan", no_wrap=True)
        table.add_column("⏭️ Skipped", style="dim cyan", no_wrap=True)
        table.add_column("🔍 Findings", style="yellow", no_wrap=True)
        table.add_column("⚡ Time", style="green", no_wrap=True)

        # Add severity breakdown columns dynamically
        severity_breakdown = summary.get("severity_breakdown", {})
        severity_columns = {}
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if severity.value in severity_breakdown:
                count = severity_breakdown[severity.value]
                icon = self._get_severity_icon(severity.value)
                color = self._get_severity_color(severity.value)
                col_name = f"{icon} {severity.value.title()}"
                table.add_column(col_name, style=color, no_wrap=True)
                severity_columns[severity.value] = count

        # Prepare row data
        row_data = [
            str(results.files_scanned),
            str(results.files_skipped),
            str(len(results.findings)),
            f"{results.scan_time:.2f}s"
        ]

        # Add severity counts in order
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            if severity.value in severity_columns:
                row_data.append(str(severity_columns[severity.value]))

        table.add_row(*row_data)

        # Print table header
        self.console.print("[bold blue]🚀 Scan Summary[/bold blue]")
        self.console.print(table)

    def _print_findings_cards(self, findings: List[Finding]) -> None:
        """Print findings as beautiful cards grouped by file."""
        # Group findings by file
        grouped_findings = {}

        for finding in findings:
            file_path = str(finding.location.file)
            if file_path not in grouped_findings:
                grouped_findings[file_path] = []
            grouped_findings[file_path].append(finding)

        # Sort groups by file path (alphabetically)
        sorted_groups = sorted(grouped_findings.keys())

        self.console.print("\n")  # Add some space

        for file_path in sorted_groups:
            findings_in_group = grouped_findings[file_path]
            self._print_file_group(file_path, findings_in_group)

    def _print_file_group(self, file_path: str, findings: List[Finding]) -> None:
        """Print all findings for a specific file."""
        # Get relative path for display
        relative_path = self._get_relative_path(Path(file_path))

        # Use file icon and consistent color for file headers
        file_icon = "📄"
        file_color = "bold blue"

        # Group header
        group_title = f"{file_icon} {relative_path} ({len(findings)} findings)"
        self.console.print(f"\n[{file_color}]{group_title}[/{file_color}]")
        self.console.print(f"[dim blue]{'─' * len(group_title)}[/dim blue]")

        # Print each finding as a card
        for i, finding in enumerate(findings, 1):
            self._print_finding_card(finding, i)

    def _print_finding_card(self, finding: Finding, index: int) -> None:
        """Print a single finding as a two-line compact message."""
        severity_color = self._get_severity_color(finding.severity.value)
        title_color = self._get_title_color(finding.type.value)

        # Get data
        confidence = finding.confidence_score()
        confidence_str = f"{confidence:.1%}" if confidence > 0 else ""

        # Create colored text objects for first line
        severity_text = Text(f"[{finding.severity.value.upper()}]", style=severity_color)
        title_text = Text(f"[{finding.title}]", style=title_color)
        checker_text = Text(finding.checker_name, style="magenta")
        confidence_text = Text(confidence_str, style="green") if confidence_str else Text("", style="")

        # Relative path with line number
        relative_path = self._get_relative_path(finding.location.file)
        location_text = Text(f"{relative_path}:{finding.location.line_start}" if finding.location.line_start else relative_path, style="cyan")

        # Print first line: main finding info
        first_line = Text()
        first_line.append(severity_text)
        first_line.append(" ")
        first_line.append(title_text)
        first_line.append(" ")
        first_line.append(checker_text)
        if confidence_str:
            first_line.append(" ")
            first_line.append(confidence_text)
        first_line.append(" ")
        first_line.append(location_text)

        self.console.print(first_line)

        # Print second line: description and code snippet
        if finding.description or finding.code_snippet:
            second_line = Text("  ", style="dim")  # Indent with two spaces

            # Add description if different from title - use severity-appropriate color
            if finding.description and finding.description != finding.title:
                desc_color = self._get_description_color(finding.severity.value)
                second_line.append(Text(finding.description, style=desc_color))

            # Add code snippet if available
            if finding.code_snippet:
                if finding.description and finding.description != finding.title:
                    second_line.append(Text(" ", style="dim"))
                # Clean up the code snippet for inline display (remove extra whitespace)
                clean_snippet = finding.code_snippet.strip().replace('\n', ' ').replace('  ', ' ')
                if len(clean_snippet) > 60:  # Truncate if too long
                    clean_snippet = clean_snippet[:57] + "..."
                second_line.append(Text(f"`{clean_snippet}`", style="dim blue"))

            self.console.print(second_line)

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
                    "code_snippet": f.code_snippet,
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

            # Print format description (plain text)
            self.console.print("Format: [SEVERITY] [TITLE] CHECKER CONFIDENCE FULL_PATH:LINE")
            self.console.print()

            for i, finding in enumerate(sorted_findings, 1):
                confidence = finding.confidence_score()
                confidence_str = f"{confidence:.1%}" if confidence > 0 else ""

                # Format the output: [SEVERITY] [TITLE] CHECKER CONFIDENCE FULL_PATH:LINE
                severity_bracket = f"[{finding.severity.value.upper()}]"
                title_bracket = f"[{finding.title}]"
                checker_clean = finding.checker_name
                confidence_clean = confidence_str
                # Relative path with line number at the end
                relative_path = self._get_relative_path(finding.location.file)
                full_path_clean = f"{relative_path}:{finding.location.line_start}" if finding.location.line_start else relative_path

                # Combine all parts with spaces
                line_parts = [severity_bracket, title_bracket, checker_clean]
                if confidence_clean:
                    line_parts.append(confidence_clean)
                line_parts.append(full_path_clean)
                line = " ".join(line_parts)

                self.console.print(line)

                # Show description if available and different from title
                if finding.description and finding.description != finding.title:
                    self.console.print(f"\nExplanation: {finding.description}")

                # Show code snippet if available
                if finding.code_snippet:
                    self.console.print(f"\nCode snippet:")
                    for snippet_line in finding.code_snippet.split('\n'):
                        self.console.print(f"  {snippet_line}")
                    self.console.print()

    def _get_severity_color(self, severity: str) -> str:
        """Get Rich color for severity level."""
        color_map = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "orange1",
            "info": "dim blue",
        }
        return color_map.get(severity.lower(), "white")

    def _get_description_color(self, severity: str) -> str:
        """Get Rich color for finding description based on severity."""
        color_map = {
            "critical": "red",
            "high": "red",
            "medium": "yellow",
            "low": "yellow",  # Changed from dim yellow to regular yellow for better readability
            "info": "blue",
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

    def _get_title_color(self, finding_type: str) -> str:
        """Get color for finding type title."""
        color_map = {
            "ai_generated": "bold cyan",    # Bold cyan for AI-generated smells
            "bad_practice": "bold cyan",   # Bold cyan for standard bad patterns
            "code_smell": "bold cyan",     # Bold cyan for code smells
            "security_issue": "bold red",  # Keep security issues red
            "performance_issue": "bold cyan", # Bold cyan for performance issues
            "style_issue": "bold cyan",    # Bold cyan for style issues
        }
        return color_map.get(finding_type.lower(), "bold white")

    def _get_relative_path(self, file_path: Path) -> str:
        """Get relative path from root directory."""
        # If root_path is a file, use its parent directory as the effective root
        effective_root = self.root_path.parent if self.root_path.is_file() else self.root_path

        try:
            relative_path = file_path.relative_to(effective_root)
            # If relative path is just '.', use the filename for better terminal compatibility
            if str(relative_path) == '.':
                return file_path.name
            return str(relative_path)
        except ValueError:
            # If path is not relative to effective_root, return the filename or absolute path as fallback
            return file_path.name if file_path.is_file() else str(file_path)

    def create_progress(self) -> Progress:
        """Create a progress bar for long operations."""
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=self.console,
            transient=True,
        )


