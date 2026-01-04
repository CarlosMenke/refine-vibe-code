"""Rich-based terminal output for Refine Vibe Code."""

import json
import re
import textwrap
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
from rich.syntax import Syntax
from pygments.lexers import get_lexer_by_name, guess_lexer
from pygments.util import ClassNotFound

from ..core.results import ScanResults, Finding, Severity


class Printer:
    """Handles terminal output formatting with Rich."""

    # Category definitions for grouping findings
    CATEGORIES = {
        "Security Issues": {
            "description": "Security vulnerabilities, hardcoded secrets, and unsafe practices",
            "checkers": [
                "hardcoded_secrets",
                "sql_injection",
                "dangerous_ai_logic",
                "contextual_sqli_audit"
            ],
            "icon": "🔒",
            "color": "red"
        },
        "Code Quality": {
            "description": "Code style, naming conventions, and documentation quality",
            "checkers": [
                "vibe_naming",
                "comment_quality",
                "edge_cases"
            ],
            "icon": "🎨",
            "color": "blue"
        },
        "Package & Dependencies": {
            "description": "Package management, imports, and dependency issues",
            "checkers": [
                "package_check",
                "dependency_validation"
            ],
            "icon": "📦",
            "color": "green"
        },
        "Best Practices": {
            "description": "Code patterns, boilerplate detection, and general best practices",
            "checkers": [
                "boilerplate"
            ],
            "icon": "✨",
            "color": "yellow"
        }
    }

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

    def _get_finding_category(self, checker_name: str) -> str:
        """Get the category for a given checker name."""
        for category_name, category_info in self.CATEGORIES.items():
            if checker_name in category_info["checkers"]:
                return category_name
        return "Other Issues"

    def _group_findings_by_category(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Group findings by their categories."""
        grouped = {}
        for finding in findings:
            category = self._get_finding_category(finding.checker_name)
            if category not in grouped:
                grouped[category] = []
            grouped[category].append(finding)
        return grouped

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

    def print_llm_warning_box(self) -> None:
        """Print beautiful warning box for LLM provider configuration issues."""
        warning_content = (
            "[bold yellow]🤖 LLM-based checkers are enabled but no LLM provider is configured![/bold yellow]\n\n"
            "[dim]FALLING BACK TO HARDCODED MOCK ANALYSIS[/dim]\n\n"
            "This will only detect obvious patterns and may miss many issues.\n"
            "For proper AI-generated code detection, configure an LLM provider:\n\n"
            "• [bold cyan]OpenAI:[/bold cyan] Set [green]OPENAI_API_KEY[/green] environment variable\n"
            "• [bold cyan]Google:[/bold cyan] Set [green]GOOGLE_API_KEY[/green] + configure provider in [magenta]refine.toml[/magenta]\n\n"
            "Run [bold]'uv run refine init'[/bold] to generate a configuration file."
        )

        warning_panel = Panel(
            warning_content,
            title="[bold red]⚠️  CONFIGURATION WARNING[/bold red]",
            title_align="center",
            border_style="yellow",
            padding=(1, 2),
            expand=False
        )

        self.console.print("\n")
        self.console.print(warning_panel)
        self.console.print("\n")

    def print_llm_error_box(self, error_message: str) -> None:
        """Print big warning box when LLM is configured but fails to work."""
        # Extract the most relevant part of the error
        error_display = str(error_message)
        if len(error_display) > 200:
            error_display = error_display[:200] + "..."

        warning_content = (
            "[bold red]🚨 LLM PROVIDER FAILED![/bold red]\n\n"
            f"[dim]Error:[/dim] [yellow]{error_display}[/yellow]\n\n"
            "[dim]FALLING BACK TO BASIC PATTERN MATCHING[/dim]\n\n"
            "The LLM provider is configured but not working. Common causes:\n\n"
            "• [bold cyan]Invalid API key:[/bold cyan] Check that your API key is correct and active\n"
            "• [bold cyan]Wrong model name:[/bold cyan] Verify the model name in [magenta]refine.toml[/magenta]\n"
            "• [bold cyan]Rate limit exceeded:[/bold cyan] Wait a moment and try again\n"
            "• [bold cyan]Network issues:[/bold cyan] Check your internet connection\n"
            "• [bold cyan]API quota exhausted:[/bold cyan] Check your billing/usage limits\n\n"
            "[dim]Check your configuration in [magenta]refine.toml[/magenta] or environment variables.[/dim]"
        )

        warning_panel = Panel(
            warning_content,
            title="[bold red]⚠️  LLM ERROR - ANALYSIS DEGRADED[/bold red]",
            title_align="center",
            border_style="red",
            padding=(1, 2),
            expand=False
        )

        self.console.print("\n")
        self.console.print(warning_panel)
        self.console.print("\n")

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
        """Print findings as beautiful cards grouped by category."""
        # Group findings by category
        grouped_findings = self._group_findings_by_category(findings)

        # Define category priority order (Security first, then Code Quality, etc.)
        category_priority = {
            "Security Issues": 0,
            "Code Quality": 1,
            "Package & Dependencies": 2,
            "Best Practices": 3,
            "Other Issues": 4
        }

        # Sort categories by priority
        sorted_categories = sorted(
            grouped_findings.keys(),
            key=lambda cat: category_priority.get(cat, 5)
        )

        self.console.print("\n")  # Add some space

        for category_name in sorted_categories:
            findings_in_category = grouped_findings[category_name]

            # Sort findings within each category by severity (decreasing) then confidence (decreasing)
            severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
            sorted_findings = sorted(
                findings_in_category,
                key=lambda f: (severity_order.get(f.severity, 5), -f.confidence_score())
            )

            self._print_category_group(category_name, sorted_findings)

    def _print_category_group(self, category_name: str, findings: List[Finding]) -> None:
        """Print all findings for a specific category."""
        # Get category info
        category_info = self.CATEGORIES.get(category_name, {
            "icon": "⚠️",
            "color": "yellow",
            "description": "Miscellaneous issues"
        })

        category_icon = category_info["icon"]
        category_color = category_info["color"]
        category_description = category_info["description"]

        # Category header with icon and description
        header_title = f"{category_icon} {category_name} ({len(findings)} findings)"
        self.console.print(f"\n[bold {category_color}]{header_title}[/bold {category_color}]")
        self.console.print(f"[dim {category_color}]{'─' * len(header_title)}[/dim {category_color}]")
        self.console.print(f"[dim {category_color}]{category_description}[/dim {category_color}]")

        # Group findings by file within this category
        findings_by_file = {}
        for finding in findings:
            file_path = str(finding.location.file)
            if file_path not in findings_by_file:
                findings_by_file[file_path] = []
            findings_by_file[file_path].append(finding)

        # Sort files alphabetically
        sorted_files = sorted(findings_by_file.keys())

        # Print each file's findings within this category
        for file_path in sorted_files:
            file_findings = findings_by_file[file_path]
            self._print_file_group_within_category(file_path, file_findings)

    def _print_file_group_within_category(self, file_path: str, findings: List[Finding]) -> None:
        """Print all findings for a specific file within a category."""
        # Get relative path for display
        relative_path = self._get_relative_path(Path(file_path))

        # Use file icon and consistent color for file headers
        file_icon = "📄"
        file_color = "bold cyan"

        # File header (indented slightly to show it's within a category)
        file_title = f"  {file_icon} {relative_path} ({len(findings)} findings)"
        self.console.print(f"\n[{file_color}]{file_title}[/{file_color}]")

        # Print each finding as a card (indented)
        for i, finding in enumerate(findings, 1):
            self._print_finding_card(finding, i, indent=True)

    def _print_finding_card(self, finding: Finding, index: int, indent: bool = False) -> None:
        """Print a single finding as a two-line compact message."""
        indent_prefix = "    " if indent else ""
        severity_color = self._get_severity_color(finding.severity.value)
        title_color = self._get_title_color(finding.type.value)

        # Get data
        confidence = finding.confidence_score()
        confidence_str = f"{confidence:.1%}" if confidence > 0 else ""

        # Create colored text objects for first line
        severity_text = Text(f"[{finding.severity.value.upper()}]", style=severity_color)
        title_text = Text(finding.title, style=title_color)
        checker_text = Text(f"[{finding.checker_name}]", style="magenta")
        confidence_text = Text(confidence_str, style="green") if confidence_str else Text("", style="")

        # Relative path with line number
        relative_path = f"{self._get_relative_path(finding.location.file)}:{finding.location.line_start}"
        location_text = Text(relative_path, style="cyan")

        # Print first line: main finding info (severity not indented)
        first_line = Text()
        first_line.append(severity_text)
        first_line.append(" ")
        first_line.append(checker_text)
        first_line.append(" ")
        first_line.append(title_text)
        if confidence_str:
            first_line.append(" ")
            first_line.append(confidence_text)
        first_line.append(" ")
        first_line.append(location_text)

        self.console.print(first_line)

        # Print second line: description (with proper wrapping)
        if finding.description and finding.description != finding.title:
            # Calculate available width for description (console width minus tab)
            available_width = self.console.width - 8  # Account for tab width

            # Wrap description text
            wrapped_lines = textwrap.wrap(finding.description, width=available_width)

            for line in wrapped_lines:
                description_line = Text("\t", style="dim")
                description_line.append(Text(line, style=""))
                self.console.print(description_line)

        # Print suggested name on new line if available (from evidence details)
        if finding.evidence:
            details = finding.evidence[0].details or {}
            suggested_name = details.get("suggested_name")
            if suggested_name:
                suggestion_line = Text("\t", style="dim")
                suggestion_line.append(Text("Rename to: ", style="dim"))
                suggestion_line.append(Text(suggested_name, style="bold green"))
                self.console.print(suggestion_line)

        # Print code snippet on new line if available
        if finding.code_snippet:
            formatted_snippet = '\n'.join(line.rstrip() for line in finding.code_snippet.split('\n'))

            # Safety limit: max 15 lines to prevent overflow
            lines = formatted_snippet.split('\n')
            if len(lines) > 15:
                formatted_snippet = '\n'.join(lines[:14]) + '\n...'
                lines = formatted_snippet.split('\n')

            # Use syntax highlighting
            self._print_code_snippet(formatted_snippet, finding.location.file)


    def _print_success_message(self) -> None:
        """Print a success message when no issues are found."""
        self.console.print("\n[bold green]🎉 Excellent! No issues found in your codebase.[/bold green]")

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

            # Group findings by category
            grouped_findings = self._group_findings_by_category(results.findings)

            # Define category priority order
            category_priority = {
                "Security Issues": 0,
                "Code Quality": 1,
                "Package & Dependencies": 2,
                "Best Practices": 3,
                "Other Issues": 4
            }

            # Sort categories by priority
            sorted_categories = sorted(
                grouped_findings.keys(),
                key=lambda cat: category_priority.get(cat, 5)
            )

            # Print format description (plain text)
            self.console.print("Format: [SEVERITY] [CHECKER] TITLE CONFIDENCE FULL_PATH:LINE")
            self.console.print()

            for category_name in sorted_categories:
                findings_in_category = grouped_findings[category_name]

                # Print category header
                category_info = self.CATEGORIES.get(category_name, {"icon": "⚠️", "description": "Miscellaneous issues"})
                self.console.print(f"\n{category_info['icon']} {category_name.upper()}")
                self.console.print(f"{'─' * (len(category_name) + 2)}")
                self.console.print(f"{category_info['description']}")
                self.console.print()

                # Sort findings within category by severity then confidence
                severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
                sorted_findings = sorted(
                    findings_in_category,
                    key=lambda f: (severity_order.get(f.severity, 5), -f.confidence_score())
                )

                for finding in sorted_findings:
                    confidence = finding.confidence_score()
                    confidence_str = f"{confidence:.1%}" if confidence > 0 else ""

                    # Format the output: [SEVERITY] [CHECKER] TITLE CONFIDENCE FULL_PATH:LINE
                    severity_bracket = f"[{finding.severity.value.upper()}]"
                    checker_bracket = f"[{finding.checker_name}]"
                    title_clean = finding.title
                    confidence_clean = confidence_str
                    # Relative path with line number at the end
                    relative_path = self._get_relative_path(finding.location.file)
                    full_path_clean = f"{relative_path}:{finding.location.line_start}"

                    # Combine all parts with spaces
                    line_parts = [severity_bracket, checker_bracket, title_clean]
                    if confidence_clean:
                        line_parts.append(confidence_clean)
                    line_parts.append(full_path_clean)
                    line = " ".join(line_parts)

                    self.console.print(line)

                    # Show description if available and different from title
                    if finding.description and finding.description != finding.title:
                        # Wrap description with proper indentation (6 spaces to align)
                        indent = "      "
                        wrapped_desc = finding.description.replace('\n', f'\n{indent}')
                        self.console.print(f"{indent}{wrapped_desc}")

                    # Show code snippet if available
                    if finding.code_snippet:
                        snippet_lines = finding.code_snippet.split('\n')
                        # Safety limit for plain text output
                        if len(snippet_lines) > 15:
                            snippet_lines = snippet_lines[:14] + ["..."]

                        # Add line numbers for plain text output
                        start_line = finding.location.line_start if finding.location.line_start else 1
                        max_line_width = len(str(start_line + len(snippet_lines) - 1))
                        for i, line in enumerate(snippet_lines):
                            line_num = start_line + i
                            if line == "...":
                                self.console.print(f"\t{line}")
                            else:
                                self.console.print(f"\t{line_num:>{max_line_width}}: {line}")
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

    def _print_code_snippet(self, code: str, file_path: Optional[Path] = None) -> None:
        """Print code snippet with syntax highlighting and line numbers."""
        if not code.strip():
            return

        # Determine the lexer based on file extension
        lexer = None
        if file_path:
            file_extension = file_path.suffix.lower()
            extension_to_lexer = {
                '.py': 'python',
                '.js': 'javascript',
                '.ts': 'typescript',
                '.java': 'java',
                '.cpp': 'cpp',
                '.c': 'c',
                '.cs': 'csharp',
                '.php': 'php',
                '.rb': 'ruby',
                '.go': 'go',
                '.rs': 'rust',
                '.sh': 'bash',
                '.sql': 'sql',
                '.html': 'html',
                '.css': 'css',
                '.json': 'json',
                '.xml': 'xml',
                '.yaml': 'yaml',
                '.yml': 'yaml',
                '.toml': 'toml',
                '.md': 'markdown',
            }

            lexer_name = extension_to_lexer.get(file_extension)
            if lexer_name:
                try:
                    lexer = get_lexer_by_name(lexer_name)
                except ClassNotFound:
                    pass

        # If we couldn't determine lexer from extension, try to guess
        if not lexer:
            try:
                lexer = guess_lexer(code)
            except ClassNotFound:
                # Fallback to plain text
                pass

        # Create syntax object without line numbers
        if lexer:
            syntax = Syntax(
                code,
                lexer,
                theme="monokai",  # Dark theme that works well in terminals
                line_numbers=False,
                word_wrap=False,
                code_width=self.console.width - 8,  # Leave some margin
            )
        else:
            # Fallback for unknown languages - plain text without line numbers
            syntax = Syntax(
                code,
                "text",
                theme="monokai",
                line_numbers=False,
                word_wrap=False,
                code_width=self.console.width - 8,
            )

        # Print the syntax-highlighted code
        self.console.print(syntax)

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


