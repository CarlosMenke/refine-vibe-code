"""LLM-based checker for naming conventions and code style."""

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from ..base import BaseChecker
from refine.core.results import Finding, Severity, FindingType, Location, Fix, FixType, Evidence
from refine.providers import get_provider

if TYPE_CHECKING:
    from refine.ui.printer import Printer


class NamingVibeChecker(BaseChecker):
    """Checker that uses LLM to analyze naming conventions and code style."""

    def __init__(self):
        super().__init__(
            name="naming_vibe",
            description="Uses LLM to analyze naming conventions and code style for AI-generated patterns",
            is_classical=False
        )

    def _get_supported_extensions(self) -> List[str]:
        return [".py"]

    def check_file(self, file_path: Path, content: str, printer: Optional["Printer"] = None) -> List[Finding]:
        """Use LLM to analyze code for naming and style issues."""
        findings = []

        try:
            # Get LLM provider
            provider = get_provider()

            # Sample content to avoid timeout with large files
            sampled_content = self._sample_content(content)

            # Create analysis prompt
            prompt = self._create_analysis_prompt(file_path, sampled_content)

            # Get LLM analysis
            response = provider.analyze_code(prompt)

            # Debug output
            if printer:
                printer.print_debug(f"LLM response for {file_path.name}: {response[:1000]}...")

            # Parse response and create findings
            findings.extend(self._parse_llm_response(response, file_path, content, printer))

        except Exception as e:
            # If LLM analysis fails, don't create findings
            if printer:
                printer.print_debug(f"LLM analysis failed for {file_path.name}: {e}")
            pass

        return findings

    def _extract_code_snippet(self, lines: List[str], line_number: int) -> str:
        """Extract a 1-2 line code snippet around the issue line."""
        if not lines or line_number < 1 or line_number > len(lines):
            return ""

        # Convert to 0-based indexing
        idx = line_number - 1

        # Get the problematic line and maybe one context line
        snippet_lines = []

        # Add the problematic line
        if idx < len(lines):
            snippet_lines.append(lines[idx])

        # Add one line of context if available (before or after)
        if idx > 0 and not lines[idx-1].strip():  # If previous line is empty, add next line
            if idx + 1 < len(lines):
                snippet_lines.append(lines[idx + 1])
        elif idx + 1 < len(lines) and not lines[idx + 1].strip():  # If next line is empty, add previous line
            if idx > 0:
                snippet_lines.insert(0, lines[idx - 1])

        # Join with newlines, but limit to 2 lines max
        return '\n'.join(snippet_lines[:2])

    def _sample_content(self, content: str) -> str:
        """Sample content to avoid timeout with large files."""
        lines = content.splitlines()
        if len(lines) <= 100:
            return content

        # For large files, sample representative sections
        # Keep the first 50 lines, then sample every 10th line, then last 50 lines
        sampled_lines = []

        # First 50 lines
        sampled_lines.extend(lines[:50])

        # Sample from middle (every 10th line)
        middle_start = 50
        middle_end = len(lines) - 50
        if middle_end > middle_start:
            for i in range(middle_start, middle_end, 10):
                sampled_lines.append(lines[i])

        # Last 50 lines
        sampled_lines.extend(lines[-50:])

        sampled_content = '\n'.join(sampled_lines)
        return sampled_content

    def _add_line_numbers(self, content: str) -> str:
        """Add line numbers to code for LLM analysis."""
        lines = content.splitlines()
        numbered_lines = []
        for i, line in enumerate(lines, 1):
            numbered_lines.append(f"{i:2d}: {line}")
        return '\n'.join(numbered_lines)

    def _create_analysis_prompt(self, file_path: Path, content: str) -> str:
        """Create a prompt for LLM analysis of naming and style."""
        return f"""Analyze this Python code for naming conventions, style, and potential AI-generation indicators. Look for:

1. Inconsistent naming conventions (camelCase vs snake_case, etc.)
2. Generic or robotic variable/function names
3. Overly complex or unnecessary abstractions
4. Code patterns typical of AI generation
5. Poor variable naming that doesn't convey intent
6. Inconsistent code style within the file
7. Redundant or verbose naming patterns

Code file: {file_path.name}

Code with line numbers:
{self._add_line_numbers(content)}

CRITICAL: For each issue found, you MUST provide the EXACT line number where the problematic code appears. Look at the line numbers in the code above and reference them precisely.

Provide your analysis in the following JSON format:
{{
  "issues": [
    {{
      "type": "naming|style|ai_pattern",
      "severity": "low|medium|high",
      "title": "Brief title",
      "description": "Detailed description - include the exact variable/function name and what it should be",
      "line_number": 42,  // MUST be the exact line number from the code above
      "confidence": 0.8,
      "current_name": "oldName",
      "suggested_name": "newDescriptiveName",
      "category": "variable|function|class|method"
    }}
  ]
}}

Focus on actual issues. If no significant issues are found, return {{"issues": []}}."""

    def _parse_llm_response(self, response: str, file_path: Path, content: str, printer: Optional["Printer"] = None) -> List[Finding]:
        """Parse LLM response and create findings."""
        findings = []

        try:
            import json

            # Strip markdown code blocks if present
            cleaned_response = response.strip()
            if cleaned_response.startswith('```json'):
                cleaned_response = cleaned_response[7:]
            if cleaned_response.endswith('```'):
                cleaned_response = cleaned_response[:-3]
            cleaned_response = cleaned_response.strip()

            # Try to parse JSON response
            data = json.loads(cleaned_response)

            for issue in data.get("issues", []):
                finding = self._create_finding_from_issue(issue, file_path, content)
                if finding:
                    findings.append(finding)

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            # If JSON parsing fails, try text parsing
            if printer and printer.debug:
                printer.print_debug(f"JSON parsing failed: {e}, trying text parsing")
                printer.print_debug(f"Raw response: {response[:1000]}...")
            findings.extend(self._parse_text_response(response, file_path, content))

        return findings

    def _create_finding_from_issue(self, issue: dict, file_path: Path, content: str) -> Finding:
        """Create a finding from a parsed issue."""
        severity_map = {
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }

        type_map = {
            "naming": FindingType.STYLE_ISSUE,
            "style": FindingType.STYLE_ISSUE,
            "ai_pattern": FindingType.AI_GENERATED,
        }

        # Determine line number with validation
        line_number = issue.get("line_number", 1)
        lines = content.splitlines()
        if line_number < 1 or line_number > len(lines):
            # Try to find the line containing the problematic name
            current_name = issue.get("current_name", "")
            if current_name:
                for i, line in enumerate(lines, 1):
                    if current_name in line:
                        line_number = i
                        break
            else:
                line_number = 1

        # Extract code snippet (1-2 lines around the issue)
        code_snippet = self._extract_code_snippet(lines, line_number)

        # Create description with suggestions
        description = issue.get("description", "LLM detected a naming or style issue")

        if issue.get("suggested_name"):
            description += f" Consider renaming to: {issue['suggested_name']}"

        # Determine fix type and prompt
        fix_prompt = "Review and improve the naming or style"
        if issue.get("suggested_name") and issue.get("current_name"):
            fix_prompt = f"Rename '{issue['current_name']}' to '{issue['suggested_name']}'"

        return Finding(
            id=f"naming_vibe_{file_path.name}_{line_number}_{hash(issue.get('title', '')) % 1000}",
            title=issue.get("title", "Naming/Style Issue"),
            description=description,
            severity=severity_map.get(issue.get("severity", "low"), Severity.LOW),
            type=type_map.get(issue.get("type", "naming"), FindingType.STYLE_ISSUE),
            location=Location(
                file=file_path,
                line_start=line_number,
            ),
            checker_name=self.name,
            code_snippet=code_snippet,  # Add the code snippet
            evidence=[Evidence(
                type="llm_analysis",
                description=f"LLM analysis: {issue.get('description', '')}",
                confidence=float(issue.get("confidence", 0.7)),
                details=issue
            )],
            fixes=[Fix(
                type=FixType.PROMPT,
                description="Improve naming or code style",
                prompt=fix_prompt
            )]
        )

    def _parse_text_response(self, response: str, file_path: Path, content: str) -> List[Finding]:
        """Fallback parsing for non-JSON LLM responses."""
        findings = []

        # Look for naming/style related keywords
        lines = response.splitlines()
        current_issue = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Look for issue indicators
            if any(keyword in line.lower() for keyword in [
                "naming:", "name:", "variable:", "function:", "style:", "convention:"
            ]):
                if current_issue:
                    findings.append(self._create_finding_from_text(current_issue, file_path))

                current_issue = {"description": line, "line_number": 1, "confidence": 0.6}
            elif current_issue:
                if "line" in line.lower() and any(char.isdigit() for char in line):
                    # Try to extract line number
                    import re
                    match = re.search(r'line\s*(\d+)', line, re.IGNORECASE)
                    if match:
                        current_issue["line_number"] = int(match.group(1))

                current_issue["description"] += " " + line

        # Add the last issue
        if current_issue:
            findings.append(self._create_finding_from_text(current_issue, file_path))

        return findings

    def _create_finding_from_text(self, issue: dict, file_path: Path) -> Finding:
        """Create a finding from text-based issue description."""
        return Finding(
            id=f"naming_vibe_text_{file_path.name}_{issue.get('line_number', 1)}_{hash(str(issue)) % 1000}",
            title="Naming/Style Issue Detected",
            description=issue.get("description", "LLM detected a naming or style issue"),
            severity=Severity.LOW,
            type=FindingType.STYLE_ISSUE,
            location=Location(
                file=file_path,
                line_start=issue.get("line_number", 1),
            ),
            checker_name=self.name,
            evidence=[Evidence(
                type="llm_analysis",
                description=issue.get("description", ""),
                confidence=issue.get("confidence", 0.6),
            )],
            fixes=[Fix(
                type=FixType.PROMPT,
                description="Review naming and style",
                prompt="Review the code for better naming conventions and style consistency"
            )]
        )





