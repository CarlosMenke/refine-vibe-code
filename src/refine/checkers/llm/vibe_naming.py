"""LLM-based checker for naming conventions and code style."""

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from .base import LLMBaseChecker
from refine.core.results import Finding, Severity, FindingType, Location, Fix, FixType, Evidence

if TYPE_CHECKING:
    from refine.ui.printer import Printer


class VibeNamingChecker(LLMBaseChecker):
    """Checker that uses LLM to analyze naming conventions and code style."""

    # Maximum lines per chunk to avoid LLM response truncation
    MAX_CHUNK_LINES = 150
    # Overlap between chunks to maintain context
    CHUNK_OVERLAP = 10

    def __init__(self):
        super().__init__(
            name="vibe_naming",
            description="Uses LLM to analyze naming conventions and code style for AI-generated patterns"
        )

    def _get_supported_extensions(self) -> List[str]:
        return [".py"]

    def _extract_code_snippet(self, content: str, line_number: int, context_lines: int = 1) -> str:
        """Extract a minimal but sufficient code snippet around the given line.

        Dynamically adjusts size based on content type and context_lines parameter.
        """
        lines = content.splitlines()
        if line_number < 1 or line_number > len(lines):
            return ""

        target_idx = line_number - 1  # Convert to 0-indexed
        target_line = lines[target_idx]

        # Determine snippet bounds based on context_lines
        start_idx = max(0, target_idx - context_lines)
        end_idx = min(len(lines), target_idx + context_lines + 1)

        # Extract and trim unnecessary blank lines at edges
        snippet_lines = lines[start_idx:end_idx]

        # Remove leading blank lines (but keep at least one context line before target)
        while len(snippet_lines) > 1 and not snippet_lines[0].strip():
            if start_idx + 1 < target_idx:
                snippet_lines = snippet_lines[1:]
                start_idx += 1
            else:
                break

        # Remove trailing blank lines
        while len(snippet_lines) > 1 and not snippet_lines[-1].strip():
            snippet_lines = snippet_lines[:-1]

        # Build numbered output
        numbered_lines = []
        for i, line in enumerate(snippet_lines, start_idx + 1):
            marker = ">" if i == line_number else ""
            numbered_lines.append(f"{marker:>1} {i:3d}| {line}")

        return "\n".join(numbered_lines)



    def _create_analysis_prompt(self, file_path: Path, content: str, start_line: int = 1) -> str:
        """Create a prompt for LLM analysis of naming and style."""
        return f"""Analyze this Python code for naming conventions and code style issues. The code has line numbers prefixed (e.g., "  42| code").

ONLY flag issues that are CLEARLY problematic. Be VERY selective - report only the most significant issues:

HIGH PRIORITY (always flag):
- Extremely cryptic names (single letters like 'f', 'x', 'a' for non-trivial functions)
- Names with typos (misspellings like 'calculte', 'functin')
- Misleading names (function says 'calculate_average' but computes sum)
- Names with numbers suggesting copy-paste (func1, func2, result1, result2)

MEDIUM PRIORITY (flag if egregious):
- Severely inconsistent conventions WITHIN THE SAME SCOPE (mixing camelCase and snake_case)
- Extremely verbose/redundant names (process_user_data_list_and_return_processed_data_list)
- Names that are profane or unprofessional

LOW PRIORITY (only flag if extreme):
- Generic names (only if VERY generic like 'stuff', 'thing', 'doSomething')
- AI-generated patterns (only if obviously robotic like 'data_item_element', 'processed_data_result')

DO NOT flag:
- Standard loop variables (i, j, k, item, x, y in comprehensions)
- Common short names in appropriate contexts (e.g., 'df' for dataframes, 'db' for database)
- Minor style preferences
- Names that are "good enough" - don't be pedantic

File: {file_path.name}

```python
{content}
```

Return JSON with ONLY significant issues (prefer fewer, high-quality findings over many low-quality ones):
{{
  "issues": [
    {{
      "type": "naming|style|ai_pattern|typo|misleading",
      "severity": "low|medium|high",
      "title": "Brief, specific title (include the problematic name in quotes)",
      "description": "One concise sentence explaining why it's problematic",
      "line_number": 42,
      "confidence": 0.8,
      "current_name": "oldName",
      "suggested_name": "newDescriptiveName",
      "category": "variable|function|class|method|parameter",
      "show_snippet": false,
      "snippet_lines": 1
    }}
  ]
}}

IMPORTANT RULES:
- line_number: Must match the EXACT line number shown at the start of each line
- title: Include the problematic name in quotes (e.g., "Cryptic function name 'f'")
- description: Keep it SHORT - one sentence max. Don't repeat the title or explain what the fix is.
- suggested_name: Provide a better name if applicable (optional - omit if no clear suggestion)
- show_snippet: Set to FALSE if the issue is clear from the title alone
- show_snippet: Set to TRUE only when code context helps understand why the name is bad
- snippet_lines: If show_snippet is true, specify context lines (1-3). Use minimal lines needed.
- confidence: Use 0.9+ only for definite issues, 0.7-0.8 for likely issues
- BE SELECTIVE: Return fewer findings (max 10) but make each one count

Return {{"issues": []}} if no significant issues found."""

    def _parse_llm_response(self, response: str, file_path: Path, content: str, printer: Optional["Printer"] = None) -> List[Finding]:
        """Parse LLM response and create findings."""
        findings = []

        try:
            import json

            # Strip markdown code blocks if present
            cleaned_response = response.strip()
            if cleaned_response.startswith('```json'):
                cleaned_response = cleaned_response[7:]
            elif cleaned_response.startswith('```'):
                cleaned_response = cleaned_response[3:]
            if cleaned_response.endswith('```'):
                cleaned_response = cleaned_response[:-3]
            cleaned_response = cleaned_response.strip()

            # Try to parse JSON response
            data = json.loads(cleaned_response)

            for issue in data.get("issues", []):
                try:
                    finding = self._create_finding_from_issue(issue, file_path, content)
                    if finding:
                        findings.append(finding)
                except Exception:
                    # Skip malformed issues but continue processing others
                    continue

        except (json.JSONDecodeError, KeyError, TypeError) as e:
            # If JSON parsing fails, try text parsing
            if printer and printer.debug:
                printer.print_debug(f"JSON parsing failed: {e}, trying text parsing")
                printer.print_debug(f"Raw response: {response[:1000]}...")
            findings.extend(self._parse_text_response(response, file_path, content))

        return findings

    def _find_name_line(self, content: str, reported_line: int, current_name: str) -> int:
        """Find the actual line containing the name near the reported line number.

        The LLM may report a line number that's slightly off. This method
        searches nearby lines to find the actual identifier.
        """
        lines = content.splitlines()
        total_lines = len(lines)

        if reported_line < 1 or reported_line > total_lines:
            return max(1, min(reported_line, total_lines))

        # If we have the name, try to find exact match first
        if current_name:
            # Search range: reported line +/- 3 lines
            search_range = 3
            for offset in range(search_range + 1):
                for direction in [0, -1, 1]:
                    check_line = reported_line + (offset * direction if direction else 0)
                    if 1 <= check_line <= total_lines:
                        line_content = lines[check_line - 1]
                        if current_name in line_content:
                            return check_line

        # If name not found nearby, return the reported line
        return reported_line

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
            "typo": FindingType.STYLE_ISSUE,
            "misleading": FindingType.BAD_PRACTICE,
        }

        # Determine line number with validation
        reported_line = issue.get("line_number", 1)
        current_name = issue.get("current_name", "")
        line_number = self._find_name_line(content, reported_line, current_name)

        lines = content.splitlines()
        if line_number < 1 or line_number > len(lines):
            line_number = 1

        # Create description (keep it concise, suggested_name is shown separately by printer)
        description = issue.get("description", "LLM detected a naming or style issue")

        # Determine fix type and prompt
        fix_prompt = "Review and improve the naming"
        if issue.get("suggested_name") and issue.get("current_name"):
            fix_prompt = f"Rename '{issue['current_name']}' to '{issue['suggested_name']}'"

        # Determine if code snippet should be shown (LLM decides)
        show_snippet = issue.get("show_snippet", True)  # Default to showing for backwards compat
        snippet_lines = min(issue.get("snippet_lines", 1), 3)  # Limit to max 3 lines as per prompt

        if show_snippet:
            code_snippet = self._extract_code_snippet(content, line_number, context_lines=snippet_lines)
        else:
            code_snippet = None

        return Finding(
            id=f"vibe_naming_{file_path.name}_{line_number}_{hash(issue.get('title', '')) % 1000}",
            title=issue.get("title", "Naming/Style Issue"),
            description=description,
            severity=severity_map.get(issue.get("severity", "low"), Severity.LOW),
            type=type_map.get(issue.get("type", "naming"), FindingType.STYLE_ISSUE),
            location=Location(
                file=file_path,
                line_start=line_number,
            ),
            checker_name=self.name,
            code_snippet=code_snippet,
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
                    findings.append(self._create_finding_from_text(current_issue, file_path, content))

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
            findings.append(self._create_finding_from_text(current_issue, file_path, content))

        return findings

    def _create_finding_from_text(self, issue: dict, file_path: Path, content: str) -> Finding:
        """Create a finding from text-based issue description."""
        line_number = issue.get("line_number", 1)
        code_snippet = self._extract_code_snippet(content, line_number, context_lines=1)

        return Finding(
            id=f"vibe_naming_text_{file_path.name}_{line_number}_{hash(str(issue)) % 1000}",
            title="Naming/Style Issue Detected",
            description=issue.get("description", "LLM detected a naming or style issue"),
            severity=Severity.LOW,
            type=FindingType.STYLE_ISSUE,
            location=Location(
                file=file_path,
                line_start=line_number,
            ),
            checker_name=self.name,
            code_snippet=code_snippet,
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

    def _create_stacked_analysis_prompt(self, content: str) -> str:
        """Create prompt for analyzing stacked files."""
        return f"""Analyze these Python files for naming conventions and code style issues. Files are separated by "# === FILE: filename.py ===" markers.

ONLY flag issues that are CLEARLY problematic. Be VERY selective - report only the most significant issues:

HIGH PRIORITY (always flag):
- Extremely cryptic names (single letters like 'f', 'x', 'a' for non-trivial functions)
- Names with typos (misspellings like 'calculte', 'functin')
- Misleading names (function says 'calculate_average' but computes sum)
- Names with numbers suggesting copy-paste (func1, func2, result1, result2)

MEDIUM PRIORITY (flag if egregious):
- Severely inconsistent conventions WITHIN THE SAME SCOPE
- Extremely verbose/redundant names
- Names that are profane or unprofessional

LOW PRIORITY (only flag if extreme):
- Generic names (only if VERY generic like 'stuff', 'thing', 'doSomething')
- AI-generated patterns (only if obviously robotic)

Return JSON with ONLY significant issues:
{{
  "issues": [
    {{
      "file": "filename.py",
      "type": "naming|style|ai_pattern|typo|misleading",
      "severity": "low|medium|high",
      "title": "Brief, specific title (include the problematic name in quotes)",
      "description": "One concise sentence explaining why it's problematic",
      "line_number": 42,
      "confidence": 0.8,
      "current_name": "oldName",
      "suggested_name": "newDescriptiveName",
      "category": "variable|function|class|method|parameter",
      "show_snippet": false,
      "snippet_lines": 1
    }}
  ]
}}

IMPORTANT RULES:
- file: Must be the filename from the "# === FILE: xxx ===" marker
- line_number: Must match the EXACT line number shown
- title: Include the problematic name in quotes
- BE SELECTIVE: Return fewer findings but make each one count

Return {{"issues": []}} if no significant issues found.

```python
{content}
```"""

    def _parse_stacked_response(self, response: str, files: List[tuple]) -> List[Finding]:
        """Parse LLM response for stacked files."""
        findings = []

        # Build a map of filename to (path, content)
        file_map = {path.name: (path, content) for path, content in files}

        try:
            import json

            cleaned_response = response.strip()
            if cleaned_response.startswith('```json'):
                cleaned_response = cleaned_response[7:]
            elif cleaned_response.startswith('```'):
                cleaned_response = cleaned_response[3:]
            if cleaned_response.endswith('```'):
                cleaned_response = cleaned_response[:-3]
            cleaned_response = cleaned_response.strip()

            data = json.loads(cleaned_response)

            for issue in data.get("issues", []):
                filename = issue.get("file", "")
                if filename in file_map:
                    file_path, content = file_map[filename]
                    finding = self._create_finding_from_issue(issue, file_path, content)
                    if finding:
                        findings.append(finding)

        except (json.JSONDecodeError, KeyError, TypeError):
            # Fallback: can't parse, return empty
            pass

        return findings
