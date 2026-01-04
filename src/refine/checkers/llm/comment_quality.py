"""LLM-based checker for detecting bad comments and docstrings."""

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING
import re

from .base import LLMBaseChecker
from refine.core.results import Finding, Severity, FindingType, Location, Fix, FixType, Evidence

if TYPE_CHECKING:
    from refine.ui.printer import Printer


class CommentQualityChecker(LLMBaseChecker):
    """Checker that uses LLM to analyze comments and docstrings for AI-generated patterns."""

    def __init__(self):
        super().__init__(
            name="comment_quality",
            description="Uses LLM to detect unnecessary, redundant, or AI-generated comments and docstrings"
        )

    def _extract_code_snippet(self, content: str, line_number: int, context_lines: int = 1) -> str:
        """Extract a minimal but sufficient code snippet around the given line.

        Dynamically adjusts size based on content type:
        - Single-line comments: show comment + 1 line of context
        - Docstrings: show opening + first few meaningful lines
        - Trims unnecessary blank lines
        """
        lines = content.splitlines()
        if line_number < 1 or line_number > len(lines):
            return ""

        target_idx = line_number - 1  # Convert to 0-indexed
        target_line = lines[target_idx].strip()

        # Determine snippet bounds based on content type
        if target_line.startswith('#'):
            # Single-line comment: minimal context
            start_idx = max(0, target_idx - 1)
            end_idx = min(len(lines), target_idx + 2)
        elif '"""' in target_line or "'''" in target_line:
            # Docstring start: show opening + a few lines
            start_idx = max(0, target_idx - 1)
            # Find docstring end or limit to 4 lines
            end_idx = target_idx + 1
            quote = '"""' if '"""' in target_line else "'''"
            for i in range(target_idx + 1, min(len(lines), target_idx + 5)):
                end_idx = i + 1
                if quote in lines[i] and i != target_idx:
                    break
        else:
            # Default: small context
            start_idx = max(0, target_idx - 1)
            end_idx = min(len(lines), target_idx + 2)

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

    def _analyze_chunk(
        self,
        provider,
        file_path: Path,
        chunk_content: str,
        start_line: int,
        content: str,
        printer: Optional["Printer"] = None
    ) -> List[Finding]:
        """Analyze a single chunk with the LLM provider."""
        prompt = self._create_analysis_prompt(file_path, chunk_content, start_line)

        if printer and printer.debug:
            printer.print_debug(f"LLM prompt for {file_path.name} (lines {start_line}+): {prompt[:200]}...")

        response = provider.analyze_code(prompt)

        if printer and printer.debug:
            printer.print_debug(f"LLM response for {file_path.name}: {response[:1000]}...")

        return self._parse_llm_response(response, file_path, content)

    def _get_supported_extensions(self) -> List[str]:
        return [".py"]



    def _has_code_content(self, content: str) -> bool:
        """Check if file contains comments or docstrings to analyze."""
        return self._has_comments_or_docstrings(content, ".py")  # Assume Python for now

    def _has_comments_or_docstrings(self, content: str, extension: str) -> bool:
        """Quick check if file contains comments or docstrings."""
        # Python docstrings and comments
        return '"""' in content or "'''" in content or "#" in content

    def _create_analysis_prompt(self, file_path: Path, content: str, start_line: int = 1) -> str:
        """Create a prompt for LLM analysis of comments and docstrings."""
        return f"""Analyze this Python code for poor quality comments and docstrings. The code has line numbers prefixed (e.g., "  42| code").

Find issues like:
- Redundant comments that restate what code does (e.g., "# add a and b" before "result = a + b")
- Generic docstrings that don't add value (e.g., "This function does X" when X is obvious from name)
- Overly verbose documentation for simple operations
- Comments that contradict the code
- AI-generated looking comments (robotic, template-like phrasing)

File: {file_path.name}

```python
{content}
```

Return JSON with ONLY the most significant issues (max 15 per chunk):
{{
  "issues": [
    {{
      "type": "unnecessary_comment|redundant_docstring|ai_generated_comment|generic_docstring|misleading|secrets_in_comment",
      "severity": "low|medium|high",
      "title": "Redundant comment: '<the comment text>'",
      "description": "Brief explanation of why it's problematic",
      "line_number": 42,
      "confidence": 0.8,
      "comment_type": "single_line|docstring",
      "suggested_action": "remove|improve",
      "show_snippet": false,
      "snippet_lines": 0
    }}
  ]
}}

IMPORTANT RULES:
- line_number: Must match the EXACT line number shown at the start of each line
- title: Include the actual comment/docstring text in quotes when possible
- show_snippet: Set to FALSE if the issue is clear from the title alone (e.g., "Redundant comment: '# Create checker'")
- show_snippet: Set to TRUE only when code context is needed to understand the issue (e.g., misleading docstrings, contradictions)
- snippet_lines: If show_snippet is true, specify how many lines of context (1-4). Use minimal lines needed.

Return {{"issues": []}} if no significant issues found."""

    def _parse_llm_response(self, response: str, file_path: Path, content: str) -> List[Finding]:
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

        except (json.JSONDecodeError, KeyError, TypeError):
            # If JSON parsing fails, try text parsing
            findings.extend(self._parse_text_response(response, file_path, content))

        return findings

    def _find_comment_line(self, content: str, reported_line: int, title: str) -> int:
        """Find the actual comment line near the reported line number.

        The LLM may report a line number that's slightly off. This method
        searches nearby lines to find the actual comment or docstring.
        """
        lines = content.splitlines()
        total_lines = len(lines)

        if reported_line < 1 or reported_line > total_lines:
            return max(1, min(reported_line, total_lines))

        # Extract the comment text from the title if present
        # e.g., "Redundant comment: '# Add src directory to path'" -> "# Add src directory to path"
        comment_text = None
        if "'" in title:
            start = title.find("'")
            end = title.rfind("'")
            if start < end:
                comment_text = title[start + 1:end].strip()

        # Search range: reported line ± 3 lines
        search_range = 3

        # If we have comment text, try to find exact match first
        if comment_text:
            for offset in range(search_range + 1):
                for direction in [0, -1, 1]:
                    check_line = reported_line + (offset * direction if direction else 0)
                    if 1 <= check_line <= total_lines:
                        line_content = lines[check_line - 1]
                        # Check if this line contains the comment text
                        if comment_text in line_content or comment_text.lstrip('#').strip() in line_content:
                            return check_line

        # Fallback: look for any comment or docstring near reported line
        for offset in range(search_range + 1):
            for direction in [0, -1, 1]:
                check_line = reported_line + (offset * direction if direction else 0)
                if 1 <= check_line <= total_lines:
                    line_content = lines[check_line - 1].strip()
                    # Check for single-line comment or docstring
                    if line_content.startswith('#') or line_content.startswith('"""') or line_content.startswith("'''"):
                        return check_line

        # If no comment found, return the reported line
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
            "unnecessary_comment": FindingType.STYLE_ISSUE,
            "redundant_docstring": FindingType.STYLE_ISSUE,
            "ai_generated_comment": FindingType.AI_GENERATED,
            "generic_docstring": FindingType.STYLE_ISSUE,
        }

        # Determine line number - try to find the actual comment line
        reported_line = issue.get("line_number", 1)
        title = issue.get("title", "")
        line_number = self._find_comment_line(content, reported_line, title)

        lines = content.splitlines()
        if line_number < 1 or line_number > len(lines):
            line_number = 1

        # Create description
        description = issue.get("description", "LLM detected a comment/docstring quality issue")

        if issue.get("suggested_text"):
            description += f" Suggested: {issue['suggested_text']}"

        # Determine fix type and prompt
        suggested_action = issue.get("suggested_action", "review")
        fix_prompt = f"Review this {issue.get('comment_type', 'comment')} for quality"

        if suggested_action == "remove":
            fix_prompt = f"Remove this unnecessary {issue.get('comment_type', 'comment')}"
        elif suggested_action == "improve":
            fix_prompt = f"Improve this {issue.get('comment_type', 'comment')} to be more meaningful"
        elif suggested_action == "replace" and issue.get("suggested_text"):
            fix_prompt = f"Replace with: {issue['suggested_text']}"

        # Determine if code snippet should be shown (LLM decides)
        show_snippet = issue.get("show_snippet", True)  # Default to showing for backwards compat
        snippet_lines = issue.get("snippet_lines", 2)

        if show_snippet:
            code_snippet = self._extract_code_snippet(content, line_number, context_lines=snippet_lines)
        else:
            code_snippet = None

        return Finding(
            id=f"comment_quality_{file_path.name}_{line_number}_{hash(issue.get('title', '')) % 1000}",
            title=issue.get("title", "Comment/Docstring Quality Issue"),
            description=description,
            severity=severity_map.get(issue.get("severity", "low"), Severity.LOW),
            type=type_map.get(issue.get("type", "unnecessary_comment"), FindingType.STYLE_ISSUE),
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
                description=f"Fix {issue.get('comment_type', 'comment')} quality issue",
                prompt=fix_prompt
            )]
        )

    def _parse_text_response(self, response: str, file_path: Path, content: str) -> List[Finding]:
        """Fallback parsing for non-JSON LLM responses."""
        findings = []

        # Look for comment/docstring related keywords
        lines = response.splitlines()
        current_issue = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Look for issue indicators
            if any(keyword in line.lower() for keyword in [
                "comment:", "docstring:", "documentation:", "unnecessary:",
                "redundant:", "generic:", "ai-generated:", "boilerplate:"
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
        line_number = issue.get("line_number", 1)
        code_snippet = self._extract_code_snippet("", line_number)  # Empty content fallback

        return Finding(
            id=f"comment_quality_text_{file_path.name}_{line_number}_{hash(str(issue)) % 1000}",
            title="Comment/Docstring Quality Issue Detected",
            description=issue.get("description", "LLM detected a comment or docstring quality issue"),
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
                description="Review comment/docstring quality",
                prompt="Review the comment or docstring for clarity, necessity, and value"
            )]
        )

    def _create_stacked_analysis_prompt(self, content: str) -> str:
        """Create prompt for analyzing stacked files."""
        return f"""Analyze these Python files for poor quality comments and docstrings. Files are separated by "# === FILE: filename.py ===" markers.

Find issues like:
- Redundant comments that restate what code does
- Generic docstrings that don't add value
- Overly verbose documentation for simple operations
- Comments that contradict the code
- AI-generated looking comments (robotic, template-like phrasing)

{{
  "issues": [
    {{
      "file": "filename.py",
      "type": "unnecessary_comment|redundant_docstring|ai_generated_comment|generic_docstring|misleading|secrets_in_comment",
      "severity": "low|medium|high",
      "title": "Redundant comment: '<the comment text>'",
      "description": "Brief explanation of why it's problematic",
      "line_number": 42,
      "confidence": 0.8,
      "comment_type": "single_line|docstring",
      "suggested_action": "remove|improve",
      "show_snippet": false,
      "snippet_lines": 0
    }}
  ]
}}

IMPORTANT RULES:
- file: Must be the filename from the "# === FILE: xxx ===" marker
- line_number: Use the line number shown at the start of each line
- Focus on the most significant issues only

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
