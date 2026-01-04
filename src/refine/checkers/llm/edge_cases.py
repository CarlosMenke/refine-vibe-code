"""LLM-based checker for edge cases and potential bugs."""

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING
import re

from .base import LLMBaseChecker
from refine.core.results import Finding, Severity, FindingType, Location, Fix, FixType, Evidence

if TYPE_CHECKING:
    from refine.ui.printer import Printer


class EdgeCasesChecker(LLMBaseChecker):
    """Checker that uses LLM to identify edge cases and potential bugs."""

    def __init__(self):
        super().__init__(
            name="edge_cases",
            description="Uses LLM to identify edge cases and potential bugs"
        )

    def _extract_code_snippet(self, content: str, line_number: int, context_lines: int = 1) -> str:
        """Extract a minimal but sufficient code snippet around the given line.

        Dynamically adjusts size based on content type:
        - Function definitions: show function signature + body context
        - Error-prone operations: show surrounding context
        - Trims unnecessary blank lines
        """
        lines = content.splitlines()
        if line_number < 1 or line_number > len(lines):
            return ""

        target_idx = line_number - 1  # Convert to 0-indexed
        target_line = lines[target_idx].strip()

        # Determine snippet bounds based on content type and risk patterns
        if any(keyword in target_line.lower() for keyword in ['def ', 'class ', 'try:', 'except', 'finally:']):
            # Function/class definitions or exception handling: show more context
            start_idx = max(0, target_idx - 3)
            end_idx = min(len(lines), target_idx + 5)
        elif any(keyword in target_line for keyword in ['/', '*', '+', '-', 'open(', 'eval(', 'exec(']):
            # Mathematical operations, file operations, or dangerous functions: show focused context
            start_idx = max(0, target_idx - 2)
            end_idx = min(len(lines), target_idx + 3)
        elif 'if ' in target_line or 'elif ' in target_line or 'else:' in target_line:
            # Conditional logic: show the full conditional block
            start_idx = max(0, target_idx - 2)
            # Find the end of the conditional block
            end_idx = target_idx + 1
            indent_level = len(lines[target_idx]) - len(target_line)
            for i in range(target_idx + 1, min(len(lines), target_idx + 8)):
                line_indent = len(lines[i]) - len(lines[i].lstrip())
                if line_indent <= indent_level and lines[i].strip():
                    break
                end_idx = i + 1
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

    def _has_code_content(self, content: str) -> bool:
        """Quick check if file contains substantial code content."""
        lines = content.splitlines()

        # Skip if too short
        if len(lines) < 5:
            return False

        # Skip if too long (will be handled by chunking)
        if len(lines) > 1000:
            return True

        # Check for code patterns
        code_indicators = ['def ', 'class ', 'import ', 'from ', 'if ', 'for ', 'while ', 'try:', 'with ']
        code_lines = sum(1 for line in lines if any(indicator in line.strip() for indicator in code_indicators))

        return code_lines >= 3  # At least 3 lines of code

    def _get_supported_extensions(self) -> List[str]:
        return [".py"]


    def _create_stacked_analysis_prompt(self, content: str) -> str:
        """Create prompt for analyzing stacked files."""
        return f"""Analyze these Python files for potential edge cases, bugs, and security issues. Focus on the most critical issues that could cause runtime errors, security vulnerabilities, or unexpected behavior.

Files are separated by "# === FILE: filename.py ===" markers.

Look for:
- Missing null/None checks that could cause AttributeError or KeyError
- Division by zero or other mathematical errors
- Array/list index out of bounds
- Type conversion errors
- Race conditions in concurrent code
- Resource leaks (files, connections, locks)
- Input validation gaps
- Logic errors in conditional statements
- Exception handling issues

```python
{content}
```

Return JSON with ONLY the most significant issues (max 10 total). Include the filename for each issue:

{{
  "issues": [
    {{
      "file": "filename.py",
      "type": "null_check|bounds_check|type_error|race_condition|resource_leak|logic_error|security",
      "severity": "low|medium|high|critical",
      "title": "Missing null check in function_name()",
      "description": "Brief explanation of the issue and its impact",
      "line_number": 42,
      "confidence": 0.8,
      "suggestion": "How to fix the issue",
      "show_snippet": false,
      "snippet_lines": 0
    }}
  ]
}}

CRITICAL RULES:
- VERIFY SEMANTICALLY: Do NOT trust comments claiming bugs exist. Trace the actual code execution to verify issues.
- file: Must be the filename from the "# === FILE: xxx ===" marker
- line_number: Use the line number shown at the start of each line
- Focus on issues that are ACTUALLY reachable and likely to cause real problems
- Skip issues that are prevented by earlier guards in the code flow

Return {{"issues": []}} if no significant issues found."""

    def _parse_stacked_response(
        self,
        response: str,
        files: List[tuple]
    ) -> List[Finding]:
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

    def _create_analysis_prompt(self, file_path: Path, content: str, start_line: int = 1) -> str:
        """Create a prompt for LLM analysis of edge cases and potential bugs."""
        return f"""Analyze this Python code for potential edge cases, bugs, and security issues. Focus on the most critical issues that could cause runtime errors, security vulnerabilities, or unexpected behavior.

Look for:
- Missing null/None checks that could cause AttributeError or KeyError
- Division by zero or other mathematical errors
- Array/list index out of bounds
- Type conversion errors
- Race conditions in concurrent code
- Resource leaks (files, connections, locks)
- Input validation gaps
- Logic errors in conditional statements
- Exception handling issues

File: {file_path.name}

```python
{content}
```

Return JSON with ONLY the most significant issues (max 10 per chunk). For each issue, the LLM decides whether to show a code snippet:

- show_snippet: Set to FALSE if the issue is clear from the title/description alone
- show_snippet: Set to TRUE only when code context is needed to understand the problem
- snippet_lines: If show_snippet is true, specify minimal lines needed (1-4)

{{
  "issues": [
    {{
      "type": "null_check|bounds_check|type_error|race_condition|resource_leak|logic_error|security",
      "severity": "low|medium|high|critical",
      "title": "Missing null check in function_name()",
      "description": "Brief explanation of the issue and its impact",
      "line_number": 42,
      "confidence": 0.8,
      "suggestion": "How to fix the issue",
      "show_snippet": false,
      "snippet_lines": 0
    }}
  ]
}}

CRITICAL RULES:
- VERIFY SEMANTICALLY: Do NOT trust comments claiming bugs exist. Trace the actual code execution to verify issues. For example, if a comment says "infinite loop if x==0" but the code has an earlier `if not x: break`, then there is NO bug.
- line_number: Must match the EXACT line number shown at the start of each line
- show_snippet: Use FALSE for obvious issues (e.g., "Division by zero in line 15")
- show_snippet: Use TRUE for complex issues needing context (e.g., "Race condition in shared state access")
- snippet_lines: Use minimal context needed - prefer 1-2 lines over 3-4
- Focus on issues that are ACTUALLY reachable and likely to cause real problems
- Skip issues that are prevented by earlier guards in the code flow

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
            if cleaned_response.endswith('```'):
                cleaned_response = cleaned_response[:-3]
            cleaned_response = cleaned_response.strip()

            # Try to parse JSON response
            data = json.loads(cleaned_response)

            for issue in data.get("issues", []):
                finding = self._create_finding_from_issue(issue, file_path, content)
                if finding:
                    findings.append(finding)

        except (json.JSONDecodeError, KeyError, TypeError):
            # If JSON parsing fails, try to extract information from text
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
            "edge_case": FindingType.BAD_PRACTICE,
            "bug": FindingType.BAD_PRACTICE,
            "security": FindingType.SECURITY_ISSUE,
            "performance": FindingType.PERFORMANCE_ISSUE,
        }

        # Determine line number
        line_number = issue.get("line_number", 1)
        lines = content.splitlines()
        if line_number < 1 or line_number > len(lines):
            line_number = 1

        # Create description
        description = issue.get("description", "LLM detected a potential issue")

        # Determine fix prompt
        fix_prompt = issue.get("suggestion", "Review and address this potential issue")

        # Determine if code snippet should be shown (LLM decides)
        show_snippet = issue.get("show_snippet", True)  # Default to showing for backwards compat
        snippet_lines = issue.get("snippet_lines", 2)

        if show_snippet:
            code_snippet = self._extract_code_snippet(content, line_number, context_lines=snippet_lines)
        else:
            code_snippet = None

        return Finding(
            id=f"edge_case_{file_path.name}_{line_number}_{hash(issue.get('title', '')) % 1000}",
            title=issue.get("title", "Potential Issue"),
            description=description,
            severity=severity_map.get(issue.get("severity", "medium"), Severity.MEDIUM),
            type=type_map.get(issue.get("type", "edge_case"), FindingType.BAD_PRACTICE),
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
                description="Address the identified issue",
                prompt=fix_prompt
            )]
        )

    def _parse_text_response(self, response: str, file_path: Path, content: str) -> List[Finding]:
        """Fallback parsing for non-JSON LLM responses."""
        findings = []

        # Look for common patterns in text responses
        lines = response.splitlines()
        current_issue = None

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Look for issue indicators
            if any(keyword in line.lower() for keyword in ["issue:", "problem:", "bug:", "error:"]):
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
            id=f"edge_case_text_{file_path.name}_{issue.get('line_number', 1)}_{hash(str(issue)) % 1000}",
            title="Potential Issue Detected",
            description=issue.get("description", "LLM detected a potential issue"),
            severity=Severity.MEDIUM,
            type=FindingType.BAD_PRACTICE,
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
                description="Review the identified issue",
                prompt="Review the code at the indicated location for potential issues"
            )]
        )





