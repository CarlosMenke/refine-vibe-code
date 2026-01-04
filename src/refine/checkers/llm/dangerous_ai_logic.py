"""LLM-based checker for detecting dangerous AI/ML logic and security vulnerabilities."""

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING
import re

from .base import LLMBaseChecker
from refine.core.results import Finding, Severity, FindingType, Location, Fix, FixType, Evidence

if TYPE_CHECKING:
    from refine.ui.printer import Printer


class DangerousAILogicChecker(LLMBaseChecker):
    """Checker that uses LLM to detect dangerous AI/ML logic and security issues."""

    # Maximum lines per chunk to avoid LLM response truncation
    MAX_CHUNK_LINES = 150
    # Overlap between chunks to maintain context
    CHUNK_OVERLAP = 10
    # Maximum parallel workers for chunk processing
    MAX_WORKERS = 4

    # AI/ML framework imports to detect
    AI_FRAMEWORKS = {
        'tensorflow', 'tf', 'torch', 'pytorch', 'keras', 'sklearn',
        'transformers', 'huggingface', 'openai', 'anthropic', 'cohere',
        'onnx', 'xgboost', 'lightgbm', 'catboost', 'mlflow', 'langchain'
    }

    def __init__(self):
        super().__init__(
            name="dangerous_ai_logic",
            description="Uses LLM to detect dangerous AI/ML logic and security vulnerabilities"
        )

    def _get_supported_extensions(self) -> List[str]:
        return [".py"]

    def _has_ai_frameworks(self, content: str) -> bool:
        """Quick check if file contains AI/ML framework usage."""
        content_lower = content.lower()

        # Check for framework imports
        for framework in self.AI_FRAMEWORKS:
            if framework in content_lower:
                return True

        # Check for common AI/ML patterns
        ai_patterns = ['.fit(', '.predict(', '.train(', '.generate(', '.completion(',
                       'model.', 'pipeline(', 'embeddings', 'tokenizer']
        return any(pattern in content_lower for pattern in ai_patterns)

    def _extract_code_snippet(self, content: str, line_number: int, total_lines: int = 2) -> str:
        """Extract a minimal code snippet around the given line.

        Args:
            content: Full file content
            line_number: The target line (1-indexed)
            total_lines: Total lines to show (1=just target, 2=target+1 after, 3=1+target+1, etc.)
        """
        lines = content.splitlines()
        if line_number < 1 or line_number > len(lines):
            return ""

        target_idx = line_number - 1

        # Calculate context: prefer showing lines after the target
        # total_lines=1: just target, total_lines=2: target+1 after, total_lines=3: 1 before+target+1 after
        if total_lines <= 1:
            before, after = 0, 0
        elif total_lines == 2:
            before, after = 0, 1
        else:
            extra = total_lines - 1
            before = extra // 2
            after = extra - before

        start_idx = max(0, target_idx - before)
        end_idx = min(len(lines), target_idx + after + 1)

        snippet_lines = lines[start_idx:end_idx]

        # Trim blank lines at edges (but keep target line visible)
        while len(snippet_lines) > 1 and not snippet_lines[0].strip() and start_idx < target_idx:
            snippet_lines = snippet_lines[1:]
            start_idx += 1
        while len(snippet_lines) > 1 and not snippet_lines[-1].strip():
            snippet_lines = snippet_lines[:-1]

        # Build numbered output with marker
        numbered_lines = []
        for i, line in enumerate(snippet_lines, start_idx + 1):
            marker = ">" if i == line_number else ""
            numbered_lines.append(f"{marker:>1} {i:3d}| {line}")

        return "\n".join(numbered_lines)


    def _has_code_content(self, content: str) -> bool:
        """Check if file contains AI/ML frameworks."""
        return self._has_ai_frameworks(content)

    def _create_analysis_prompt(self, file_path: Path, content: str, start_line: int = 1) -> str:
        """Create a focused prompt for dangerous AI/ML logic detection."""
        return f"""Analyze this Python code for dangerous AI/ML security vulnerabilities. Line numbers are prefixed (e.g., "  42| code").

CRITICAL ISSUES (always flag):
- Hardcoded API keys for AI services (OpenAI, Anthropic, HuggingFace tokens)
- exec()/eval() with AI model outputs (code injection risk)
- torch.load() without weights_only=True (arbitrary code execution)
- pickle.load() for model deserialization (insecure)
- Loading models from untrusted URLs without verification

HIGH PRIORITY:
- User input directly passed to model.predict() without validation
- Training data loaded from user input (data poisoning)
- Model outputs used in SQL queries or shell commands
- Infinite training loops (while True with .fit())
- No rate limiting on AI API calls

MEDIUM PRIORITY:
- Missing input bounds checking before inference
- No error handling around AI API calls
- Sensitive data in prompts without sanitization

DO NOT flag:
- Standard model.parameters() or state_dict() for optimizers/saving
- Legitimate model checkpointing
- Proper use of environment variables for API keys
- Well-validated input preprocessing

File: {file_path.name}

```python
{content}
```

Return JSON with significant issues only (max 8 per chunk):
{{
  "issues": [
    {{
      "type": "api_key_exposed|code_injection|unsafe_deserialization|data_poisoning|input_validation|resource_exhaustion",
      "severity": "low|medium|high|critical",
      "title": "Brief title with the problematic pattern in quotes",
      "description": "One sentence explaining the security risk",
      "line_number": 42,
      "confidence": 0.9,
      "suggestion": "How to fix it",
      "show_snippet": false,
      "snippet_lines": 2
    }}
  ]
}}

IMPORTANT:
- line_number: EXACT line number from the prefixed numbers
- title: Include the dangerous pattern/variable in quotes
- description: ONE sentence - explain the risk, not the fix
- show_snippet: FALSE for most issues - the title should be self-explanatory
- show_snippet: TRUE only when the vulnerability spans multiple lines or needs context
- snippet_lines: TOTAL lines to show (1=just the issue line, 2=issue+next line, 3=before+issue+after). Use 2 max.
- BE SELECTIVE: Only report real security risks, not style issues

Return {{"issues": []}} if no security issues found."""

    def _parse_llm_response(self, response: str, file_path: Path, content: str) -> List[Finding]:
        """Parse LLM response and create findings."""
        findings = []

        try:
            import json

            # Strip markdown code blocks
            cleaned = response.strip()
            if cleaned.startswith('```json'):
                cleaned = cleaned[7:]
            elif cleaned.startswith('```'):
                cleaned = cleaned[3:]
            if cleaned.endswith('```'):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()

            data = json.loads(cleaned)

            for issue in data.get("issues", []):
                try:
                    finding = self._create_finding_from_issue(issue, file_path, content)
                    if finding:
                        findings.append(finding)
                except Exception:
                    continue

        except (json.JSONDecodeError, KeyError, TypeError):
            # Fallback to pattern-based detection for critical issues
            findings.extend(self._fallback_pattern_check(file_path, content))

        return findings

    def _find_issue_line(self, content: str, reported_line: int, title: str) -> int:
        """Find the actual line containing the issue near the reported line."""
        lines = content.splitlines()
        total_lines = len(lines)

        if reported_line < 1 or reported_line > total_lines:
            return max(1, min(reported_line, total_lines))

        # Extract pattern from title (text in quotes)
        pattern = None
        if "'" in title:
            start = title.find("'")
            end = title.rfind("'")
            if start < end:
                pattern = title[start + 1:end]

        if pattern:
            for offset in range(4):
                for direction in [0, -1, 1]:
                    check = reported_line + (offset * direction if direction else 0)
                    if 1 <= check <= total_lines and pattern in lines[check - 1]:
                        return check

        return reported_line

    def _create_finding_from_issue(self, issue: dict, file_path: Path, content: str) -> Optional[Finding]:
        """Create a finding from a parsed issue."""
        severity_map = {
            "low": Severity.LOW,
            "medium": Severity.MEDIUM,
            "high": Severity.HIGH,
            "critical": Severity.CRITICAL,
        }

        type_map = {
            "api_key_exposed": FindingType.SECURITY_ISSUE,
            "code_injection": FindingType.SECURITY_ISSUE,
            "unsafe_deserialization": FindingType.SECURITY_ISSUE,
            "data_poisoning": FindingType.SECURITY_ISSUE,
            "input_validation": FindingType.SECURITY_ISSUE,
            "resource_exhaustion": FindingType.PERFORMANCE_ISSUE,
        }

        reported_line = issue.get("line_number", 1)
        title = issue.get("title", "")
        line_number = self._find_issue_line(content, reported_line, title)

        lines = content.splitlines()
        if line_number < 1 or line_number > len(lines):
            line_number = 1

        # Build concise description
        description = issue.get("description", "Potential AI/ML security vulnerability detected")

        # Determine code snippet visibility (default to not showing - title should be clear)
        show_snippet = issue.get("show_snippet", False)
        snippet_lines = min(issue.get("snippet_lines", 2), 3)  # Max 3 total lines

        code_snippet = None
        if show_snippet:
            code_snippet = self._extract_code_snippet(content, line_number, total_lines=snippet_lines)

        # Build fix prompt
        suggestion = issue.get("suggestion", "Review and address this security concern")

        return Finding(
            id=f"dangerous_ai_{file_path.name}_{line_number}_{hash(title) % 1000}",
            title=issue.get("title", "Dangerous AI/ML Pattern"),
            description=description,
            severity=severity_map.get(issue.get("severity", "medium"), Severity.MEDIUM),
            type=type_map.get(issue.get("type", "security"), FindingType.SECURITY_ISSUE),
            location=Location(file=file_path, line_start=line_number),
            checker_name=self.name,
            code_snippet=code_snippet,
            evidence=[Evidence(
                type="llm_analysis",
                description=f"AI security analysis: {description}",
                confidence=float(issue.get("confidence", 0.8)),
                details=issue
            )],
            fixes=[Fix(
                type=FixType.PROMPT,
                description="Fix AI/ML security issue",
                prompt=suggestion
            )]
        )

    def _fallback_pattern_check(self, file_path: Path, content: str) -> List[Finding]:
        """Fallback pattern-based detection for critical issues when LLM fails."""
        findings = []
        lines = content.splitlines()

        # Critical patterns that should always be flagged
        critical_patterns = [
            (r'(openai|anthropic|cohere).*api[_-]?key\s*[=:]\s*["\'][^"\']{10,}["\']',
             "Hardcoded AI API key", "critical", "api_key_exposed"),
            (r'eval\s*\([^)]*\.(predict|generate|completion)',
             "eval() with AI model output", "critical", "code_injection"),
            (r'exec\s*\([^)]*\.(predict|generate|completion)',
             "exec() with AI model output", "critical", "code_injection"),
            (r'torch\.load\s*\([^)]*\)\s*$',
             "torch.load() without weights_only=True", "high", "unsafe_deserialization"),
            (r'pickle\.load\s*\(',
             "pickle.load() for deserialization", "high", "unsafe_deserialization"),
        ]

        for i, line in enumerate(lines, 1):
            for pattern, title, severity, issue_type in critical_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        id=f"dangerous_ai_fallback_{file_path.name}_{i}_{hash(title) % 1000}",
                        title=title,
                        description=f"Pattern detected: {title.lower()}",
                        severity=Severity.CRITICAL if severity == "critical" else Severity.HIGH,
                        type=FindingType.SECURITY_ISSUE,
                        location=Location(file=file_path, line_start=i),
                        checker_name=self.name,
                        code_snippet=self._extract_code_snippet(content, i, total_lines=1),
                        evidence=[Evidence(
                            type="pattern_match",
                            description=f"Regex pattern match for {issue_type}",
                            confidence=0.9
                        )],
                        fixes=[Fix(
                            type=FixType.PROMPT,
                            description="Address security vulnerability",
                            prompt=f"Fix this {issue_type.replace('_', ' ')} vulnerability"
                        )]
                    ))
                    break  # One finding per line

        return findings

    def _create_stacked_analysis_prompt(self, content: str) -> str:
        """Create prompt for analyzing stacked files."""
        return f"""Analyze these Python files for dangerous AI/ML security vulnerabilities. Files are separated by "# === FILE: filename.py ===" markers.

CRITICAL ISSUES (always flag):
- Hardcoded API keys for AI services (OpenAI, Anthropic, HuggingFace tokens)
- exec()/eval() with AI model outputs (code injection risk)
- torch.load() without weights_only=True (arbitrary code execution)
- pickle.load() for model deserialization (insecure)
- Loading models from untrusted URLs without verification

HIGH PRIORITY:
- User input directly passed to model.predict() without validation
- Training data loaded from user input (data poisoning)
- Model outputs used in SQL queries or shell commands
- Infinite training loops (while True with .fit())
- No rate limiting on AI API calls

Return JSON with significant issues only (max 8 per file):

{{
  "issues": [
    {{
      "file": "filename.py",
      "type": "api_key_exposed|code_injection|unsafe_deserialization|data_poisoning|input_validation|resource_exhaustion",
      "severity": "low|medium|high|critical",
      "title": "Brief title with the problematic pattern in quotes",
      "description": "One sentence explaining the security risk",
      "line_number": 42,
      "confidence": 0.9,
      "suggestion": "How to fix it",
      "show_snippet": false,
      "snippet_lines": 2
    }}
  ]
}}

IMPORTANT:
- file: Must be the filename from the "# === FILE: xxx ===" marker
- line_number: EXACT line number from the prefixed numbers
- BE SELECTIVE: Only report real security risks

Return {{"issues": []}} if no security issues found.

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

            cleaned = response.strip()
            if cleaned.startswith('```json'):
                cleaned = cleaned[7:]
            elif cleaned.startswith('```'):
                cleaned = cleaned[3:]
            if cleaned.endswith('```'):
                cleaned = cleaned[:-3]
            cleaned = cleaned.strip()

            data = json.loads(cleaned)

            for issue in data.get("issues", []):
                filename = issue.get("file", "")
                if filename in file_map:
                    file_path, content = file_map[filename]
                    finding = self._create_finding_from_issue(issue, file_path, content)
                    if finding:
                        findings.append(finding)

        except (json.JSONDecodeError, KeyError, TypeError):
            # Fallback to pattern-based detection
            for file_path, content in files:
                findings.extend(self._fallback_pattern_check(file_path, content))

        return findings
