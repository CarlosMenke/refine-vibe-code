"""LLM-based checker for naming conventions and code style."""

from pathlib import Path
from typing import List

from ..base import BaseChecker
from ...core.results import Finding, Severity, FindingType, Location, Fix, FixType, Evidence
from ...providers import get_provider


class NamingVibeChecker(BaseChecker):
    """Checker that uses LLM to analyze naming conventions and code style."""

    def __init__(self):
        super().__init__(
            name="naming_vibe",
            description="Uses LLM to analyze naming conventions and code style for AI-generated patterns",
            is_classical=False
        )

    def _get_supported_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".java", ".cpp", ".c", ".go", ".rs"]

    def check_file(self, file_path: Path, content: str) -> List[Finding]:
        """Use LLM to analyze code for naming and style issues."""
        findings = []

        # Skip very small or very large files
        lines = content.splitlines()
        if len(lines) < 10 or len(lines) > 300:
            return findings

        try:
            # Get LLM provider
            provider = get_provider()

            # Create analysis prompt
            prompt = self._create_analysis_prompt(file_path, content)

            # Get LLM analysis
            response = provider.analyze_code(prompt)

            # Parse response and create findings
            findings.extend(self._parse_llm_response(response, file_path, content))

        except Exception as e:
            # If LLM analysis fails, don't create findings
            pass

        return findings

    def _create_analysis_prompt(self, file_path: Path, content: str) -> str:
        """Create a prompt for LLM analysis of naming and style."""
        file_ext = file_path.suffix.lower()

        language_map = {
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".java": "Java",
            ".cpp": "C++",
            ".c": "C",
            ".go": "Go",
            ".rs": "Rust",
        }

        language = language_map.get(file_ext, "programming language")

        return f"""Analyze this {language} code for naming conventions, style, and potential AI-generation indicators. Look for:

1. Inconsistent naming conventions (camelCase vs snake_case, etc.)
2. Generic or robotic variable/function names
3. Overly complex or unnecessary abstractions
4. Code patterns typical of AI generation
5. Poor variable naming that doesn't convey intent
6. Inconsistent code style within the file
7. Redundant or verbose naming patterns

Code file: {file_path.name}
Language: {language}

Code:
```{(language.lower())}
{content}
```

Provide your analysis in the following JSON format:
{{
  "issues": [
    {{
      "type": "naming|style|ai_pattern",
      "severity": "low|medium|high",
      "title": "Brief title",
      "description": "Detailed description",
      "line_number": 42,
      "confidence": 0.8,
      "current_name": "oldName",
      "suggested_name": "newName",
      "category": "variable|function|class|method"
    }}
  ]
}}

Focus on actual issues. If no significant issues are found, return {{"issues": []}}."""

    def _parse_llm_response(self, response: str, file_path: Path, content: str) -> List[Finding]:
        """Parse LLM response and create findings."""
        findings = []

        try:
            import json

            # Try to parse JSON response
            data = json.loads(response.strip())

            for issue in data.get("issues", []):
                finding = self._create_finding_from_issue(issue, file_path, content)
                if finding:
                    findings.append(finding)

        except (json.JSONDecodeError, KeyError, TypeError):
            # If JSON parsing fails, try text parsing
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

        # Determine line number
        line_number = issue.get("line_number", 1)
        lines = content.splitlines()
        if line_number < 1 or line_number > len(lines):
            line_number = 1

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





