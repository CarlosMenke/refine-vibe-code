"""LLM-based checker for edge cases and potential bugs."""

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from ..base import BaseChecker
from refine.core.results import Finding, Severity, FindingType, Location, Fix, FixType, Evidence
from refine.providers import get_provider

if TYPE_CHECKING:
    from refine.ui.printer import Printer


class EdgeCasesChecker(BaseChecker):
    """Checker that uses LLM to identify edge cases and potential bugs."""

    def __init__(self):
        super().__init__(
            name="edge_cases",
            description="Uses LLM to identify edge cases and potential bugs",
            is_classical=False
        )

    def _get_supported_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".java", ".cpp", ".c", ".go", ".rs"]

    def check_file(self, file_path: Path, content: str, printer: Optional["Printer"] = None) -> List[Finding]:
        """Use LLM to analyze code for edge cases and potential bugs."""
        findings = []

        # Skip if content is too short or too long
        lines = content.splitlines()
        if len(lines) < 5 or len(lines) > 200:
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
            # If LLM analysis fails, don't create findings but log could be added
            pass

        return findings

    def _create_analysis_prompt(self, file_path: Path, content: str) -> str:
        """Create a prompt for LLM analysis."""
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

        return f"""Analyze this {language} code for potential edge cases, bugs, and issues. Focus on:

1. Null/undefined checks that might be missing
2. Boundary conditions not handled
3. Error conditions not considered
4. Race conditions or concurrency issues
5. Type mismatches or conversions
6. Resource leaks or cleanup issues
7. Input validation problems
8. Logic errors or incorrect assumptions

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
      "type": "edge_case|bug|security|performance",
      "severity": "low|medium|high|critical",
      "title": "Brief title",
      "description": "Detailed description",
      "line_number": 42,
      "confidence": 0.8,
      "suggestion": "How to fix it"
    }}
  ]
}}

Only include actual issues you find. If no issues are found, return {{"issues": []}}."""

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

        return Finding(
            id=f"edge_case_{file_path.name}_{line_number}_{hash(issue.get('title', '')) % 1000}",
            title=issue.get("title", "Potential Issue"),
            description=issue.get("description", "LLM detected a potential issue"),
            severity=severity_map.get(issue.get("severity", "medium"), Severity.MEDIUM),
            type=type_map.get(issue.get("type", "edge_case"), FindingType.BAD_PRACTICE),
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
                description="Address the identified issue",
                prompt=issue.get("suggestion", "Review and fix the identified issue")
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





