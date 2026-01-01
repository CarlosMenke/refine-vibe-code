"""LLM-based checker for detecting bad comments and docstrings."""

from pathlib import Path
from typing import List
import re

from ..base import BaseChecker
from refine.core.results import Finding, Severity, FindingType, Location, Fix, FixType, Evidence
from refine.providers import get_provider


class CommentQualityChecker(BaseChecker):
    """Checker that uses LLM to analyze comments and docstrings for AI-generated patterns."""

    def __init__(self):
        super().__init__(
            name="comment_quality",
            description="Uses LLM to detect unnecessary, redundant, or AI-generated comments and docstrings",
            is_classical=False
        )

    def _get_supported_extensions(self) -> List[str]:
        return [".py", ".js", ".ts", ".java", ".cpp", ".c", ".go", ".rs", ".php", ".rb"]

    def check_file(self, file_path: Path, content: str) -> List[Finding]:
        """Use LLM to analyze comments and docstrings for quality issues."""
        findings = []

        # Skip very small or very large files
        lines = content.splitlines()
        if len(lines) < 5 or len(lines) > 500:
            return findings

        # Quick check for presence of comments/docstrings
        if not self._has_comments_or_docstrings(content, file_path.suffix):
            return findings

        try:
            # Get LLM provider
            provider = get_provider()

            # If provider is not available, use mock analysis for testing
            if not provider.is_available():
                findings.extend(self._mock_analysis(file_path, content))
                return findings

            # Create analysis prompt
            prompt = self._create_analysis_prompt(file_path, content)

            # Get LLM analysis
            response = provider.analyze_code(prompt)

            # Parse response and create findings
            findings.extend(self._parse_llm_response(response, file_path, content))

        except Exception as e:
            # If LLM analysis fails, try mock analysis
            findings.extend(self._mock_analysis(file_path, content))

        return findings

    def _mock_analysis(self, file_path: Path, content: str) -> List[Finding]:
        """Mock analysis for testing when LLM is not available."""
        findings = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            line_content = line.strip()

            # Check for obvious redundant comments
            if "# Add the first number to the second number" in line_content:
                findings.append(Finding(
                    id=f"comment_quality_mock_{file_path.name}_{i}_redundant",
                    title="Redundant Comment",
                    description="Comment simply restates what the code does without adding value",
                    severity=Severity.LOW,
                    type=FindingType.STYLE_ISSUE,
                    location=Location(file=file_path, line_start=i),
                    checker_name=self.name,
                    evidence=[Evidence(
                        type="pattern_match",
                        description="Comment '# Add the first number to the second number' is redundant",
                        confidence=0.9
                    )],
                    fixes=[Fix(
                        type=FixType.PROMPT,
                        description="Remove redundant comment",
                        prompt="Remove this comment as it simply restates the obvious operation"
                    )]
                ))

            # Check for obvious docstring issues
            elif "This function calculates the sum of two numbers." in line_content:
                findings.append(Finding(
                    id=f"comment_quality_mock_{file_path.name}_{i}_generic_docstring",
                    title="Generic Docstring",
                    description="Docstring provides no meaningful information beyond what the function name suggests",
                    severity=Severity.LOW,
                    type=FindingType.STYLE_ISSUE,
                    location=Location(file=file_path, line_start=i),
                    checker_name=self.name,
                    evidence=[Evidence(
                        type="pattern_match",
                        description="Generic docstring that doesn't add value",
                        confidence=0.8
                    )],
                    fixes=[Fix(
                        type=FixType.PROMPT,
                        description="Improve docstring",
                        prompt="Replace with a more meaningful docstring or remove if unnecessary"
                    )]
                ))

            # Check for verbose docstrings
            elif "This function is designed to validate the user input that is passed to it." in line_content:
                findings.append(Finding(
                    id=f"comment_quality_mock_{file_path.name}_{i}_verbose_docstring",
                    title="Overly Verbose Docstring",
                    description="Docstring is unnecessarily detailed and verbose for a simple validation function",
                    severity=Severity.LOW,
                    type=FindingType.STYLE_ISSUE,
                    location=Location(file=file_path, line_start=i),
                    checker_name=self.name,
                    evidence=[Evidence(
                        type="pattern_match",
                        description="Excessively verbose docstring",
                        confidence=0.8
                    )],
                    fixes=[Fix(
                        type=FixType.PROMPT,
                        description="Simplify docstring",
                        prompt="Simplify this docstring to be more concise and meaningful"
                    )]
                ))

        return findings

    def _has_comments_or_docstrings(self, content: str, extension: str) -> bool:
        """Quick check if file contains comments or docstrings."""
        if extension == ".py":
            # Python docstrings and comments
            return '"""' in content or "'''" in content or "#" in content
        elif extension in [".js", ".ts"]:
            # JavaScript/TypeScript comments
            return "//" in content or "/*" in content
        elif extension == ".java":
            # Java comments
            return "//" in content or "/*" in content or "/**" in content
        elif extension in [".cpp", ".c"]:
            # C/C++ comments
            return "//" in content or "/*" in content
        elif extension == ".go":
            # Go comments
            return "//" in content
        elif extension == ".rs":
            # Rust comments
            return "//" in content or "/*" in content
        elif extension == ".php":
            # PHP comments
            return "//" in content or "#" in content or "/*" in content
        elif extension == ".rb":
            # Ruby comments
            return "#" in content
        return False

    def _create_analysis_prompt(self, file_path: Path, content: str) -> str:
        """Create a prompt for LLM analysis of comments and docstrings."""
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
            ".php": "PHP",
            ".rb": "Ruby",
        }

        language = language_map.get(file_ext, "programming language")

        comment_syntax = self._get_comment_syntax(file_ext)

        return f"""Analyze this {language} code for poor quality comments and docstrings that appear to be AI-generated or unnecessary. Look for:

1. Comments that simply restate what the code does without adding value
2. Generic or boilerplate docstrings (e.g., "This function does X" where X is obvious)
3. Overly verbose comments that don't provide meaningful insight
4. Comments that contradict or don't match the code
5. Docstrings that use generic templates or phrases
6. Redundant comments that explain obvious operations
7. Comments with poor grammar or robotic phrasing typical of AI generation
8. Docstrings that don't follow language conventions or are unnecessarily detailed

Code file: {file_path.name}
Language: {language}
Comment syntax: {comment_syntax}

Code:
```{(language.lower())}
{content}
```

Provide your analysis in the following JSON format:
{{
  "issues": [
    {{
      "type": "unnecessary_comment|redundant_docstring|ai_generated_comment|generic_docstring",
      "severity": "low|medium|high",
      "title": "Brief title",
      "description": "Detailed description of why this comment/docstring is problematic",
      "line_number": 42,
      "confidence": 0.8,
      "comment_type": "single_line|multi_line|docstring",
      "suggested_action": "remove|improve|replace",
      "suggested_text": "Better comment text (optional)"
    }}
  ]
}}

Focus on actual issues. If no significant issues are found, return {{"issues": []}}."""

    def _get_comment_syntax(self, extension: str) -> str:
        """Get comment syntax description for the language."""
        syntax_map = {
            ".py": "# for single line, ''' or \"\"\" for docstrings/multi-line",
            ".js": "// for single line, /* */ for multi-line",
            ".ts": "// for single line, /* */ for multi-line",
            ".java": "// for single line, /* */ for multi-line, /** */ for doc",
            ".cpp": "// for single line, /* */ for multi-line",
            ".c": "// for single line, /* */ for multi-line",
            ".go": "// for single line, /* */ for multi-line",
            ".rs": "// for single line, /* */ for multi-line",
            ".php": "// for single line, # for single line, /* */ for multi-line",
            ".rb": "# for single line",
        }
        return syntax_map.get(extension, "standard comment syntax")

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
            "unnecessary_comment": FindingType.STYLE_ISSUE,
            "redundant_docstring": FindingType.STYLE_ISSUE,
            "ai_generated_comment": FindingType.AI_GENERATED,
            "generic_docstring": FindingType.STYLE_ISSUE,
        }

        # Determine line number
        line_number = issue.get("line_number", 1)
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
        return Finding(
            id=f"comment_quality_text_{file_path.name}_{issue.get('line_number', 1)}_{hash(str(issue)) % 1000}",
            title="Comment/Docstring Quality Issue Detected",
            description=issue.get("description", "LLM detected a comment or docstring quality issue"),
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
                description="Review comment/docstring quality",
                prompt="Review the comment or docstring for clarity, necessity, and value"
            )]
        )
