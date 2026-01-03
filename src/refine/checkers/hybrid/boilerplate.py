"""Classical checker for boilerplate code patterns."""

import re
import ast
from pathlib import Path
from typing import List, Dict, Pattern, Any, Optional, TYPE_CHECKING

from ..base import BaseChecker
from refine.core.results import Finding, Severity, FindingType, Location, Fix, FixType, Evidence

if TYPE_CHECKING:
    from refine.ui.printer import Printer


class BoilerplateChecker(BaseChecker):
    """Checker for objective code quality issues and unnecessary complexity."""

    def __init__(self):
        super().__init__(
            name="boilerplate",
            description="Detects objective code quality issues and unnecessary complexity patterns",
            is_classical=True
        )

        # Patterns for objective code quality issues
        self.boilerplate_patterns = {
            "generic_variable_names": re.compile(
                r'\b(?:temp|tmp|var|data|result|value|item|obj|object)_\d+\b'
            ),
            "unnecessary_lambda": re.compile(
                r'lambda\s+\w+\s*:\s*\w+[\[\]\.\w]*'
            ),
            "over_engineered_solution": re.compile(
                r'class\s+\w+:\s*\n\s+def\s+__init__\(self\):\s*\n\s+pass',
                re.MULTILINE
            ),
        }

    def _extract_code_snippet(self, content: str, line_number: int, context_lines: int = 1) -> str:
        """Extract a code snippet around the given line number."""
        lines = content.splitlines()
        if line_number < 1 or line_number > len(lines):
            return ""

        # Get the target line and some context
        start_line = max(0, line_number - context_lines - 1)
        end_line = min(len(lines), line_number + context_lines)

        # Extract the snippet
        snippet_lines = lines[start_line:end_line]

        # Join with line numbers for clarity
        numbered_lines = []
        for i, line in enumerate(snippet_lines, start_line + 1):
            marker = ">" if i == line_number else ""
            numbered_lines.append(f"{marker:>1} {i:3d}| {line}")

        return "\n".join(numbered_lines)

    def _get_supported_extensions(self) -> List[str]:
        return [".py"]

    def check_file(self, file_path: Path, content: str, printer: Optional["Printer"] = None) -> List[Finding]:
        """Check file for boilerplate patterns."""
        findings = []
        lines = content.splitlines()

        # For Python files, use AST-based analysis for better accuracy
        if file_path.suffix.lower() == '.py':
            findings.extend(self._check_python_ast(file_path, content))
        else:
            # For other languages, fall back to regex patterns
            for pattern_name, pattern in self.boilerplate_patterns.items():
                matches = list(pattern.finditer(content))
                for match in matches:
                    line_start = content[:match.start()].count('\n') + 1
                    line_end = content[:match.end()].count('\n') + 1

                    finding = self._create_finding_for_pattern(
                        pattern_name, match, file_path, content, lines, line_start, line_end
                    )
                    if finding:
                        findings.append(finding)

        return findings

    def _check_python_ast(self, file_path: Path, content: str) -> List[Finding]:
        """Check Python file using AST for better docstring analysis."""
        findings = []

        try:
            tree = ast.parse(content, filename=str(file_path))

            # Only check for lambda expressions and other patterns
            for node in ast.walk(tree):
                if isinstance(node, ast.Lambda):
                    lambda_issues = self._analyze_lambda(node, file_path, content)
                    findings.extend(lambda_issues)

                # Check for lambda expressions
                if isinstance(node, ast.Lambda):
                    lambda_issues = self._analyze_lambda(node, file_path, content)
                    findings.extend(lambda_issues)

            # Still check for other patterns using regex
            for pattern_name in ['unnecessary_lambda', 'over_engineered_solution', 'generic_variable_names']:
                if pattern_name in self.boilerplate_patterns:
                    pattern = self.boilerplate_patterns[pattern_name]
                    matches = list(pattern.finditer(content))
                    for match in matches:
                        line_start = content[:match.start()].count('\n') + 1
                        line_end = content[:match.end()].count('\n') + 1
                        lines = content.splitlines()

                        finding = self._create_finding_for_pattern(
                            pattern_name, match, file_path, lines, line_start, line_end
                        )
                        if finding:
                            findings.append(finding)

        except SyntaxError:
            # If AST parsing fails, fall back to regex patterns
            for pattern_name, pattern in self.boilerplate_patterns.items():
                matches = list(pattern.finditer(content))
                for match in matches:
                    line_start = content[:match.start()].count('\n') + 1
                    line_end = content[:match.end()].count('\n') + 1
                    lines = content.splitlines()

                    finding = self._create_finding_for_pattern(
                        pattern_name, match, file_path, content, lines, line_start, line_end
                    )
                    if finding:
                        findings.append(finding)

        return findings


    def _analyze_lambda(self, node: ast.Lambda, file_path: Path, content: str) -> List[Finding]:
        """Analyze lambda expression for potential unnecessary usage."""
        findings = []

        # Only flag if lambda is truly simple and unnecessary
        if self._is_unnecessary_lambda(node):
            lines = content.splitlines()
            line_start = node.lineno
            line_end = node.end_lineno or node.lineno

            # Get the lambda source code
            lambda_code = self._get_node_source(node, content)

            # Extract code snippet
            code_snippet = self._extract_code_snippet(content, line_start)

            findings.append(Finding(
                id=f"unnecessary_lambda_{file_path.name}_{line_start}",
                title="Unnecessary Lambda",
                description="Lambda function may be unnecessary and indicates AI-generated code",
                severity=Severity.LOW,
                type=FindingType.AI_GENERATED,
                location=Location(
                    file=file_path,
                    line_start=line_start,
                    line_end=line_end,
                ),
                checker_name=self.name,
                code_snippet=code_snippet,
                evidence=[Evidence(
                    type="ast_lambda",
                    description=f"Simple lambda '{lambda_code}' could potentially be replaced with a more readable alternative",
                    confidence=0.6,
                )],
                fixes=[Fix(
                    type=FixType.PROMPT,
                    description="Consider replacing lambda with a named function or alternative",
                    prompt="Consider if this lambda adds clarity or if it could be replaced with a named function, list comprehension, or built-in function"
                )]
            ))

        return findings

    def _is_unnecessary_lambda(self, node: ast.Lambda) -> bool:
        """Determine if a lambda is potentially unnecessary."""
        # Only flag very simple lambdas that just return an attribute/method call
        if len(node.args.args) != 1:
            return False

        body = node.body

        # Check for simple attribute access: lambda x: x.attr
        if isinstance(body, ast.Attribute) and isinstance(body.value, ast.Name):
            if body.value.id == node.args.args[0].arg:
                return True

        # Check for simple method calls: lambda x: x.method()
        if isinstance(body, ast.Call) and isinstance(body.func, ast.Attribute):
            if (isinstance(body.func.value, ast.Name) and
                body.func.value.id == node.args.args[0].arg and
                not body.args):  # No arguments to the method call
                return True

        # Check for dictionary access: lambda x: x['key'] or lambda x: x.key
        if isinstance(body, ast.Subscript):
            if (isinstance(body.value, ast.Name) and
                body.value.id == node.args.args[0].arg):
                return True

        # Check for simple item access: lambda x: x[index]
        if isinstance(body, ast.Subscript):
            if (isinstance(body.value, ast.Name) and
                body.value.id == node.args.args[0].arg and
                isinstance(body.slice, ast.Index) and
                isinstance(body.slice.value, (ast.Str, ast.Num))):
                return True

        return False

    def _get_node_source(self, node: ast.AST, content: str) -> str:
        """Extract source code for an AST node."""
        try:
            lines = content.splitlines()
            start_line = node.lineno - 1
            end_line = node.end_lineno - 1 if node.end_lineno else start_line

            if start_line == end_line:
                # Single line
                line = lines[start_line]
                # Try to extract just the lambda part
                start_col = getattr(node, 'col_offset', 0)
                end_col = getattr(node, 'end_col_offset', len(line))
                return line[start_col:end_col].strip()
            else:
                # Multi-line (rare for lambdas)
                return '\n'.join(lines[start_line:end_line+1]).strip()
        except:
            return "lambda expression"

    def _create_finding_for_pattern(
        self,
        pattern_name: str,
        match: re.Match,
        file_path: Path,
        content: str,
        lines: List[str],
        line_start: int,
        line_end: int
    ) -> Finding:
        """Create a finding for a specific pattern match."""

        pattern_info = {
            "generic_variable_names": {
                "title": "Generic Variable Names",
                "description": "Variable names follow generic patterns that reduce code clarity",
                "severity": Severity.LOW,
                "confidence": 0.7,
            },
            "unnecessary_lambda": {
                "title": "Unnecessary Lambda",
                "description": "Lambda function may be unnecessary - consider using a named function or built-in",
                "severity": Severity.LOW,
                "confidence": 0.6,
            },
            "over_engineered_solution": {
                "title": "Over-engineered Solution",
                "description": "Code appears over-engineered for the problem it solves",
                "severity": Severity.MEDIUM,
                "confidence": 0.7,
            },
        }

        info = pattern_info.get(pattern_name, {
            "title": "Boilerplate Pattern",
            "description": "Detected potential boilerplate code pattern",
            "severity": Severity.LOW,
            "confidence": 0.5,
        })

        # Get the matched text
        matched_text = match.group(0)
        if len(matched_text) > 100:
            matched_text = matched_text[:97] + "..."

        # Extract code snippet
        code_snippet = self._extract_code_snippet(content, line_start)

        return Finding(
            id=f"{pattern_name}_{file_path.name}_{line_start}",
            title=info["title"],
            description=info["description"],
            severity=info["severity"],
            type=FindingType.AI_GENERATED,
            location=Location(
                file=file_path,
                line_start=line_start,
                line_end=line_end if line_end > line_start else None,
            ),
            checker_name=self.name,
            code_snippet=code_snippet,
            evidence=[Evidence(
                type="pattern",
                description=f"Matched pattern: {matched_text}",
                confidence=info["confidence"],
                details={"pattern": pattern_name, "matched_text": matched_text}
            )],
            fixes=[Fix(
                type=FixType.PROMPT,
                description="Review and improve the code/comment",
                prompt="Consider rewriting this code or comment to be more specific and human-like"
            )]
        )





