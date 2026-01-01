"""Hybrid checker for SQL injection vulnerabilities.

Combines classical AST-based analysis with LLM deep logic to detect
SQL injection vulnerabilities, particularly raw string interpolation
in database queries where parameterized queries should be used.
"""

import ast
import re
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple, Optional

from ..base import BaseChecker
from refine.core.results import Finding, Severity, FindingType, Location, Fix, FixType, Evidence
from refine.providers import get_provider


class SQLInjectionChecker(BaseChecker):
    """Hybrid checker for SQL injection vulnerabilities using Bandit-style analysis + LLM."""

    def __init__(self):
        super().__init__(
            name="sql_injection",
            description="Detects SQL injection vulnerabilities, especially raw string interpolation in DB queries",
            is_classical=True  # Primary classical with LLM enhancement
        )

        # SQL-related function and method names to monitor
        self.sql_functions = {
            'execute', 'executemany', 'executescript', 'cursor.execute',
            'connection.execute', 'db.execute', 'sqlite3.execute',
            'psycopg2.execute', 'pymysql.execute', 'mysql.connector.execute'
        }

        # SQL-related imports to detect
        self.sql_imports = {
            'sqlite3', 'psycopg2', 'pymysql', 'mysql.connector',
            'sqlalchemy', 'peewee', 'pony.orm'
        }

        # Dangerous string formatting patterns in SQL context
        self.dangerous_patterns = [
            # f-string usage
            re.compile(r'f["\'][\s\S]*?\{.*?\}[\s\S]*?["\']'),
            # % formatting
            re.compile(r'["\'][\s\S]*?%\s*\([\s\S]*?\)[\s\S]*?["\']'),
            re.compile(r'["\'][\s\S]*?%\s*\w+[\s\S]*?["\']'),
            # .format() calls
            re.compile(r'["\'][\s\S]*?["\']\.format\('),
            # String concatenation with +
            re.compile(r'["\'][\s\S]*?["\']\s*\+\s*\w+'),
            # Direct variable interpolation without parameterization
            re.compile(r'["\'][\s\S]*?["\']\s*%\s*\([^)]*?\w+[^)]*?\)'),
        ]

    def _get_supported_extensions(self) -> List[str]:
        """Return supported file extensions."""
        return ['.py']  # Focus on Python for now

    def check_file(self, file_path: Path, content: str) -> List[Finding]:
        """Check a file for SQL injection vulnerabilities using hybrid analysis."""
        findings = []

        # Skip if file doesn't contain SQL-related imports
        if not self._has_sql_imports(content):
            return findings

        try:
            # Parse the AST for classical analysis
            tree = ast.parse(content, filename=str(file_path))
            classical_findings = self._classical_analysis(tree, content, file_path)
            findings.extend(classical_findings)

            # Use LLM for deeper analysis of suspicious patterns
            llm_findings = self._llm_analysis(content, file_path, classical_findings)
            findings.extend(llm_findings)

        except SyntaxError:
            # If file has syntax errors, still try basic pattern matching
            pattern_findings = self._pattern_based_analysis(content, file_path)
            findings.extend(pattern_findings)

        return findings

    def _has_sql_imports(self, content: str) -> bool:
        """Check if the file imports SQL-related modules."""
        lines = content.splitlines()
        for line in lines:
            line = line.strip()
            if line.startswith('import ') or line.startswith('from '):
                for sql_import in self.sql_imports:
                    if sql_import in line:
                        return True
        return False

    def _classical_analysis(self, tree: ast.AST, content: str, file_path: Path) -> List[Finding]:
        """Perform classical AST-based analysis for SQL injection patterns."""
        findings = []

        class SQLInjectionVisitor(ast.NodeVisitor):
            def __init__(self, checker, content: str, file_path: Path):
                self.checker = checker
                self.content = content
                self.file_path = file_path
                self.findings = []
                self.sql_context = False
                self.lines = content.splitlines()

            def visit_Call(self, node):
                # Check for SQL execution functions
                func_name = self._get_full_func_name(node.func)
                if any(sql_func in func_name for sql_func in self.checker.sql_functions):
                    self.sql_context = True
                    self._analyze_sql_call(node)
                    self.sql_context = False
                else:
                    # Check for SQL-related method calls
                    if isinstance(node.func, ast.Attribute) and node.func.attr in ['execute', 'executemany']:
                        self.sql_context = True
                        self._analyze_sql_call(node)
                        self.sql_context = False

                self.generic_visit(node)

            def _analyze_sql_call(self, node):
                """Analyze a SQL execution call for injection vulnerabilities."""
                if not node.args:
                    return

                # Check first argument (SQL query)
                sql_arg = node.args[0]

                if isinstance(sql_arg, ast.Str):
                    # Direct string literal - check for dangerous patterns
                    self._check_string_literal(sql_arg)

                elif isinstance(sql_arg, ast.BinOp) and isinstance(sql_arg.op, ast.Add):
                    # String concatenation
                    self._check_string_concatenation(sql_arg, node)

                elif isinstance(sql_arg, ast.JoinedStr):
                    # f-string
                    self._check_f_string(sql_arg, node)

                elif isinstance(sql_arg, ast.Call):
                    # Check for .format() calls
                    if isinstance(sql_arg.func, ast.Attribute) and sql_arg.func.attr == 'format':
                        self._check_format_call(sql_arg, node)

            def _check_string_literal(self, node):
                """Check string literals for dangerous SQL patterns."""
                sql_text = node.s
                if self._has_dangerous_sql_patterns(sql_text):
                    line_no = node.lineno
                    finding = self._create_finding(
                        title="Potentially vulnerable SQL query",
                        description="SQL query contains string formatting patterns that may be vulnerable to injection",
                        severity=Severity.MEDIUM,
                        location=Location(
                            file=self.file_path,
                            line_start=line_no,
                            line_end=line_no
                        ),
                        code_snippet=self.lines[line_no - 1] if line_no <= len(self.lines) else "",
                        evidence_type="pattern",
                        confidence=0.7
                    )
                    self.findings.append(finding)

            def _check_string_concatenation(self, node, call_node):
                """Check string concatenation in SQL context."""
                line_no = call_node.lineno
                finding = self._create_finding(
                    title="SQL string concatenation detected",
                    description="String concatenation in SQL query is vulnerable to SQL injection",
                    severity=Severity.HIGH,
                    location=Location(
                        file=self.file_path,
                        line_start=line_no,
                        line_end=line_no
                    ),
                    code_snippet=self.lines[line_no - 1] if line_no <= len(self.lines) else "",
                    evidence_type="ast",
                    confidence=0.9
                )
                self.findings.append(finding)

            def _check_f_string(self, node, call_node):
                """Check f-strings in SQL context."""
                line_no = call_node.lineno
                finding = self._create_finding(
                    title="f-string in SQL query",
                    description="f-string usage in SQL query may be vulnerable to SQL injection",
                    severity=Severity.HIGH,
                    location=Location(
                        file=self.file_path,
                        line_start=line_no,
                        line_end=line_no
                    ),
                    code_snippet=self.lines[line_no - 1] if line_no <= len(self.lines) else "",
                    evidence_type="ast",
                    confidence=0.8
                )
                self.findings.append(finding)

            def _check_format_call(self, node, call_node):
                """Check .format() calls in SQL context."""
                line_no = call_node.lineno
                finding = self._create_finding(
                    title="String formatting in SQL query",
                    description=".format() usage in SQL query may be vulnerable to SQL injection",
                    severity=Severity.HIGH,
                    location=Location(
                        file=self.file_path,
                        line_start=line_no,
                        line_end=line_no
                    ),
                    code_snippet=self.lines[line_no - 1] if line_no <= len(self.lines) else "",
                    evidence_type="ast",
                    confidence=0.8
                )
                self.findings.append(finding)

            def _get_full_func_name(self, func_node) -> str:
                """Get the full function/method name from an AST node."""
                if isinstance(func_node, ast.Name):
                    return func_node.id
                elif isinstance(func_node, ast.Attribute):
                    return self._get_full_func_name(func_node.value) + '.' + func_node.attr
                return ""

            def _has_dangerous_sql_patterns(self, sql_text: str) -> bool:
                """Check if SQL text contains dangerous patterns."""
                sql_lower = sql_text.lower()
                # Look for SELECT, INSERT, UPDATE, DELETE followed by user input patterns
                if not any(keyword in sql_lower for keyword in ['select', 'insert', 'update', 'delete']):
                    return False

                # Check for variable interpolation patterns, but exclude parameterized placeholders
                # Allow %s, %d, %(name)s style parameters but flag other % usage
                if '%' in sql_text:
                    # Check if % is used for parameterization (like %s, %(name)s) vs interpolation
                    import re
                    # Allow common parameterized patterns
                    param_patterns = [
                        r'%\(.*?\)[sd]',  # %(name)s, %(name)d
                        r'%[sd]',         # %s, %d
                    ]
                    # Remove valid parameterized patterns and check if % remains
                    test_sql = sql_text
                    for pattern in param_patterns:
                        test_sql = re.sub(pattern, '', test_sql)
                    if '%' in test_sql:
                        return True

                # Check for f-string style {variable} patterns
                if '{' in sql_text and '}' in sql_text:
                    return True

                # String concatenation is always dangerous in SQL context
                if '+' in sql_text:
                    return True

                return False

            def _create_finding(self, title: str, description: str, severity: Severity,
                              location: Location, code_snippet: str, evidence_type: str,
                              confidence: float) -> Finding:
                """Create a standardized finding."""
                return Finding(
                    id=f"sql_injection_{location.line_start}_{hash(title)}",
                    title=title,
                    description=description,
                    severity=severity,
                    type=FindingType.SECURITY_ISSUE,
                    location=location,
                    checker_name="sql_injection",
                    evidence=[Evidence(
                        type=evidence_type,
                        description=f"Detected via {evidence_type} analysis",
                        confidence=confidence
                    )],
                    fixes=[Fix(
                        type=FixType.PROMPT,
                        description="Use parameterized queries instead of string interpolation",
                        prompt="Replace string interpolation with parameterized queries using ? placeholders or named parameters"
                    )],
                    code_snippet=code_snippet.strip()
                )

        visitor = SQLInjectionVisitor(self, content, file_path)
        visitor.visit(tree)
        return visitor.findings

    def _llm_analysis(self, content: str, file_path: Path, classical_findings: List[Finding]) -> List[Finding]:
        """Use LLM for deeper analysis of SQL injection patterns."""
        findings = []

        if not classical_findings:
            return findings

        try:
            provider = get_provider()

            # Create analysis prompt focusing on the suspicious areas
            prompt = self._create_llm_prompt(content, classical_findings)

            # Get LLM analysis
            response = provider.analyze_code(prompt)

            # Parse LLM response and create additional findings
            llm_findings = self._parse_llm_response(response, file_path, content)
            findings.extend(llm_findings)

        except Exception:
            # If LLM analysis fails, continue without it
            pass

        return findings

    def _create_llm_prompt(self, content: str, classical_findings: List[Finding]) -> str:
        """Create a prompt for LLM analysis of SQL injection patterns."""
        lines = content.splitlines()

        # Extract relevant code sections around findings
        relevant_sections = []
        for finding in classical_findings:
            start_line = max(0, finding.location.line_start - 3)
            end_line = min(len(lines), finding.location.line_start + 3)
            section = '\n'.join(lines[start_line:end_line])
            relevant_sections.append(f"Lines {start_line+1}-{end_line}:\n{section}")

        sections_text = '\n\n'.join(relevant_sections)

        prompt = f"""Analyze the following Python code sections for SQL injection vulnerabilities.
Focus on database queries and check if user input is properly sanitized or if parameterized queries are used.

Code sections to analyze:
{sections_text}

Please identify:
1. Any SQL injection vulnerabilities
2. Whether parameterized queries are properly used
3. If user input is directly interpolated into SQL strings
4. Any other security concerns related to database operations

Provide your analysis in the following JSON format:
{{
    "vulnerabilities": [
        {{
            "line": <line_number>,
            "type": "sql_injection|parameterization_missing|user_input_unsanitized",
            "severity": "high|medium|low",
            "description": "<detailed description>",
            "recommendation": "<fix recommendation>"
        }}
    ],
    "overall_assessment": "<brief summary>"
}}

If no vulnerabilities are found, return an empty vulnerabilities array."""

        return prompt

    def _parse_llm_response(self, response: str, file_path: Path, content: str) -> List[Finding]:
        """Parse LLM response and create findings."""
        findings = []
        lines = content.splitlines()

        try:
            import json
            # Try to extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                json_response = response[json_start:json_end]
                data = json.loads(json_response)

                for vuln in data.get('vulnerabilities', []):
                    line_no = vuln.get('line', 1)
                    vuln_type = vuln.get('type', 'sql_injection')
                    severity_str = vuln.get('severity', 'medium')
                    description = vuln.get('description', '')
                    recommendation = vuln.get('recommendation', '')

                    # Map string severity to enum
                    severity_map = {
                        'low': Severity.LOW,
                        'medium': Severity.MEDIUM,
                        'high': Severity.HIGH,
                        'critical': Severity.CRITICAL
                    }
                    severity = severity_map.get(severity_str.lower(), Severity.MEDIUM)

                    finding = Finding(
                        id=f"llm_sql_injection_{line_no}_{hash(description)}",
                        title=f"LLM-detected SQL injection: {vuln_type}",
                        description=description,
                        severity=severity,
                        type=FindingType.SECURITY_ISSUE,
                        location=Location(
                            file=file_path,
                            line_start=line_no,
                            line_end=line_no
                        ),
                        checker_name="sql_injection",
                        evidence=[Evidence(
                            type="llm_analysis",
                            description="Detected via LLM deep logic analysis",
                            confidence=0.8,
                            details={"llm_response": response}
                        )],
                        fixes=[Fix(
                            type=FixType.PROMPT,
                            description=recommendation,
                            prompt=recommendation
                        )],
                        code_snippet=lines[line_no - 1] if 0 < line_no <= len(lines) else ""
                    )
                    findings.append(finding)

        except (json.JSONDecodeError, KeyError, IndexError):
            # If JSON parsing fails, create a generic finding
            pass

        return findings

    def _pattern_based_analysis(self, content: str, file_path: Path) -> List[Finding]:
        """Fallback pattern-based analysis when AST parsing fails."""
        findings = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            line_lower = line.lower()

            # Check for SQL keywords and dangerous patterns
            if any(keyword in line_lower for keyword in ['select', 'insert', 'update', 'delete']):
                for pattern in self.dangerous_patterns:
                    if pattern.search(line):
                        finding = Finding(
                            id=f"pattern_sql_injection_{i}_{hash(line)}",
                            title="Potential SQL injection via pattern matching",
                            description="Detected string interpolation patterns in SQL context",
                            severity=Severity.MEDIUM,
                            type=FindingType.SECURITY_ISSUE,
                            location=Location(
                                file=file_path,
                                line_start=i,
                                line_end=i
                            ),
                            checker_name="sql_injection",
                            evidence=[Evidence(
                                type="pattern",
                                description="Pattern-based detection of dangerous SQL string handling",
                                confidence=0.6
                            )],
                            fixes=[Fix(
                                type=FixType.PROMPT,
                                description="Use parameterized queries",
                                prompt="Replace string interpolation with parameterized queries using ? placeholders"
                            )],
                            code_snippet=line.strip()
                        )
                        findings.append(finding)
                        break  # Only report once per line

        return findings
