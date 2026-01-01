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
            # % formatting with tuples/dicts
            re.compile(r'["\'][\s\S]*?%\s*\([\s\S]*?\)[\s\S]*?["\']'),
            re.compile(r'["\'][\s\S]*?%\s*\w+[\s\S]*?["\']'),
            # .format() calls
            re.compile(r'["\'][\s\S]*?["\']\.format\('),
            # String concatenation with +
            re.compile(r'["\'][\s\S]*?["\']\s*\+\s*\w+'),
            # Direct variable interpolation without parameterization
            re.compile(r'["\'][\s\S]*?["\']\s*%\s*\([^)]*?\w+[^)]*?\)'),
        ]

        # Enhanced patterns for contextual SQL injection detection
        self.contextual_patterns = [
            # SQL with WHERE clause containing variable interpolation
            re.compile(r'(?i)select.*where.*\{.*\}.*from', re.DOTALL),
            re.compile(r'(?i)select.*where.*\+.*from', re.DOTALL),
            re.compile(r'(?i)update.*set.*where.*\{.*\}', re.DOTALL),
            re.compile(r'(?i)delete.*where.*\{.*\}', re.DOTALL),
            re.compile(r'(?i)insert.*values.*\{.*\}', re.DOTALL),

            # LIKE clauses with interpolation
            re.compile(r'(?i)like.*\{.*\}', re.DOTALL),
            re.compile(r'(?i)like.*\+.*', re.DOTALL),

            # IN clauses with interpolation
            re.compile(r'(?i)in\s*\(.*\{.*\}.*\)', re.DOTALL),

            # ORDER BY with interpolation
            re.compile(r'(?i)order\s+by.*\{.*\}', re.DOTALL),

            # Complex queries with multiple interpolations
            re.compile(r'\{.*\}.*\{.*\}', re.DOTALL),
        ]

        # Contextual patterns that suggest user input variables
        self.user_input_indicators = [
            'user', 'input', 'param', 'arg', 'data', 'value', 'search', 'query',
            'filter', 'username', 'password', 'email', 'name', 'id', 'key'
        ]

        # SQL keywords that typically require parameterization
        self.parameterizable_keywords = [
            'where', 'like', 'in', 'between', 'having', 'order by', 'group by'
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
            def __init__(self, checker, content: str, file_path: Path, contextual_patterns, user_input_indicators, parameterizable_keywords):
                self.checker = checker
                self.content = content
                self.file_path = file_path
                self.findings = []
                self.sql_context = False
                self.lines = content.splitlines()
                self.contextual_patterns = contextual_patterns
                self.user_input_indicators = user_input_indicators
                self.parameterizable_keywords = parameterizable_keywords

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

                # Contextual analysis: Check if this looks like it should be parameterized
                self._check_contextual_parameterization(node)

                # Enhanced pattern analysis
                self._check_enhanced_patterns(node)

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
                """Check f-strings in SQL context with contextual analysis."""
                line_no = call_node.lineno
                sql_text = self._extract_f_string_content(node)

                # Extract variables from the f-string
                variables = self._extract_variables_from_sql(sql_text)
                user_input_vars = [var for var in variables if self._is_user_input_variable(var)]
                has_parameterizable_clauses = self._sql_has_parameterizable_clauses(sql_text)

                # Debug print (commented out)
                # print(f"DEBUG: f-string at line {line_no}, sql_text='{sql_text}', variables={variables}, user_input_vars={user_input_vars}, has_param_clauses={has_parameterizable_clauses}")

                # Determine severity and description based on context
                if user_input_vars and has_parameterizable_clauses:
                    severity = Severity.CRITICAL
                    title = "Critical: User input interpolated in parameterizable SQL clause"
                    description = f"f-string interpolates user input variables {user_input_vars} in SQL clauses that should use parameterization"
                    confidence = 0.95
                elif user_input_vars:
                    severity = Severity.HIGH
                    title = "High risk: User input in f-string SQL query"
                    description = f"f-string contains user input variables {user_input_vars} that may be vulnerable to SQL injection"
                    confidence = 0.9
                else:
                    severity = Severity.MEDIUM
                    title = "f-string in SQL query"
                    description = "f-string usage in SQL query may be vulnerable to SQL injection"
                    confidence = 0.8

                finding = self._create_finding(
                    title=title,
                    description=description,
                    severity=severity,
                    location=Location(
                        file=self.file_path,
                        line_start=line_no,
                        line_end=line_no
                    ),
                    code_snippet=self.lines[line_no - 1] if line_no <= len(self.lines) else "",
                    evidence_type="contextual_ast",
                    confidence=confidence
                )
                self.findings.append(finding)

            def _extract_f_string_content(self, node) -> str:
                """Extract the string content from an f-string AST node."""
                content = ""
                for value in node.values:
                    if isinstance(value, ast.Str):
                        content += value.s
                    elif isinstance(value, ast.FormattedValue):
                        # This is a {variable} placeholder
                        if isinstance(value.value, ast.Name):
                            content += f"{{{value.value.id}}}"
                        else:
                            content += "{expr}"
                return content

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

            def _check_contextual_parameterization(self, node):
                """Check if the SQL call should be using parameterized queries."""
                if len(node.args) < 2:
                    return  # No parameters provided

                sql_arg = node.args[0]

                # Only check if we have string interpolation or formatting
                has_interpolation = (
                    isinstance(sql_arg, (ast.JoinedStr, ast.BinOp)) or
                    (isinstance(sql_arg, ast.Call) and
                     isinstance(sql_arg.func, ast.Attribute) and
                     sql_arg.func.attr == 'format')
                )

                if not has_interpolation:
                    return

                # Check if second argument looks like it should be parameters
                if len(node.args) > 1:
                    param_arg = node.args[1]
                    if self._looks_like_parameters(param_arg):
                        # This looks like parameters were intended but string interpolation was used
                        line_no = node.lineno
                        finding = self._create_finding(
                            title="Contextual SQL injection: Parameterized query expected",
                            description="SQL query uses string interpolation but appears to have parameters that should be used with parameterization",
                            severity=Severity.HIGH,
                            location=Location(
                                file=self.file_path,
                                line_start=line_no,
                                line_end=line_no
                            ),
                            code_snippet=self.lines[line_no - 1] if line_no <= len(self.lines) else "",
                            evidence_type="contextual",
                            confidence=0.9
                        )
                        self.findings.append(finding)

            def _looks_like_parameters(self, param_arg) -> bool:
                """Check if an AST node looks like it contains query parameters."""
                if isinstance(param_arg, ast.Tuple):
                    # Tuple of parameters like (user_input,)
                    return len(param_arg.elts) > 0
                elif isinstance(param_arg, ast.Dict):
                    # Dict of named parameters like {"username": user_input}
                    return len(param_arg.keys) > 0
                elif isinstance(param_arg, ast.Name):
                    # Variable that might contain parameters
                    var_name = param_arg.id.lower()
                    # Check if variable name suggests parameters
                    return any(indicator in var_name for indicator in self.user_input_indicators)
                return False

            def _check_enhanced_patterns(self, node):
                """Check for enhanced contextual SQL injection patterns."""
                if not node.args:
                    return

                sql_arg = node.args[0]
                sql_text = ""

                # Extract SQL text based on AST node type
                if isinstance(sql_arg, ast.Str):
                    sql_text = sql_arg.s
                elif isinstance(sql_arg, ast.JoinedStr):
                    sql_text = self._extract_f_string_content(sql_arg)
                elif isinstance(sql_arg, ast.BinOp) and isinstance(sql_arg.op, ast.Add):
                    sql_text = self._extract_concatenated_string(sql_arg)
                elif isinstance(sql_arg, ast.Call) and isinstance(sql_arg.func, ast.Attribute) and sql_arg.func.attr == 'format':
                    sql_text = self._extract_format_string(sql_arg)

                if not sql_text:
                    return

                # Check against enhanced contextual patterns
                for pattern in self.contextual_patterns:
                    if pattern.search(sql_text):
                        line_no = node.lineno

                        # Analyze the pattern to provide specific feedback
                        pattern_description = self._analyze_pattern_match(pattern, sql_text)

                        finding = self._create_finding(
                            title="Enhanced pattern: Contextual SQL injection detected",
                            description=f"{pattern_description} - SQL query uses dangerous interpolation in clauses that should be parameterized",
                            severity=Severity.HIGH,
                            location=Location(
                                file=self.file_path,
                                line_start=line_no,
                                line_end=line_no
                            ),
                            code_snippet=self.lines[line_no - 1] if line_no <= len(self.lines) else "",
                            evidence_type="enhanced_pattern",
                            confidence=0.9
                        )
                        self.findings.append(finding)
                        break  # Only report once per call

            def _extract_concatenated_string(self, node) -> str:
                """Extract string content from concatenated AST nodes."""
                result = ""
                if isinstance(node.left, ast.Str):
                    result += node.left.s
                if isinstance(node.right, ast.Str):
                    result += node.right.s
                elif isinstance(node.right, ast.Name):
                    result += f"{{{node.right.id}}}"
                return result

            def _extract_format_string(self, node) -> str:
                """Extract string content from .format() calls."""
                if node.args and isinstance(node.func.value, ast.Str):
                    template = node.func.value.s
                    # Replace {0}, {1}, etc. with placeholders
                    for i, arg in enumerate(node.args):
                        template = template.replace(f"{{{i}}}", f"{{{arg.id if isinstance(arg, ast.Name) else 'expr'}}}")
                    return template
                return ""

            def _analyze_pattern_match(self, pattern, sql_text: str) -> str:
                """Analyze what type of pattern was matched for better descriptions."""
                sql_lower = sql_text.lower()

                if 'where' in sql_lower and ('{' in sql_text or '+' in sql_text):
                    return "WHERE clause with variable interpolation"
                elif 'like' in sql_lower and ('{' in sql_text or '+' in sql_text):
                    return "LIKE clause with variable interpolation"
                elif 'in' in sql_lower and ('{' in sql_text or '+' in sql_text):
                    return "IN clause with variable interpolation"
                elif 'order by' in sql_lower and ('{' in sql_text or '+' in sql_text):
                    return "ORDER BY clause with variable interpolation"
                elif 'values' in sql_lower and ('{' in sql_text or '+' in sql_text):
                    return "INSERT VALUES with variable interpolation"
                elif sql_text.count('{') > 1:
                    return "Multiple variable interpolations in SQL query"
                else:
                    return "Complex SQL query with dangerous interpolation"

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

            def _extract_variables_from_sql(self, sql_text: str) -> List[str]:
                """Extract variable names from SQL string interpolation patterns."""
                variables = []

                # Extract variables from f-string patterns {variable}
                f_string_vars = re.findall(r'\{(\w+)\}', sql_text)
                variables.extend(f_string_vars)

                # Extract variables from % formatting
                percent_vars = re.findall(r'%\((\w+)\)', sql_text)
                variables.extend(percent_vars)

                # Extract variables from .format() style {0}, {variable}
                format_vars = re.findall(r'\{(\w+)\}', sql_text)
                variables.extend(format_vars)

                return list(set(variables))  # Remove duplicates

            def _is_user_input_variable(self, var_name: str) -> bool:
                """Check if a variable name suggests it contains user input."""
                var_lower = var_name.lower()
                return any(indicator in var_lower for indicator in self.user_input_indicators)

            def _sql_has_parameterizable_clauses(self, sql_text: str) -> bool:
                """Check if SQL contains clauses that typically need parameterization."""
                sql_lower = sql_text.lower()
                return any(keyword in sql_lower for keyword in self.parameterizable_keywords)

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

        visitor = SQLInjectionVisitor(self, content, file_path, self.contextual_patterns, self.user_input_indicators, self.parameterizable_keywords)
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
        """Create a prompt for LLM analysis of SQL injection patterns with contextual focus."""
        lines = content.splitlines()

        # Extract relevant code sections around findings
        relevant_sections = []
        for finding in classical_findings:
            start_line = max(0, finding.location.line_start - 5)  # More context
            end_line = min(len(lines), finding.location.line_start + 5)
            section = '\n'.join(lines[start_line:end_line])
            relevant_sections.append(f"Lines {start_line+1}-{end_line}:\n{section}")

        sections_text = '\n\n'.join(relevant_sections)

        prompt = f"""Analyze the following Python code sections for contextual SQL injection vulnerabilities.

CONTEXT: This is a "Contextual SQLi Audit" - focus on detecting cases where the code looks like it SHOULD be using parameterized queries but isn't. Look for:

1. Variables that appear to contain user input (names like user_input, username, password, email, search_term, etc.)
2. SQL queries that use string interpolation/formatting instead of proper parameterization
3. Cases where parameters are passed separately but the query still uses interpolation
4. SQL clauses (WHERE, LIKE, IN, ORDER BY, etc.) that typically require parameterization
5. Situations where the developer "forgot" to use parameterized queries despite having the right structure

Code sections to analyze:
{sections_text}

For each potential vulnerability, determine:
- Is this user input being interpolated into SQL?
- Should this be using parameterized queries instead?
- What specific variables look like user input?
- Is the SQL structure one that typically needs parameterization?

Provide your analysis in the following JSON format:
{{
    "vulnerabilities": [
        {{
            "line": <line_number>,
            "type": "contextual_sqli|forgot_parameterization|user_input_interpolation",
            "severity": "critical|high|medium|low",
            "description": "<detailed description explaining why this looks like it should be parameterized>",
            "user_input_variables": ["<var1>", "<var2>"],
            "recommendation": "<specific fix recommendation>"
        }}
    ],
    "overall_assessment": "<brief summary of contextual SQL injection patterns found>"
}}

If no contextual vulnerabilities are found, return an empty vulnerabilities array."""

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
        """Enhanced pattern-based analysis for contextual SQL injection detection."""
        findings = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            line_lower = line.lower()

            # Check for SQL keywords and dangerous patterns
            if any(keyword in line_lower for keyword in ['select', 'insert', 'update', 'delete']):
                # Check for dangerous interpolation patterns
                for pattern in self.dangerous_patterns:
                    if pattern.search(line):
                        # Enhanced analysis: check for user input context
                        user_input_vars = self._find_user_input_variables_in_context(lines, i)
                        has_parameterizable_clauses = self._line_has_parameterizable_clauses(line)

                        # Determine severity based on context
                        if user_input_vars and has_parameterizable_clauses:
                            severity = Severity.HIGH
                            title = "Contextual SQL injection: User input in parameterizable query"
                            description = f"Pattern matching detected user input variables {user_input_vars} in SQL query that should use parameterization"
                            confidence = 0.85
                        elif user_input_vars:
                            severity = Severity.MEDIUM
                            title = "Potential SQL injection: User input detected"
                            description = f"Detected string interpolation with user input variables {user_input_vars}"
                            confidence = 0.7
                        else:
                            severity = Severity.MEDIUM
                            title = "Potential SQL injection via pattern matching"
                            description = "Detected string interpolation patterns in SQL context"
                            confidence = 0.6

                        finding = Finding(
                            id=f"pattern_sql_injection_{i}_{hash(line)}",
                            title=title,
                            description=description,
                            severity=severity,
                            type=FindingType.SECURITY_ISSUE,
                            location=Location(
                                file=file_path,
                                line_start=i,
                                line_end=i
                            ),
                            checker_name="sql_injection",
                            evidence=[Evidence(
                                type="contextual_pattern",
                                description="Enhanced pattern-based detection with user input context analysis",
                                confidence=confidence,
                                details={"user_input_vars": user_input_vars}
                            )],
                            fixes=[Fix(
                                type=FixType.PROMPT,
                                description="Use parameterized queries",
                                prompt="Replace string interpolation with parameterized queries using ? placeholders or named parameters"
                            )],
                            code_snippet=line.strip()
                        )
                        findings.append(finding)
                        break  # Only report once per line

        return findings

    def _find_user_input_variables_in_context(self, lines: List[str], line_no: int) -> List[str]:
        """Find user input variables in the context around a SQL line."""
        user_vars = []
        # Look at surrounding lines for variable assignments and usage
        start_line = max(0, line_no - 10)
        end_line = min(len(lines), line_no + 5)

        # Pattern to find variable assignments that look like user input
        var_assignment_pattern = re.compile(r'^(\s*)(\w+)\s*=\s*(.+)$')

        for i in range(start_line, end_line):
            if i == line_no - 1:  # Skip the SQL line itself
                continue

            line = lines[i].strip()
            match = var_assignment_pattern.match(line)
            if match:
                var_name = match.group(2)
                var_value = match.group(3).strip()

                # Check if variable name suggests user input
                if self._is_user_input_variable(var_name):
                    user_vars.append(var_name)
                # Check if value looks like user input (string literals, function calls that return user input)
                elif self._looks_like_user_input_value(var_value):
                    user_vars.append(var_name)

        return list(set(user_vars))  # Remove duplicates

    def _looks_like_user_input_value(self, value: str) -> bool:
        """Check if a variable value looks like it contains user input."""
        value_lower = value.lower()

        # Check for common user input sources
        user_input_sources = [
            'input(', 'request.', 'form.', 'args.', 'get(', 'post(',
            'stdin', 'argv', 'environ', 'parameter', 'argument'
        ]

        return any(source in value_lower for source in user_input_sources)

    def _line_has_parameterizable_clauses(self, line: str) -> bool:
        """Check if a line contains SQL clauses that typically need parameterization."""
        line_lower = line.lower()
        return any(keyword in line_lower for keyword in self.parameterizable_keywords)
