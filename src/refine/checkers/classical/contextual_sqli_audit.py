"""Classical checker for contextual SQL injection audit - detects raw string interpolation in DB queries."""

import ast
import re
from pathlib import Path
from typing import List, Optional, Set, Dict, Any, TYPE_CHECKING

from ..base import BaseChecker
from refine.core.results import Finding, Severity, FindingType, Location, Fix, FixType, Evidence

if TYPE_CHECKING:
    from refine.ui.printer import Printer


class ContextualSQLiAuditChecker(BaseChecker):
    """Checker that detects raw string interpolation in database queries where parameterized queries should be used."""

    def __init__(self):
        super().__init__(
            name="contextual_sqli_audit",
            description="Detects raw string interpolation in database queries that should use parameterized queries",
            is_classical=True
        )

        # Database-related imports and cursor creation patterns
        self.db_imports = {
            'sqlite3', 'psycopg2', 'pymysql', 'mysql.connector', 'sqlalchemy',
            'psycopg2.connect', 'sqlite3.connect', 'pymysql.connect', 'mysql.connector.connect'
        }

        # SQL keywords for detection
        self.sql_keywords = {
            'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER',
            'EXECUTE', 'EXEC', 'MERGE', 'TRUNCATE', 'WITH'
        }

        # Cursor method patterns
        self.cursor_methods = {
            'execute', 'executemany', 'executescript', 'execute_async'
        }

    def _get_supported_extensions(self) -> List[str]:
        return [".py"]

    def check_file(self, file_path: Path, content: str, printer: Optional["Printer"] = None) -> List[Finding]:
        """Check Python file for contextual SQL injection patterns."""
        findings = []

        if printer and printer.debug:
            printer.print_debug(f"Checking file {file_path.name} for contextual SQL injection")

        try:
            tree = ast.parse(content, filename=str(file_path))

            # Track database connections and cursors
            db_context = self._analyze_db_context(tree, content)

            # Look for SQL execution patterns
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    findings.extend(self._check_sql_execution_context(node, db_context, file_path, content))

        except SyntaxError:
            # Skip files with syntax errors
            pass

        return findings

    def _analyze_db_context(self, tree: ast.AST, content: str) -> Dict[str, Any]:
        """Analyze the file to understand database usage context."""
        context = {
            'connections': set(),
            'cursors': set(),
            'imports': set(),
            'has_db_activity': False
        }

        # Check imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in self.db_imports:
                        context['imports'].add(alias.name)
                        context['has_db_activity'] = True

            elif isinstance(node, ast.ImportFrom):
                if node.module and node.module in self.db_imports:
                    context['imports'].add(node.module)
                    context['has_db_activity'] = True

            # Track cursor creation
            elif isinstance(node, ast.Assign):
                if self._is_cursor_assignment(node):
                    if isinstance(node.targets[0], ast.Name):
                        context['cursors'].add(node.targets[0].id)

        return context

    def _is_cursor_assignment(self, node: ast.Assign) -> bool:
        """Check if assignment creates a database cursor."""
        if not isinstance(node.value, ast.Call):
            return False

        # Check for conn.cursor() calls
        if isinstance(node.value.func, ast.Attribute) and node.value.func.attr == 'cursor':
            return True

        return False

    def _check_sql_execution_context(self, node: ast.Call, db_context: Dict[str, Any],
                                   file_path: Path, content: str) -> List[Finding]:
        """Check SQL execution calls in context."""
        findings = []

        # Only check if we have database activity
        if not db_context['has_db_activity']:
            return findings

        # Check if this is a cursor.execute() call
        if self._is_cursor_method_call(node):
            findings.extend(self._analyze_execute_call(node, db_context, file_path, content))

        return findings

    def _is_cursor_method_call(self, node: ast.Call) -> bool:
        """Check if this is a cursor method call."""
        if not isinstance(node.func, ast.Attribute):
            return False

        method_name = node.func.attr
        return method_name in self.cursor_methods

    def _analyze_execute_call(self, node: ast.Call, db_context: Dict[str, Any],
                            file_path: Path, content: str) -> List[Finding]:
        """Analyze a cursor.execute() call for contextual SQL injection."""
        findings = []

        if not node.args:
            return findings

        sql_arg = node.args[0]
        lines = content.splitlines()
        line_content = lines[node.lineno - 1] if node.lineno <= len(lines) else ""

        # Check different types of SQL argument patterns
        if isinstance(sql_arg, ast.Constant) and isinstance(sql_arg.value, str):
            # Direct string literal - check for interpolation patterns
            findings.extend(self._check_string_literal_patterns(sql_arg, node, file_path, content))

        elif isinstance(sql_arg, (ast.JoinedStr, ast.FormattedValue)):
            # f-string usage - high risk
            findings.append(self._create_contextual_finding(
                "f-string", sql_arg, node, file_path, content, Severity.CRITICAL
            ))

        elif isinstance(sql_arg, ast.BinOp) and isinstance(sql_arg.op, ast.Add):
            # String concatenation - high risk
            findings.append(self._create_contextual_finding(
                "string concatenation", sql_arg, node, file_path, content, Severity.CRITICAL
            ))

        elif isinstance(sql_arg, ast.Call):
            # Check for format() calls and other dangerous patterns
            if self._is_format_method_call(sql_arg):
                findings.append(self._create_contextual_finding(
                    ".format() method", sql_arg, node, file_path, content, Severity.CRITICAL
                ))

        # Check for % formatting (which would be a BinOp with Mod)
        elif isinstance(sql_arg, ast.BinOp) and isinstance(sql_arg.op, ast.Mod):
            findings.append(self._create_contextual_finding(
                "% formatting", sql_arg, node, file_path, content, Severity.CRITICAL
            ))

        return findings

    def _check_string_literal_patterns(self, sql_arg: ast.Constant, node: ast.Call,
                                     file_path: Path, content: str) -> List[Finding]:
        """Check string literals for patterns that suggest missing parameterization."""
        findings = []
        sql_string = sql_arg.value

        # Look for SQL with placeholders that might be missing parameters
        if self._contains_sql_keywords(sql_string):
            # Check for format placeholders without parameters
            has_placeholders = '?' in sql_string or '%s' in sql_string or ':param' in sql_string

            if has_placeholders:
                # Check if parameters are provided
                has_params = len(node.args) > 1

                if not has_params:
                    # Missing parameters for placeholders
                    findings.append(self._create_placeholder_finding(
                        sql_arg, node, file_path, content
                    ))

            # Check for dynamic SQL patterns that suggest interpolation should be used
            elif self._suggests_interpolation(sql_string):
                findings.append(self._create_interpolation_suggestion(
                    sql_arg, node, file_path, content
                ))

        return findings

    def _contains_sql_keywords(self, sql_string: str) -> bool:
        """Check if string contains SQL keywords."""
        sql_upper = sql_string.upper()
        return any(keyword in sql_upper for keyword in self.sql_keywords)

    def _suggests_interpolation(self, sql_string: str) -> bool:
        """Check if SQL pattern suggests interpolation might be needed."""
        # Look for patterns like WHERE column = 'value' that might be dynamic
        patterns = [
            r"WHERE\s+\w+\s*=\s*['\"][^'\"]*['\"]",  # WHERE id = 'value'
            r"WHERE\s+\w+\s+LIKE\s*['\"][^'\"]*['\"]",  # WHERE name LIKE 'pattern'
            r"INSERT\s+INTO\s+\w+\s+VALUES\s*\(",  # INSERT INTO table VALUES (
        ]

        return any(re.search(pattern, sql_string, re.IGNORECASE) for pattern in patterns)

    def _is_format_method_call(self, node: ast.Call) -> bool:
        """Check if this is a .format() method call."""
        return isinstance(node.func, ast.Attribute) and node.func.attr == 'format'

    def _create_contextual_finding(self, vuln_type: str, sql_arg: ast.AST, node: ast.Call,
                                  file_path: Path, content: str, severity: Severity) -> Finding:
        """Create a contextual SQL injection finding."""
        lines = content.splitlines()
        line_content = lines[node.lineno - 1] if node.lineno <= len(lines) else ""

        severity_descriptions = {
            Severity.CRITICAL: "Critical risk - direct user input injection possible",
            Severity.HIGH: "High risk - potential injection vulnerability",
            Severity.MEDIUM: "Medium risk - unsafe pattern detected",
            Severity.LOW: "Low risk - consider using parameterized queries"
        }

        return Finding(
            id=f"contextual_sqli_{vuln_type.replace(' ', '_')}_{file_path.name}_{node.lineno}",
            title=f"Contextual SQLi: {vuln_type} in query",
            description=f"Raw {vuln_type} detected in database query. {severity_descriptions[severity]}",
            severity=severity,
            type=FindingType.SECURITY_ISSUE,
            location=Location(
                file=file_path,
                line_start=node.lineno,
                column_start=node.col_offset
            ),
            checker_name=self.name,
            code_snippet=line_content.strip(),
            evidence=[Evidence(
                type="contextual_analysis",
                description=f"Detected {vuln_type} pattern in SQL execution where parameterized queries should be used",
                confidence=0.9
            )],
            fixes=[Fix(
                type=FixType.PROMPT,
                description="Replace with parameterized query",
                prompt=self._get_parameterization_fix(vuln_type, line_content)
            )]
        )

    def _create_placeholder_finding(self, sql_arg: ast.Constant, node: ast.Call,
                                   file_path: Path, content: str) -> Finding:
        """Create finding for missing parameters with placeholders."""
        lines = content.splitlines()
        line_content = lines[node.lineno - 1] if node.lineno <= len(lines) else ""

        return Finding(
            id=f"contextual_sqli_missing_params_{file_path.name}_{node.lineno}",
            title="Contextual SQLi: Placeholders without parameters",
            description="SQL query contains placeholders (?) but no parameters provided to execute()",
            severity=Severity.HIGH,
            type=FindingType.SECURITY_ISSUE,
            location=Location(
                file=file_path,
                line_start=node.lineno,
                column_start=node.col_offset
            ),
            checker_name=self.name,
            code_snippet=line_content.strip(),
            evidence=[Evidence(
                type="contextual_analysis",
                description="SQL query with placeholders but missing parameter tuple",
                confidence=0.85
            )],
            fixes=[Fix(
                type=FixType.PROMPT,
                description="Add parameters to execute call",
                prompt="Provide parameters as tuple: cursor.execute('SELECT * FROM table WHERE id = ?', (user_id,))"
            )]
        )

    def _create_interpolation_suggestion(self, sql_arg: ast.Constant, node: ast.Call,
                                       file_path: Path, content: str) -> Finding:
        """Create finding suggesting interpolation for dynamic queries."""
        lines = content.splitlines()
        line_content = lines[node.lineno - 1] if node.lineno <= len(lines) else ""

        return Finding(
            id=f"contextual_sqli_suggest_param_{file_path.name}_{node.lineno}",
            title="Contextual SQLi: Consider parameterized query",
            description="SQL query appears to contain dynamic values that should use parameterized queries",
            severity=Severity.MEDIUM,
            type=FindingType.SECURITY_ISSUE,
            location=Location(
                file=file_path,
                line_start=node.lineno,
                column_start=node.col_offset
            ),
            checker_name=self.name,
            code_snippet=line_content.strip(),
            evidence=[Evidence(
                type="contextual_analysis",
                description="Query pattern suggests dynamic values that should be parameterized",
                confidence=0.7
            )],
            fixes=[Fix(
                type=FixType.PROMPT,
                description="Use parameterized query for dynamic values",
                prompt="Replace hardcoded values with parameters: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
            )]
        )

    def _get_parameterization_fix(self, vuln_type: str, line_content: str) -> str:
        """Generate specific fix prompt based on vulnerability type."""
        if "f-string" in vuln_type:
            return "Replace f-string with parameterized query: cursor.execute('SELECT * FROM table WHERE id = ?', (user_id,))"
        elif "concatenation" in vuln_type:
            return "Replace string concatenation with parameterized query: cursor.execute('SELECT * FROM table WHERE name = ?', (name,))"
        elif ".format()" in vuln_type:
            return "Replace .format() with parameterized query: cursor.execute('SELECT * FROM table WHERE id = ?', (user_id,))"
        elif "% formatting" in vuln_type:
            return "Replace % formatting with parameterized query: cursor.execute('SELECT * FROM table WHERE id = ?', (user_id,))"
        else:
            return "Use parameterized queries to prevent SQL injection: cursor.execute('SELECT * FROM table WHERE column = ?', (value,))"

