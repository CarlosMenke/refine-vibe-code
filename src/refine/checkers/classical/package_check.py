"""Classical checker for package and import issues."""

import ast
import re
from pathlib import Path
from typing import List, Dict, Set, Optional, TYPE_CHECKING

from ..base import BaseChecker
from refine.core.results import Finding, Severity, FindingType, Location, Fix, FixType, Evidence

if TYPE_CHECKING:
    from refine.ui.printer import Printer


class PackageCheckChecker(BaseChecker):
    """Checker for Python package and import issues."""

    def __init__(self):
        super().__init__(
            name="package_check",
            description="Checks for Python packaging and import issues",
            is_classical=True
        )

    def _get_supported_extensions(self) -> List[str]:
        return [".py"]

    def check_file(self, file_path: Path, content: str, printer: Optional["Printer"] = None) -> List[Finding]:
        """Check a Python file for packaging and import issues."""
        findings = []

        if printer and printer.debug:
            printer.print_debug(f"Checking file {file_path.name} for package issues")

        try:
            # Parse the AST
            tree = ast.parse(content, filename=str(file_path))

            # Check for various issues
            findings.extend(self._check_imports(tree, file_path, content))
            findings.extend(self._check_package_structure(file_path, content))
            findings.extend(self._check_common_issues(tree, file_path, content))

        except SyntaxError as e:
            # Report syntax errors as findings
            findings.append(Finding(
                id=f"syntax_error_{file_path.name}_{e.lineno}",
                title="Syntax Error",
                description=f"Syntax error in Python file: {e.msg}",
                severity=Severity.HIGH,
                type=FindingType.BAD_PRACTICE,
                location=Location(
                    file=file_path,
                    line_start=e.lineno or 1,
                    column_start=e.offset or 1
                ),
                checker_name=self.name,
                evidence=[Evidence(
                    type="syntax",
                    description=f"SyntaxError: {e.msg}",
                    confidence=1.0
                )]
            ))

        return findings

    def _check_imports(self, tree: ast.AST, file_path: Path, content: str) -> List[Finding]:
        """Check for import-related issues."""
        findings = []
        lines = content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                findings.extend(self._check_import_statement(node, file_path, lines))
            elif isinstance(node, ast.ImportFrom):
                findings.extend(self._check_import_from_statement(node, file_path, lines))

        return findings

    def _check_import_statement(self, node: ast.Import, file_path: Path, lines: List[str]) -> List[Finding]:
        """Check import statements for issues."""
        findings = []

        for alias in node.names:
            module_name = alias.name

            # Check for wildcard imports
            if alias.asname == "*":
                findings.append(Finding(
                    id=f"wildcard_import_{file_path.name}_{node.lineno}",
                    title="Wildcard Import",
                    description=f"Wildcard import 'import {module_name}' makes code harder to understand",
                    severity=Severity.MEDIUM,
                    type=FindingType.BAD_PRACTICE,
                    location=Location(
                        file=file_path,
                        line_start=node.lineno,
                        column_start=node.col_offset
                    ),
                    checker_name=self.name,
                    evidence=[Evidence(
                        type="ast",
                        description="AST analysis detected wildcard import",
                        confidence=1.0
                    )],
                    fixes=[Fix(
                        type=FixType.PROMPT,
                        description="Replace wildcard import with explicit imports",
                        prompt=f"Replace 'import {module_name}' with explicit imports of only the needed symbols"
                    )]
                ))

        return findings

    def _check_import_from_statement(self, node: ast.ImportFrom, file_path: Path, lines: List[str]) -> List[Finding]:
        """Check 'from X import Y' statements for issues."""
        findings = []

        if node.module is None:
            return findings

        # Check for relative imports with too many dots
        if node.level > 2:
            findings.append(Finding(
                id=f"deep_relative_import_{file_path.name}_{node.lineno}",
                title="Deep Relative Import",
                description=f"Deep relative import with {node.level} levels may indicate package structure issues",
                severity=Severity.LOW,
                type=FindingType.BAD_PRACTICE,
                location=Location(
                    file=file_path,
                    line_start=node.lineno,
                    column_start=node.col_offset
                ),
                checker_name=self.name,
                evidence=[Evidence(
                    type="ast",
                    description=f"Relative import with {node.level} dots",
                    confidence=0.9
                )]
            ))

        # Check for wildcard imports from modules
        for alias in node.names:
            if alias.name == "*":
                findings.append(Finding(
                    id=f"wildcard_from_import_{file_path.name}_{node.lineno}",
                    title="Wildcard From Import",
                    description=f"Wildcard import 'from {node.module} import *' reduces code clarity",
                    severity=Severity.MEDIUM,
                    type=FindingType.BAD_PRACTICE,
                    location=Location(
                        file=file_path,
                        line_start=node.lineno,
                        column_start=node.col_offset
                    ),
                    checker_name=self.name,
                    evidence=[Evidence(
                        type="ast",
                        description="AST analysis detected wildcard from import",
                        confidence=1.0
                    )]
                ))

        return findings

    def _check_package_structure(self, file_path: Path, content: str) -> List[Finding]:
        """Check for package structure issues."""
        findings = []

        # Check if the immediate parent directory is a package (has __init__.py)
        # Only check the immediate parent, not all ancestors
        parent_dir = file_path.parent
        if parent_dir.name.startswith('.'):
            return findings

        init_file = parent_dir / "__init__.py"
        if not init_file.exists():
            # Look for other Python files in the same directory
            py_files = list(parent_dir.glob("*.py"))
            if len(py_files) > 1:  # More than just this file and potentially __init__.py
                findings.append(Finding(
                    id=f"missing_init_{parent_dir.name}_{file_path.name}",
                    title="Missing __init__.py",
                    description=f"Directory {parent_dir.name} contains Python files but no __init__.py",
                    severity=Severity.LOW,
                    type=FindingType.BAD_PRACTICE,
                    location=Location(file=file_path, line_start=1),
                    checker_name=self.name,
                    evidence=[Evidence(
                        type="filesystem",
                        description=f"Found {len(py_files)} Python files in directory {parent_dir.name} without __init__.py",
                        confidence=0.8
                    )]
                ))

        return findings

    def _check_common_issues(self, tree: ast.AST, file_path: Path, content: str) -> List[Finding]:
        """Check for common Python issues."""
        findings = []
        lines = content.splitlines()

        # Check for print statements (potential debug code)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
                if node.lineno <= len(lines):
                    line_content = lines[node.lineno - 1].strip()
                    findings.append(Finding(
                        id=f"debug_print_{file_path.name}_{node.lineno}",
                        title="Debug Print Statement",
                        description="Print statement found - may be leftover debug code",
                        severity=Severity.LOW,
                        type=FindingType.BAD_PRACTICE,
                        location=Location(
                            file=file_path,
                            line_start=node.lineno,
                            column_start=node.col_offset
                        ),
                        checker_name=self.name,
                        evidence=[Evidence(
                            type="ast",
                            description=f"Found print statement: {line_content}",
                            confidence=0.7
                        )],
                        fixes=[Fix(
                            type=FixType.PROMPT,
                            description="Remove debug print statement or replace with proper logging",
                            prompt="Consider removing this print statement or replacing it with proper logging"
                        )]
                    ))

        return findings





