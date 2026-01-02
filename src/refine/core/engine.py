"""Runs the scan pipeline."""

import time
from pathlib import Path
from typing import List, Set, Optional
import fnmatch

from ..config.schema import RefineConfig
from .auditor import Auditor
from .results import ScanResults, ScanStats, Finding
from ..ui.printer import Printer
class ScanEngine:
    """Main scanning engine that orchestrates the analysis pipeline."""

    def __init__(self, config: RefineConfig, printer: Printer):
        self.config = config
        self.printer = printer
        self.auditor = Auditor(config, printer)

        # Register all available checkers
        from ..checkers import get_all_checkers
        for checker in get_all_checkers():
            self.auditor.register_checker(checker)

    def scan(self, path: Path) -> ScanResults:
        """Run the complete scan pipeline on the given path."""
        start_time = time.time()

        self.printer.print_status("Starting scan...")

        # Discover files to scan
        files_to_scan = self._discover_files(path)
        self.printer.print_status(f"Found {len(files_to_scan)} files to scan")

        # Initialize results
        results = ScanResults()
        all_findings = []

        # Process each file
        for i, file_path in enumerate(files_to_scan, 1):
            if self.printer.verbose:
                self.printer.print_file_status(f"Scanning ({i}/{len(files_to_scan)})", file_path)

            try:
                # Read file content
                content = self._read_file_content(file_path)
                if content is None:
                    results.files_skipped += 1
                    continue

                # Audit the file
                findings = self.auditor.audit_file(file_path, content)
                all_findings.extend(findings)

                results.files_scanned += 1

            except Exception as e:
                self.auditor.stats.add_error(f"Failed to scan {file_path}: {e}")
                results.files_skipped += 1

        # Deduplicate findings to prevent the same line being flagged multiple times
        deduplicated_findings = self._deduplicate_findings(all_findings)

        # Finalize results
        results.findings = deduplicated_findings
        results.files_scanned = len(files_to_scan) - results.files_skipped
        results.scan_time = time.time() - start_time
        results.config_used = self.config.model_dump()

        # Update with auditor stats
        results.files_skipped += self.auditor.stats.files_skipped

        self.printer.print_status(
            f"Scan completed in {results.scan_time:.2f}s. "
            f"Found {len(all_findings)} issues in {results.files_scanned} files."
        )

        return results

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Deduplicate findings to prevent the same line being flagged multiple times."""
        if not findings:
            return findings

        # Group findings by (file_path, line_number)
        finding_groups = {}
        for finding in findings:
            key = (str(finding.location.file), finding.location.line_start or 0)
            if key not in finding_groups:
                finding_groups[key] = []
            finding_groups[key].append(finding)

        deduplicated = []

        for (file_path, line_num), group_findings in finding_groups.items():
            if len(group_findings) == 1:
                # No duplicates, keep the single finding
                deduplicated.append(group_findings[0])
            else:
                # Multiple findings for same line, deduplicate
                deduplicated.extend(self._resolve_duplicates(group_findings))

        return deduplicated

    def _resolve_duplicates(self, findings: List[Finding]) -> List[Finding]:
        """Resolve duplicate findings for the same line."""
        if not findings:
            return findings

        # Special handling for SQL injection checkers - they often detect the same issues
        sql_injection_checkers = {'contextual_sqli_audit', 'sql_injection'}
        sql_findings = [f for f in findings if f.checker_name in sql_injection_checkers]
        other_findings = [f for f in findings if f.checker_name not in sql_injection_checkers]

        if len(sql_findings) > 1:
            # If we have multiple SQL injection findings, keep only the one with highest severity
            # Prefer sql_injection over contextual_sqli_audit if same severity
            severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            sql_findings.sort(key=lambda f: (
                -severity_order.get(f.severity.value, 0),  # Higher severity first
                1 if f.checker_name == 'sql_injection' else 0,  # Prefer sql_injection
                -f.confidence_score()  # Higher confidence first
            ))
            # Keep only the best SQL finding
            sql_findings = sql_findings[:1]

        # Return deduplicated SQL findings plus any other findings
        return sql_findings + other_findings

    def _discover_files(self, path: Path) -> List[Path]:
        """Discover files to scan based on configuration."""
        files = []

        if path.is_file():
            if self._should_scan_file(path):
                files.append(path)
            return files

        # Walk directory tree
        for root, dirs, filenames in os.walk(path):
            root_path = Path(root)

            # Skip excluded directories
            dirs[:] = [d for d in dirs if not self._should_skip_directory(root_path / d)]

            for filename in filenames:
                file_path = root_path / filename
                if self._should_scan_file(file_path):
                    files.append(file_path)

                    # Check file limit
                    if len(files) >= self.config.scan.max_files:
                        self.printer.print_warning(
                            f"Reached maximum file limit ({self.config.scan.max_files}). "
                            "Some files may not be scanned."
                        )
                        break

            if len(files) >= self.config.scan.max_files:
                break

        return files

    def _should_scan_file(self, file_path: Path) -> bool:
        """Check if a file should be scanned based on patterns."""
        # Check file size
        try:
            if file_path.stat().st_size > self.config.scan.max_file_size:
                return False
        except OSError:
            return False

        # Check include patterns
        included = False
        for pattern in self.config.scan.include_patterns:
            if fnmatch.fnmatch(str(file_path), pattern):
                included = True
                break

        if not included:
            return False

        # Check exclude patterns
        for pattern in self.config.scan.exclude_patterns:
            if fnmatch.fnmatch(str(file_path), pattern):
                return False

        return True

    def _should_skip_directory(self, dir_path: Path) -> bool:
        """Check if a directory should be skipped."""
        dir_str = str(dir_path) + "/"

        for pattern in self.config.scan.exclude_patterns:
            if pattern.endswith("/"):
                if fnmatch.fnmatch(dir_str, pattern):
                    return True
            elif fnmatch.fnmatch(str(dir_path), pattern):
                return True

        return False

    def _read_file_content(self, file_path: Path) -> Optional[str]:
        """Read file content safely."""
        try:
            # Check file size again
            if file_path.stat().st_size > self.config.scan.max_file_size:
                return None

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()

        except (OSError, UnicodeDecodeError):
            return None


# Import here to avoid circular imports
import os
