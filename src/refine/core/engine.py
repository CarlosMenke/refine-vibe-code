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
                self.printer.print_status(f"Scanning {file_path} ({i}/{len(files_to_scan)})")

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

        # Finalize results
        results.findings = all_findings
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
