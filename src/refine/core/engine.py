"""Runs the scan pipeline."""

import time
import threading
from pathlib import Path
from typing import List, Set, Optional, Dict
import fnmatch
from concurrent.futures import ThreadPoolExecutor, as_completed

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

        # Check if we should use batch processing (only if LLM checkers are enabled)
        has_llm_checkers = not self.config.checkers.classical_only and any(
            not c.is_classical for c in self.auditor.get_enabled_checkers()
        )
        use_batch = has_llm_checkers and self.config.chunking.stack_small_files
        batch_threshold_lines = int(
            self.config.chunking.max_chunk_lines * self.config.chunking.stack_threshold
        )

        # Prepare file data for parallel processing
        file_data = []
        batch_files = []

        for file_path in files_to_scan:
            try:
                # Read file content
                content = self._read_file_content(file_path)
                if content is None:
                    results.files_skipped += 1
                    continue

                file_data.append((file_path, content))

                # Collect small Python files for batch LLM processing
                if use_batch and file_path.suffix == '.py':
                    line_count = len(content.splitlines())
                    if line_count <= batch_threshold_lines:
                        batch_files.append((file_path, content))

            except Exception as e:
                self.auditor.stats.add_error(f"Failed to scan {file_path}: {e}")
                results.files_skipped += 1

        # Run parallel processing
        classical_findings, llm_findings = self._scan_files_parallel(file_data, batch_files)

        all_findings.extend(classical_findings)
        all_findings.extend(llm_findings)

        # Deduplicate findings to prevent the same line being flagged multiple times
        deduplicated_findings = self._deduplicate_findings(all_findings)

        # Finalize results
        results.findings = deduplicated_findings
        results.files_scanned = len(file_data)
        results.scan_time = time.time() - start_time
        results.config_used = self.config.model_dump()

        # Update with auditor stats
        results.files_skipped += self.auditor.stats.files_skipped

        self.printer.print_status(
            f"Scan completed in {results.scan_time:.2f}s. "
            f"Found {len(all_findings)} issues in {results.files_scanned} files."
        )

        # Print checker usage summary
        self._print_checker_usage_summary()

        return results

    def _print_checker_usage_summary(self) -> None:
        """Print summary of which checkers ran and which were skipped."""
        from ..checkers import get_all_checkers

        # Get all available checkers and their types
        all_checkers = {checker.name: checker for checker in get_all_checkers()}

        # Get enabled checkers
        enabled_checkers = self.auditor.get_enabled_checkers()
        enabled_names = {c.name for c in enabled_checkers}

        # Determine which checkers were actually used
        ran_checkers = []
        skipped_checkers = []

        for checker_name in all_checkers.keys():
            if checker_name in enabled_names:
                ran_checkers.append(checker_name)
            else:
                skipped_checkers.append(checker_name)

        # Determine if LLM was used
        llm_used = not self.config.checkers.classical_only and any(
            not c.is_classical for c in enabled_checkers
        )

        # Build the colorful summary message
        parts = []

        if ran_checkers:
            ran_formatted = ", ".join(f"[cyan]{checker}[/cyan]" for checker in sorted(ran_checkers))
            parts.append(f"[bold green]✓ Ran:[/bold green] {ran_formatted}")

        if skipped_checkers:
            skipped_formatted = ", ".join(f"[dim]{checker}[/dim]" for checker in sorted(skipped_checkers))
            parts.append(f"[yellow]⏭️ Skipped:[/yellow] {skipped_formatted}")

        if llm_used:
            parts.append("[bold blue]🤖 LLM used[/bold blue]")
        else:
            parts.append("[dim]LLM not used[/dim]")

        summary = " │ ".join(parts)

        # Print the summary with an empty line above the Scan Summary table
        self.printer.print_status("")  # Empty line
        self.printer.console.print(summary)

    def _scan_files_parallel(self, file_data: List[tuple], batch_files: List[tuple]) -> tuple:
        """Scan files in parallel using separate threads for classical and LLM checkers."""
        classical_findings = []
        llm_findings = []

        # Run classical checkers sequentially in their own thread
        def run_classical_checkers():
            nonlocal classical_findings
            for i, (file_path, content) in enumerate(file_data, 1):
                if self.printer.verbose:
                    self.printer.print_file_status(f"Running classical checkers ({i}/{len(file_data)})", file_path)
                try:
                    findings = self.auditor.audit_file_classical(file_path, content)
                    classical_findings.extend(findings)
                except Exception as e:
                    self.auditor.stats.add_error(f"Classical checkers failed on {file_path}: {e}")

        # Run LLM checkers in parallel threads
        def run_llm_checkers():
            nonlocal llm_findings
            # Use ThreadPoolExecutor for LLM checkers
            with ThreadPoolExecutor(max_workers=max(1, min(len(file_data), 10))) as executor:  # Limit workers to avoid overwhelming
                future_to_file = {}
                for file_path, content in file_data:
                    # Skip files that will be processed in batch
                    if batch_files and (file_path, content) in batch_files:
                        continue
                    future = executor.submit(self.auditor.audit_file_llm, file_path, content)
                    future_to_file[future] = file_path

                # Collect LLM results
                for future in as_completed(future_to_file):
                    file_path = future_to_file[future]
                    try:
                        findings = future.result()
                        llm_findings.extend(findings)
                        if self.printer.verbose:
                            self.printer.print_file_status("LLM checkers completed", file_path)
                    except Exception as e:
                        self.auditor.stats.add_error(f"LLM checkers failed on {file_path}: {e}")

        # Start classical checkers in their own thread
        classical_thread = threading.Thread(target=run_classical_checkers)
        classical_thread.start()

        # Run LLM checkers in parallel (this will block until complete)
        run_llm_checkers()

        # Wait for classical thread to complete
        classical_thread.join()

        # Handle batch processing if needed
        if batch_files:
            if self.printer.verbose:
                self.printer.print_status(
                    f"Batch processing {len(batch_files)} small files for LLM analysis..."
                )
            try:
                batch_findings = self.auditor.audit_files_batch(batch_files)
                llm_findings.extend(batch_findings)
            except Exception as e:
                self.auditor.stats.add_error(f"Batch LLM processing failed: {e}")

        return classical_findings, llm_findings

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
