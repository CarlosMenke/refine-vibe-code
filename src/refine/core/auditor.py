"""Logic for classical vs. LLM triage."""

from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..config.schema import RefineConfig
from .results import Finding, ScanResults, ScanStats
from ..checkers.base import BaseChecker
from ..ui.printer import Printer


class Auditor:
    """Handles triage between classical and LLM-based checkers."""

    def __init__(self, config: RefineConfig, printer: Printer):
        self.config = config
        self.printer = printer
        self.checkers: Dict[str, BaseChecker] = {}
        self.stats = ScanStats()
        self._llm_error_shown = False  # Track if LLM error warning has been shown

    def register_checker(self, checker: BaseChecker) -> None:
        """Register a checker with the auditor."""
        self.checkers[checker.name] = checker
        self.stats.checkers_used.append(checker.name)

    def get_enabled_checkers(self) -> List[BaseChecker]:
        """Get list of enabled checkers based on configuration."""
        enabled_names = set(self.config.checkers.enabled)

        # Filter by classical/LLM only flags
        if self.config.checkers.classical_only:
            return [c for c in self.checkers.values() if c.is_classical and c.name in enabled_names]
        elif self.config.checkers.llm_only:
            return [c for c in self.checkers.values() if not c.is_classical and c.name in enabled_names]
        else:
            return [c for c in self.checkers.values() if c.name in enabled_names]

    def should_use_llm(self, file_path: Path, content: str) -> bool:
        """Determine if LLM analysis should be used for a file."""
        # Skip LLM for very large files
        if len(content) > self.config.scan.max_file_size:
            return False

        # Skip LLM for binary files or files with non-text content
        try:
            content.encode('utf-8')
        except UnicodeEncodeError:
            return False

        # Check if we have any LLM checkers enabled
        enabled_checkers = self.get_enabled_checkers()
        has_llm_checkers = any(not c.is_classical for c in enabled_checkers)

        return has_llm_checkers and not self.config.checkers.classical_only

    def audit_file(self, file_path: Path, content: str) -> List[Finding]:
        """Audit a single file with all enabled checkers."""
        findings = []
        findings.extend(self.audit_file_classical(file_path, content))
        findings.extend(self.audit_file_llm(file_path, content))
        return findings

    def audit_file_classical(self, file_path: Path, content: str) -> List[Finding]:
        """Run only classical (AST-based) checkers on a file."""
        findings = []
        enabled_checkers = self.get_enabled_checkers()
        classical_checkers = [c for c in enabled_checkers if c.is_classical]

        for checker in classical_checkers:
            try:
                checker_findings = checker.check_file(file_path, content, self.printer)
                findings.extend(checker_findings)
            except Exception as e:
                self.stats.add_error(f"Classical checker '{checker.name}' failed on {file_path}: {e}")

        return findings

    def audit_file_llm(self, file_path: Path, content: str) -> List[Finding]:
        """Run only LLM-based checkers on a file."""
        findings = []
        enabled_checkers = self.get_enabled_checkers()
        llm_checkers = [c for c in enabled_checkers if not c.is_classical]

        if not self.should_use_llm(file_path, content):
            if self.printer.debug:
                self.printer.print_debug(f"Skipping LLM checkers (should_use_llm=False)")
            return findings

        if self.printer.debug:
            self.printer.print_debug(f"Running {len(llm_checkers)} LLM checkers in parallel")

        # Run LLM checkers in parallel
        with ThreadPoolExecutor(max_workers=max(1, len(llm_checkers))) as executor:
            # Submit all LLM checker tasks
            future_to_checker = {
                executor.submit(self._run_single_llm_checker, checker, file_path, content): checker
                for checker in llm_checkers
            }

            # Collect results as they complete
            for future in as_completed(future_to_checker):
                checker = future_to_checker[future]
                try:
                    checker_findings = future.result()
                    if self.printer.debug:
                        self.printer.print_debug(f"LLM checker {checker.name} found {len(checker_findings)} findings")
                    findings.extend(checker_findings)
                    self.stats.llm_calls += 1
                except Exception as e:
                    error_msg = str(e)
                    self.stats.add_error(f"LLM checker '{checker.name}' failed on {file_path}: {error_msg}")
                    # Show big warning on first LLM error (likely config issue)
                    if not self._llm_error_shown and self._is_llm_config_error(error_msg):
                        self.printer.print_llm_error_box(error_msg)
                        self._llm_error_shown = True

        return findings

    def _run_single_llm_checker(self, checker: BaseChecker, file_path: Path, content: str) -> List[Finding]:
        """Run a single LLM checker and return its findings."""
        if self.printer.debug:
            self.printer.print_debug(f"Running LLM checker: {checker.name}")
        return checker.check_file(file_path, content, self.printer)

    def _run_batch_llm_checker(self, checker: BaseChecker, files: List[Tuple[Path, str]]) -> List[Finding]:
        """Run a single LLM checker in batch mode and return its findings."""
        try:
            # Check if checker supports batch processing
            if hasattr(checker, 'supports_batch') and checker.supports_batch():
                if self.printer.debug:
                    self.printer.print_debug(f"Using batch mode for {checker.name}")
                return checker.check_files(files, self.printer)
            else:
                # Fallback: process each file individually
                if self.printer.debug:
                    self.printer.print_debug(f"Checker {checker.name} doesn't support batch, using individual mode")
                findings = []
                for file_path, content in files:
                    checker_findings = checker.check_file(file_path, content, self.printer)
                    findings.extend(checker_findings)
                return findings
        except Exception as e:
            # Re-raise to be handled by the caller
            raise e

    def _is_llm_config_error(self, error_msg: str) -> bool:
        """Check if an error message indicates an LLM configuration issue."""
        config_error_patterns = [
            "api key",
            "api_key",
            "apikey",
            "authentication",
            "unauthorized",
            "invalid key",
            "invalid api",
            "model not found",
            "model_not_found",
            "invalid model",
            "rate limit",
            "quota",
            "billing",
            "permission denied",
            "access denied",
            "connection error",
            "timeout",
            "network",
            "404",
            "401",
            "403",
            "500",
            "502",
            "503",
        ]
        error_lower = error_msg.lower()
        return any(pattern in error_lower for pattern in config_error_patterns)

    def audit_files_batch(self, files: List[tuple]) -> List[Finding]:
        """Run LLM checkers on multiple files in batch mode.

        Args:
            files: List of (file_path, content) tuples

        Returns:
            List of findings from all files
        """
        findings = []
        enabled_checkers = self.get_enabled_checkers()
        llm_checkers = [c for c in enabled_checkers if not c.is_classical]

        if not llm_checkers:
            return findings

        if self.printer.debug:
            self.printer.print_debug(f"Batch processing {len(files)} files with {len(llm_checkers)} LLM checkers")

        # Run batch checkers in parallel
        with ThreadPoolExecutor(max_workers=max(1, len(llm_checkers))) as executor:
            # Submit all batch checker tasks
            future_to_checker = {
                executor.submit(self._run_batch_llm_checker, checker, files): checker
                for checker in llm_checkers
            }

            # Collect results as they complete
            for future in as_completed(future_to_checker):
                checker = future_to_checker[future]
                try:
                    checker_findings = future.result()
                    findings.extend(checker_findings)
                    self.stats.llm_calls += 1  # One batch call per checker
                except Exception as e:
                    error_msg = str(e)
                    self.stats.add_error(f"LLM checker '{checker.name}' failed in batch mode: {error_msg}")
                    # Show big warning on first LLM error (likely config issue)
                    if not self._llm_error_shown and self._is_llm_config_error(error_msg):
                        self.printer.print_llm_error_box(error_msg)
                        self._llm_error_shown = True

        return findings

    def triage_findings(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        """Triage findings by severity and type for reporting."""
        triaged = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }

        for finding in findings:
            if finding.severity.value in triaged:
                triaged[finding.severity.value].append(finding)

        return triaged

    def generate_recommendations(self, findings: List[Finding]) -> List[str]:
        """Generate recommendations based on findings."""
        recommendations = []

        # Count issues by type
        type_counts = {}
        for finding in findings:
            type_counts[finding.type.value] = type_counts.get(finding.type.value, 0) + 1

        # Generate recommendations based on patterns

        if type_counts.get("security_issue", 0) > 0:
            recommendations.append(
                "Security issues found. Review and fix these issues before deployment."
            )

        if type_counts.get("performance_issue", 0) > 0:
            recommendations.append(
                "Performance issues detected. Consider profiling and optimization."
            )

        if type_counts.get("bad_practice", 0) > len(findings) * 0.2:
            recommendations.append(
                "Multiple bad practices found. Consider team training or code review improvements."
            )

        return recommendations




