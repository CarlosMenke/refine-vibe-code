"""Base class for hybrid checkers that combine classical and LLM analysis."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

from ..base import BaseChecker
from refine.core.results import Finding
from refine.providers import get_provider

if TYPE_CHECKING:
    from refine.ui.printer import Printer


class HybridChecker(BaseChecker, ABC):
    """Base class for hybrid checkers combining classical and LLM analysis."""

    def __init__(self, name: str, description: str):
        super().__init__(name, description, is_classical=False)  # Hybrid is not purely classical

    def check_file(self, file_path: Path, content: str, printer: Optional["Printer"] = None) -> List[Finding]:
        """Run both classical and LLM analysis and combine results."""
        findings = []

        # Run classical analysis first
        classical_findings = self._run_classical_analysis(file_path, content, printer)
        findings.extend(classical_findings)

        # Run LLM analysis if available
        llm_findings = self._run_llm_analysis(file_path, content, printer)
        findings.extend(llm_findings)

        return findings

    @abstractmethod
    def _run_classical_analysis(self, file_path: Path, content: str, printer: Optional["Printer"] = None) -> List[Finding]:
        """Run classical (AST/pattern-based) analysis."""
        pass

    @abstractmethod
    def _run_llm_analysis(self, file_path: Path, content: str, printer: Optional["Printer"] = None) -> List[Finding]:
        """Run LLM-based analysis."""
        pass

    def _get_llm_provider(self):
        """Get LLM provider if available."""
        provider = get_provider()
        return provider if provider.is_available() else None

