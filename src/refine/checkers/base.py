"""Abstract Base Class for all checkers."""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import List

from ..core.results import Finding


class BaseChecker(ABC):
    """Abstract base class for all code checkers."""

    def __init__(self, name: str, description: str, is_classical: bool = True):
        self.name = name
        self.description = description
        self.is_classical = is_classical  # True for AST-based, False for LLM-based

    @abstractmethod
    def check_file(self, file_path: Path, content: str) -> List[Finding]:
        """Check a single file and return findings.

        Args:
            file_path: Path to the file being checked
            content: Content of the file as a string

        Returns:
            List of Finding objects representing issues found
        """
        pass

    def supports_file(self, file_path: Path) -> bool:
        """Check if this checker supports the given file type.

        Default implementation checks file extension.
        Subclasses can override for more sophisticated checks.
        """
        return self._get_supported_extensions() and \
               file_path.suffix.lower() in self._get_supported_extensions()

    @abstractmethod
    def _get_supported_extensions(self) -> List[str]:
        """Return list of file extensions this checker supports.

        Returns:
            List of file extensions (e.g., ['.py', '.js'])
        """
        pass

    def get_metadata(self) -> dict:
        """Get metadata about this checker."""
        return {
            "name": self.name,
            "description": self.description,
            "is_classical": self.is_classical,
            "supported_extensions": self._get_supported_extensions(),
        }

    def __str__(self) -> str:
        return f"{self.name}: {self.description}"

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name='{self.name}', classical={self.is_classical})>"


def get_all_checkers() -> List[BaseChecker]:
    """Get all available checkers."""
    from .classical.package_check import PackageCheckChecker
    from .classical.boilerplate import BoilerplateChecker
    from .classical.hardcoded_secrets import HardcodedSecretsChecker
    from .classical.dependency_validation import DependencyValidationChecker
    from .llm.edge_cases import EdgeCasesChecker
    from .llm.vibe_naming import VibeNamingChecker
    from .llm.comment_quality import CommentQualityChecker
    from .llm.dangerous_ai_logic import DangerousAILogicChecker
    from .hybrid.sql_injection import SQLInjectionChecker

    return [
        PackageCheckChecker(),
        BoilerplateChecker(),
        HardcodedSecretsChecker(),
        DependencyValidationChecker(),
        EdgeCasesChecker(),
        VibeNamingChecker(),
        CommentQualityChecker(),
        DangerousAILogicChecker(),
        SQLInjectionChecker(),
    ]





