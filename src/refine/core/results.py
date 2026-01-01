"""Standardized finding/prompt objects for Refine Vibe Code."""

from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field
from datetime import datetime


class Severity(str, Enum):
    """Severity levels for findings."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingType(str, Enum):
    """Types of findings."""

    AI_GENERATED = "ai_generated"
    BAD_PRACTICE = "bad_practice"
    CODE_SMELL = "code_smell"
    SECURITY_ISSUE = "security_issue"
    PERFORMANCE_ISSUE = "performance_issue"
    STYLE_ISSUE = "style_issue"


class FixType(str, Enum):
    """Types of fixes available."""

    PROMPT = "prompt"  # User needs to manually fix
    AUTO_FIX = "auto_fix"  # Can be automatically fixed
    NONE = "none"  # No fix available


class Location(BaseModel):
    """Location information for a finding."""

    file: Path
    line_start: int
    line_end: Optional[int] = None
    column_start: Optional[int] = None
    column_end: Optional[int] = None

    def __str__(self) -> str:
        """String representation of location."""
        parts = [str(self.file)]
        if self.line_start > 0:
            parts.append(f"line {self.line_start}")
            if self.line_end and self.line_end != self.line_start:
                parts[-1] = f"lines {self.line_start}-{self.line_end}"
        return ":".join(parts)


class Fix(BaseModel):
    """A suggested fix for a finding."""

    type: FixType
    description: str
    prompt: Optional[str] = None  # For PROMPT type fixes
    auto_fix: Optional[Dict[str, Any]] = None  # For AUTO_FIX type fixes

    def is_auto_fixable(self) -> bool:
        """Check if this fix can be applied automatically."""
        return self.type == FixType.AUTO_FIX and self.auto_fix is not None


class Evidence(BaseModel):
    """Evidence supporting a finding."""

    type: str  # e.g., "pattern", "ast", "llm_analysis"
    description: str
    confidence: float = Field(ge=0.0, le=1.0)
    details: Optional[Dict[str, Any]] = None


class Finding(BaseModel):
    """A single finding/result from a checker."""

    id: str
    title: str
    description: str
    severity: Severity
    type: FindingType
    location: Location
    checker_name: str
    evidence: List[Evidence] = Field(default_factory=list)
    fixes: List[Fix] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.now)
    code_snippet: Optional[str] = None  # 1-2 line preview of offending code

    def has_fixes(self) -> bool:
        """Check if this finding has any suggested fixes."""
        return len(self.fixes) > 0

    def get_auto_fixes(self) -> List[Fix]:
        """Get all auto-fixable fixes."""
        return [fix for fix in self.fixes if fix.is_auto_fixable()]

    def confidence_score(self) -> float:
        """Calculate overall confidence score from evidence."""
        if not self.evidence:
            return 0.5  # Default confidence

        # Weighted average of evidence confidence
        total_weight = len(self.evidence)
        total_confidence = sum(ev.confidence for ev in self.evidence)

        return total_confidence / total_weight if total_weight > 0 else 0.5


class ScanResults(BaseModel):
    """Results from a complete scan."""

    findings: List[Finding] = Field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    scan_time: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.now)
    config_used: Optional[Dict[str, Any]] = None

    def has_issues(self) -> bool:
        """Check if the scan found any issues."""
        return len(self.findings) > 0

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_type(self, finding_type: FindingType) -> List[Finding]:
        """Get findings filtered by type."""
        return [f for f in self.findings if f.type == finding_type]

    def get_findings_by_checker(self, checker_name: str) -> List[Finding]:
        """Get findings filtered by checker."""
        return [f for f in self.findings if f.checker_name == checker_name]

    def get_findings_by_file(self, file_path: Path) -> List[Finding]:
        """Get findings filtered by file."""
        return [f for f in self.findings if f.location.file == file_path]

    def summary(self) -> Dict[str, Any]:
        """Generate a summary of the results."""
        severity_counts = {}
        type_counts = {}
        checker_counts = {}

        for finding in self.findings:
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
            type_counts[finding.type.value] = type_counts.get(finding.type.value, 0) + 1
            checker_counts[finding.checker_name] = checker_counts.get(finding.checker_name, 0) + 1

        return {
            "total_findings": len(self.findings),
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "scan_time": self.scan_time,
            "severity_breakdown": severity_counts,
            "type_breakdown": type_counts,
            "checker_breakdown": checker_counts,
        }


class ScanStats(BaseModel):
    """Statistics about the scanning process."""

    files_processed: int = 0
    files_skipped: int = 0
    checkers_used: List[str] = Field(default_factory=list)
    llm_calls: int = 0
    errors: List[str] = Field(default_factory=list)

    def add_error(self, error: str) -> None:
        """Add an error to the stats."""
        self.errors.append(error)

    def has_errors(self) -> bool:
        """Check if there were any errors during scanning."""
        return len(self.errors) > 0





