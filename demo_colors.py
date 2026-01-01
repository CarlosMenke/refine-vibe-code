#!/usr/bin/env python3
"""
Demo script to show the new color-coded output and compact summary.
"""

from pathlib import Path
from src.refine.core.results import ScanResults, Finding, FindingType, Severity, Location, Evidence, Fix
from src.refine.ui.printer import Printer

def demo_colors():
    """Demonstrate the new color-coded output."""
    # Create mock findings with different types
    findings = [
        Finding(
            id="1",
            title="AI-generated function with generic naming",
            description="This function appears to be AI-generated with generic variable names and verbose comments.",
            severity=Severity.MEDIUM,
            type=FindingType.AI_GENERATED,
            location=Location(file=Path("example.py"), line_start=10),
            checker_name="naming_vibe",
            evidence=[Evidence(type="pattern", description="Generic variable names detected", confidence=0.85)],
            fixes=[Fix(type="prompt", description="Consider using more descriptive variable names", prompt="Rename variables to be more descriptive")]
        ),
        Finding(
            id="2",
            title="Bad practice: overly verbose comments",
            description="Function has redundant comments that don't add value.",
            severity=Severity.LOW,
            type=FindingType.BAD_PRACTICE,
            location=Location(file=Path("example.py"), line_start=15),
            checker_name="comment_quality",
            evidence=[Evidence(type="ast", description="Verbose comment pattern detected", confidence=0.75)],
            fixes=[Fix(type="prompt", description="Remove redundant comments", prompt="Remove comments that merely restate what the code does")]
        )
    ]

    # Create scan results
    results = ScanResults(
        findings=findings,
        files_scanned=5,
        files_skipped=1,
        scan_time=1.23
    )

    # Print results
    printer = Printer(verbose=True)
    printer.print_results(results)

if __name__ == "__main__":
    demo_colors()
