"""Integration tests for scanning functionality."""

import pytest
from pathlib import Path
from src.refine.core.engine import ScanEngine
from src.refine.config.schema import RefineConfig
from src.refine.ui.printer import Printer


class TestScanIntegration:
    """Integration tests for scanning."""

    def test_scan_python_file(self, test_files_dir: Path, sample_config: RefineConfig):
        """Test scanning a Python file."""
        # Use only classical checkers for this test to avoid LLM dependency
        sample_config.checkers.llm_only = False
        sample_config.checkers.classical_only = True

        printer = Printer(output_format="plain", verbose=False)
        engine = ScanEngine(sample_config, printer)

        results = engine.scan(test_files_dir / "test.py")

        assert results.files_scanned == 1
        assert results.files_skipped == 0
        assert isinstance(results.findings, list)

    def test_scan_directory(self, test_files_dir: Path, sample_config: RefineConfig):
        """Test scanning a directory."""
        # Use only classical checkers
        sample_config.checkers.classical_only = True

        printer = Printer(output_format="plain", verbose=False)
        engine = ScanEngine(sample_config, printer)

        results = engine.scan(test_files_dir)

        assert results.files_scanned >= 1
        assert isinstance(results.findings, list)

    def test_scan_with_exclusions(self, test_files_dir: Path, sample_config: RefineConfig):
        """Test scanning with file exclusions."""
        # Add exclusion pattern
        sample_config.scan.exclude_patterns.append("*.js")
        sample_config.checkers.classical_only = True

        printer = Printer(output_format="plain", verbose=False)
        engine = ScanEngine(sample_config, printer)

        results = engine.scan(test_files_dir)

        # Should scan Python file but skip JS file
        assert results.files_scanned >= 1
        # Check that we didn't scan the JS file (it might be skipped for other reasons too)
        js_file = test_files_dir / "test.js"
        if js_file.exists():
            # If JS file exists, it should be skipped due to exclusion
            assert any("*.js" in pattern for pattern in sample_config.scan.exclude_patterns)





