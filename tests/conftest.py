"""Pytest configuration and fixtures."""

import pytest
from pathlib import Path
from typing import Dict, Any

from src.refine.config.schema import RefineConfig


@pytest.fixture
def sample_config() -> RefineConfig:
    """Sample configuration for testing."""
    return RefineConfig()


@pytest.fixture
def test_files_dir(tmp_path: Path) -> Path:
    """Create a temporary directory with test files."""
    # Create some sample Python files
    python_file = tmp_path / "test.py"
    python_file.write_text("""
def calculate_total(items):
    \"\"\"Calculate total from list of items.\"\"\"
    total = 0
    for item in items:
        total = total + item
    return total

# Print debug info
print("Debug: calculating total")

if __name__ == "__main__":
    result = calculate_total([1, 2, 3, 4, 5])
    print(f"Total: {result}")
""")

    # Create a JavaScript file with some issues
    js_file = tmp_path / "test.js"
    js_file.write_text("""
function processData(data) {
    // This function processes the data
    let result = [];
    for (let i = 0; i < data.length; i++) {
        // Add item to result
        result.push(data[i] * 2);
    }
    return result;
}

// Debug print
console.log("Processing data");
""")

    return tmp_path


@pytest.fixture
def mock_finding() -> Dict[str, Any]:
    """Mock finding for testing."""
    return {
        "id": "test_finding_1",
        "title": "Test Finding",
        "description": "This is a test finding",
        "severity": "medium",
        "type": "bad_practice",
        "location": {
            "file": "test.py",
            "line_start": 1,
        },
        "checker_name": "test_checker",
        "evidence": [{
            "type": "test",
            "description": "Test evidence",
            "confidence": 0.8,
        }],
        "fixes": [{
            "type": "prompt",
            "description": "Test fix",
            "prompt": "Fix this issue",
        }]
    }





