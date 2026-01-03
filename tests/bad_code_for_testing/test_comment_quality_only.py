#!/usr/bin/env python3
"""
Test just the comment_quality checker in isolation to measure timing.
"""

import time
import sys
import os
from pathlib import Path

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'src'))

from refine.checkers.llm.comment_quality import CommentQualityChecker

def main():
    # Use the same test file
    file_path = Path('tests/bad_code_for_testing/test_comment_quality_stress.py')

    print(f"Testing comment_quality checker on: {file_path}")
    with open(file_path, 'r') as f:
        content = f.read()

    print(f"File size: {len(content)} characters, {len(content.splitlines())} lines")
    print()

    # Create checker
    checker = CommentQualityChecker()

    # Time the check_file method
    print("Running comment_quality.check_file()...")
    start_time = time.time()

    findings = checker.check_file(file_path, content)

    end_time = time.time()
    duration = end_time - start_time

    print(f"Checker completed in {duration:.2f} seconds")
    print(f"Found {len(findings)} issues")

    # Show first few findings
    for i, finding in enumerate(findings[:3]):
        print(f"  {i+1}. {finding.title} (line {finding.location.line_start})")

    if len(findings) > 3:
        print(f"  ... and {len(findings) - 3} more")

if __name__ == "__main__":
    main()
