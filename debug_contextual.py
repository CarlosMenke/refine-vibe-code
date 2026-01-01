#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from pathlib import Path
from refine.checkers.hybrid.sql_injection import SQLInjectionChecker

def test_contextual_checker():
    checker = SQLInjectionChecker()
    test_file = Path("tests/bad_code_for_testing/test_contextual_sql_injection.py")

    with open(test_file, 'r') as f:
        content = f.read()

    print(f"File has SQL imports: {checker._has_sql_imports(content)}")
    print(f"Checker is classical: {checker.is_classical}")

    findings = checker.check_file(test_file, content)
    print(f"Found {len(findings)} findings:")
    for i, finding in enumerate(findings, 1):
        print(f"  {i}. {finding.title} ({finding.severity}) - Line {finding.location.line_start}")

if __name__ == "__main__":
    test_contextual_checker()
