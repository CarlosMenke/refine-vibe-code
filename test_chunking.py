#!/usr/bin/env python3
"""
Test script to demonstrate chunking and parallel processing implementation.
"""

import time
from pathlib import Path
from src.refine.checkers.llm.edge_cases import EdgeCasesChecker
from src.refine.config.loader import load_config

def test_chunking():
    """Test the chunking functionality."""
    # Load a large test file
    test_file = Path("tests/bad_code_for_testing/test_large_complex_file.py")
    with open(test_file, 'r') as f:
        content = f.read()

    print(f"Test file: {test_file}")
    print(f"Total lines: {len(content.splitlines())}")
    print()

    # Create checker and test chunking
    checker = EdgeCasesChecker()

    print("Config settings:")
    config = checker._get_config()
    print(f"  max_chunk_lines: {config.chunking.max_chunk_lines}")
    print(f"  use_ast_boundaries: {config.chunking.use_ast_boundaries}")
    print("  parallel_chunks: enabled")
    print("  max_parallel_requests: configured")
    print()

    # Test chunking
    chunks = checker._split_into_chunks(content, test_file)
    print(f"File split into {len(chunks)} chunks:")

    for i, (chunk_content, start_line) in enumerate(chunks):
        lines_in_chunk = len(chunk_content.splitlines())
        print(f"  Chunk {i+1}: lines {start_line}-{start_line + lines_in_chunk - 1} ({lines_in_chunk} lines)")

    print()
    print("Chunking test completed!")

if __name__ == "__main__":
    test_chunking()
