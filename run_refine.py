#!/usr/bin/env python
"""Simple wrapper script to run refine with uv."""
import sys
import os

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Import and run the main app
from refine.main import app

def main():
    """Entry point for uv run refine."""
    app()

if __name__ == '__main__':
    main()
