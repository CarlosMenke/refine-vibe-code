#!/usr/bin/env python3

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

import json
from pathlib import Path
from refine.checkers.llm.naming_vibe import NamingVibeChecker
from refine.providers import get_provider

# Get the LLM response
checker = NamingVibeChecker()
file_path = Path('tests/bad_code_for_testing/test_naming_vibe_short.py')
with open(file_path, 'r') as f:
    content = f.read()

print('File length:', len(content))
print('Lines:', len(content.splitlines()))
print('\n' + '='*50)
print('FILE CONTENT:')
print('='*50)
print(content)
print('='*50)

# Create the prompt and get response directly
sampled_content = checker._sample_content(content)
prompt = checker._create_analysis_prompt(file_path, sampled_content)
provider = get_provider()
response = provider.analyze_code(prompt)

print('\n' + '='*50)
print('LLM PROMPT:')
print('='*50)
print(prompt[:1000] + '...' if len(prompt) > 1000 else prompt)

print('\n' + '='*50)
print('RAW LLM RESPONSE:')
print('='*50)
print(repr(response))

# Try to parse it
try:
    # Extract JSON from markdown code blocks if present
    json_content = response.strip()
    if json_content.startswith('```json'):
        json_content = json_content[7:]  # Remove ```json
    if json_content.endswith('```'):
        json_content = json_content[:-3]  # Remove ```
    json_content = json_content.strip()

    print('\n' + '='*50)
    print('PARSED JSON:')
    print('='*50)
    print('JSON content to parse:')
    print(repr(json_content[:200]) + '...' if len(json_content) > 200 else repr(json_content))

    # Parse JSON
    response_data = json.loads(json_content)
    print('Successfully parsed JSON')
    print('Number of issues:', len(response_data.get('issues', [])))

    # Check each issue
    for i, issue in enumerate(response_data.get('issues', [])):
        print(f'Issue {i+1}: line {issue.get("line_number")}, title: {issue.get("title")}')

except Exception as e:
    print(f'\nJSON parsing failed: {e}')
    import traceback
    traceback.print_exc()
