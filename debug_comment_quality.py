import json
from pathlib import Path
from src.refine.checkers.llm.comment_quality import CommentQualityChecker
from refine.providers import get_provider

# Get the LLM response
checker = CommentQualityChecker()
file_path = Path('tests/bad_code_for_testing/test_bad_vibe_code_logic_stress.py')
with open(file_path, 'r') as f:
    content = f.read()

print('File length:', len(content))
print('Lines:', len(content.splitlines()))

# Create the prompt and get response directly
prompt = checker._create_analysis_prompt(file_path, content)
provider = get_provider()
response = provider.analyze_code(prompt)

print('Raw response:')
print(repr(response))
print()

# Try to parse it
try:
    # Extract JSON from markdown code blocks if present
    json_content = response.strip()
    if json_content.startswith('```json'):
        json_content = json_content[7:]  # Remove ```json
    if json_content.endswith('```'):
        json_content = json_content[:-3]  # Remove ```
    json_content = json_content.strip()

    print('JSON content to parse:')
    print(repr(json_content[:200]) + '...' if len(json_content) > 200 else repr(json_content))
    print()

    # Parse JSON
    response_data = json.loads(json_content)
    print('Successfully parsed JSON')
    print('Number of issues:', len(response_data.get('issues', [])))

    # Check each issue
    for i, issue in enumerate(response_data.get('issues', [])):
        print(f'Issue {i+1}: line {issue.get("line_number")}, title: {issue.get("title")}')

except Exception as e:
    print('JSON parsing failed:', e)
    import traceback
    traceback.print_exc()

