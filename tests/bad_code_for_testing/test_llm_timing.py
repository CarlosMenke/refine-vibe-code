#!/usr/bin/env python3
"""
Direct LLM API timing test for comment quality analysis.
Bypasses refine code to test raw API performance.
"""

import time
import json
from pathlib import Path

def create_comment_quality_prompt(file_path: Path, content: str) -> str:
    """Create the same prompt that refine uses for comment quality analysis."""

    language = "Python"
    comment_syntax = "# for single line, ''' or \"\"\" for docstrings/multi-line"

    return f"""Analyze this {language} code for poor quality comments and docstrings that appear to be AI-generated or unnecessary. Look for:

1. Comments that simply restate what the code does without adding value
2. Generic or boilerplate docstrings (e.g., "This function does X" where X is obvious)
3. Overly verbose comments that don't provide meaningful insight
4. Comments that contradict or don't match the code
5. Docstrings that use generic templates or phrases
6. Redundant comments that explain obvious operations
7. Comments with poor grammar or robotic phrasing typical of AI generation
8. Docstrings that don't follow language conventions or are unnecessarily detailed

Code file: {file_path.name}
Language: {language}
Comment syntax: {comment_syntax}

Code:
```python
{content}
```

Provide your analysis in the following JSON format:
{{
  "issues": [
    {{
      "type": "unnecessary_comment|redundant_docstring|ai_generated_comment|generic_docstring",
      "severity": "low|medium|high",
      "title": "Brief title",
      "description": "Detailed description of why this comment/docstring is problematic",
      "line_number": 42,
      "confidence": 0.8,
      "comment_type": "single_line|multi_line|docstring",
      "suggested_action": "remove|improve|replace",
      "suggested_text": "Better comment text (optional)"
    }}
  ]
}}

Focus on actual issues. If no significant issues are found, return {{"issues": []}}."""

def main():
    # Use the same test file that's causing issues
    file_path = Path('tests/bad_code_for_testing/test_comment_quality_stress.py')

    print(f"Loading file: {file_path}")
    with open(file_path, 'r') as f:
        content = f.read()

    print(f"File size: {len(content)} characters")
    print(f"File lines: {len(content.splitlines())}")
    print()

    # Create the same prompt that refine uses
    prompt = create_comment_quality_prompt(file_path, content)
    print(f"Prompt size: {len(prompt)} characters")
    print(f"Prompt tokens (rough estimate): {len(prompt.split()) * 1.3:.0f}")
    print()

    # Make direct API call
    try:
        import openai

        print("Making direct LLM API call...")
        start_time = time.time()

        client = openai.OpenAI(
            api_key="AIzaSyBejp0MayLQU6eFnUWk_BOGFVf4w6xYPAQ",
            base_url="https://generativelanguage.googleapis.com/v1beta/openai/"
        )

        response = client.chat.completions.create(
            model="gemini-2.0-flash",
            messages=[
                {
                    "role": "system",
                    "content": "You are a code analysis expert. Analyze code for issues, bugs, and improvements. Be precise and focus on actual problems."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            temperature=0.1,
            max_tokens=10000,
            timeout=120  # 2 minutes timeout
        )

        end_time = time.time()
        duration = end_time - start_time

        print(f"API call completed in {duration:.2f} seconds")

        result = response.choices[0].message.content
        print(f"Response size: {len(result)} characters")

        # Try to parse the JSON response
        try:
            # Extract JSON from markdown code blocks if present
            json_content = result.strip()
            if json_content.startswith('```json'):
                json_content = json_content[7:]  # Remove ```json
            if json_content.endswith('```'):
                json_content = json_content[:-3]  # Remove ```
            json_content = json_content.strip()

            response_data = json.loads(json_content)
            print(f"Successfully parsed JSON with {len(response_data.get('issues', []))} issues found")

        except Exception as e:
            print(f"JSON parsing failed: {e}")

        print("\n" + "="*50)
        print("RESPONSE PREVIEW:")
        print("="*50)
        print(result[:500] + "..." if len(result) > 500 else result)

    except Exception as e:
        print(f"API call failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
