"""Unit tests for comment quality checker."""

import pytest
from pathlib import Path
from src.refine.checkers.llm.comment_quality import CommentQualityChecker


class TestCommentQualityChecker:
    """Test CommentQualityChecker functionality."""

    def test_checker_initialization(self):
        """Test that the checker initializes correctly."""
        checker = CommentQualityChecker()
        assert checker.name == "comment_quality"
        assert checker.description == "Uses LLM to detect unnecessary, redundant, or AI-generated comments and docstrings"
        assert not checker.is_classical

    def test_supported_extensions(self):
        """Test supported file extensions."""
        checker = CommentQualityChecker()
        extensions = checker._get_supported_extensions()
        expected = [".py", ".js", ".ts", ".java", ".cpp", ".c", ".go", ".rs", ".php", ".rb"]
        assert extensions == expected

    def test_supports_file_type(self):
        """Test file type support checking."""
        checker = CommentQualityChecker()
        assert checker.supports_file(Path("test.py"))
        assert checker.supports_file(Path("test.js"))
        assert checker.supports_file(Path("test.java"))
        assert not checker.supports_file(Path("test.txt"))

    def test_has_comments_detection(self):
        """Test comment/docstring detection."""
        checker = CommentQualityChecker()

        # Python file with comments/docstrings
        python_code = '''
def function():
    """This is a docstring."""
    # This is a comment
    pass
'''
        assert checker._has_comments_or_docstrings(python_code, ".py")

        # Python file without comments
        no_comments = "def function():\n    pass\n"
        assert not checker._has_comments_or_docstrings(no_comments, ".py")

        # JavaScript file with comments
        js_code = '''
function test() {
    // This is a comment
    return true;
}
'''
        assert checker._has_comments_or_docstrings(js_code, ".js")

    def test_skip_large_files(self):
        """Test that large files are skipped."""
        checker = CommentQualityChecker()

        # Create a large file (more than 500 lines)
        large_content = "# comment\n" * 600
        findings = checker.check_file(Path("large.py"), large_content)
        assert findings == []

    def test_skip_small_files(self):
        """Test that very small files are skipped."""
        checker = CommentQualityChecker()

        # Create a very small file (less than 5 lines)
        small_content = "x = 1\n"
        findings = checker.check_file(Path("small.py"), small_content)
        assert findings == []

    def test_get_comment_syntax(self):
        """Test comment syntax retrieval."""
        checker = CommentQualityChecker()

        assert "# for single line, ''' or \"\"\" for docstrings/multi-line" in checker._get_comment_syntax(".py")
        assert "// for single line, /* */ for multi-line" in checker._get_comment_syntax(".js")
        assert "// for single line, /* */ for multi-line" in checker._get_comment_syntax(".cpp")

    def test_create_analysis_prompt(self):
        """Test prompt creation."""
        checker = CommentQualityChecker()
        test_file = Path("test.py")
        test_content = "def test():\n    pass"

        prompt = checker._create_analysis_prompt(test_file, test_content)

        assert "test.py" in prompt
        assert "Python" in prompt
        assert "Analyze this Python code" in prompt
        assert "unnecessary" in prompt
        assert "AI-generated" in prompt
        assert test_content in prompt
