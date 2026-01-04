"""AST-based code chunker for intelligent file splitting."""

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple


@dataclass
class CodeBlock:
    """Represents a logical code block (function, class, or module-level code)."""
    start_line: int
    end_line: int
    block_type: str  # 'function', 'class', 'async_function', 'module_code'
    name: Optional[str] = None


@dataclass
class Chunk:
    """A chunk of code ready for analysis."""
    content: str
    start_line: int
    end_line: int
    file_path: Optional[Path] = None
    is_stacked: bool = False  # True if this chunk contains multiple files


@dataclass
class FileContent:
    """Represents a file's content for stacking."""
    path: Path
    content: str
    line_count: int


class ASTChunker:
    """Chunks code based on AST boundaries (functions/classes)."""

    def __init__(self, max_chunk_lines: int = 150):
        self.max_chunk_lines = max_chunk_lines

    def _parse_code_blocks(self, content: str) -> List[CodeBlock]:
        """Parse Python code and extract logical blocks."""
        try:
            tree = ast.parse(content)
        except SyntaxError:
            # If parsing fails, return empty list (will fall back to line-based)
            return []

        blocks = []
        lines = content.splitlines()
        total_lines = len(lines)

        # Track which lines belong to top-level definitions
        covered_lines = set()

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.FunctionDef):
                end_line = self._find_block_end(node, lines)
                blocks.append(CodeBlock(
                    start_line=node.lineno,
                    end_line=end_line,
                    block_type='function',
                    name=node.name
                ))
                covered_lines.update(range(node.lineno, end_line + 1))
            elif isinstance(node, ast.AsyncFunctionDef):
                end_line = self._find_block_end(node, lines)
                blocks.append(CodeBlock(
                    start_line=node.lineno,
                    end_line=end_line,
                    block_type='async_function',
                    name=node.name
                ))
                covered_lines.update(range(node.lineno, end_line + 1))
            elif isinstance(node, ast.ClassDef):
                end_line = self._find_block_end(node, lines)
                blocks.append(CodeBlock(
                    start_line=node.lineno,
                    end_line=end_line,
                    block_type='class',
                    name=node.name
                ))
                covered_lines.update(range(node.lineno, end_line + 1))

        # Add module-level code blocks (imports, global variables, etc.)
        module_code_start = None
        for i in range(1, total_lines + 1):
            if i not in covered_lines:
                line = lines[i - 1].strip()
                if line and not line.startswith('#'):  # Non-empty, non-comment
                    if module_code_start is None:
                        module_code_start = i
            else:
                if module_code_start is not None:
                    blocks.append(CodeBlock(
                        start_line=module_code_start,
                        end_line=i - 1,
                        block_type='module_code',
                        name=None
                    ))
                    module_code_start = None

        # Handle trailing module code
        if module_code_start is not None:
            blocks.append(CodeBlock(
                start_line=module_code_start,
                end_line=total_lines,
                block_type='module_code',
                name=None
            ))

        # Sort by start line
        blocks.sort(key=lambda b: b.start_line)
        return blocks

    def _find_block_end(self, node: ast.AST, lines: List[str]) -> int:
        """Find the actual end line of a block, including all nested content."""
        # Use end_lineno if available (Python 3.8+)
        if hasattr(node, 'end_lineno') and node.end_lineno:
            return node.end_lineno

        # Fallback: find by indentation
        start_line = node.lineno
        if start_line > len(lines):
            return start_line

        # Get the indentation of the definition line
        def_line = lines[start_line - 1]
        base_indent = len(def_line) - len(def_line.lstrip())

        end_line = start_line
        for i in range(start_line, len(lines)):
            line = lines[i]
            if not line.strip():  # Empty line
                continue
            current_indent = len(line) - len(line.lstrip())
            if i > start_line - 1 and current_indent <= base_indent and line.strip():
                break
            end_line = i + 1

        return end_line

    def chunk_content(self, content: str, file_path: Optional[Path] = None) -> List[Chunk]:
        """Split content into chunks based on AST boundaries.

        Strategy:
        1. Parse code into logical blocks (functions, classes, module code)
        2. Group adjacent blocks until max_chunk_lines is reached
        3. Never split a single function/class across chunks
        4. If a single block exceeds max_chunk_lines, keep it as one chunk
        """
        lines = content.splitlines()
        total_lines = len(lines)

        # Small files: return as single chunk
        if total_lines <= self.max_chunk_lines:
            return [Chunk(
                content=content,
                start_line=1,
                end_line=total_lines,
                file_path=file_path
            )]

        # Parse AST blocks
        blocks = self._parse_code_blocks(content)

        # If no blocks found (syntax error or empty), fall back to line-based
        if not blocks:
            return self._chunk_by_lines(content, file_path)

        # Group blocks into chunks
        chunks = []
        current_blocks: List[CodeBlock] = []
        current_line_count = 0

        for block in blocks:
            block_lines = block.end_line - block.start_line + 1

            # If adding this block would exceed limit, finalize current chunk
            if current_blocks and current_line_count + block_lines > self.max_chunk_lines:
                chunk = self._create_chunk_from_blocks(current_blocks, lines, file_path)
                chunks.append(chunk)
                current_blocks = []
                current_line_count = 0

            current_blocks.append(block)
            current_line_count += block_lines

        # Don't forget the last chunk
        if current_blocks:
            chunk = self._create_chunk_from_blocks(current_blocks, lines, file_path)
            chunks.append(chunk)

        return chunks

    def _create_chunk_from_blocks(
        self, blocks: List[CodeBlock], lines: List[str], file_path: Optional[Path]
    ) -> Chunk:
        """Create a chunk from a list of code blocks."""
        start_line = blocks[0].start_line
        end_line = blocks[-1].end_line

        # Include any leading content (imports, etc.) for the first block
        # by looking for content before the first block
        if blocks[0].start_line > 1:
            # Check if there's module-level code before
            for i in range(blocks[0].start_line - 1, 0, -1):
                line = lines[i - 1].strip()
                if line and not line.startswith('#'):
                    # Found non-empty, non-comment line
                    # Include everything from line 1 if this is early in the file
                    if i <= 10:  # Within first 10 lines (likely imports)
                        start_line = 1
                    break

        chunk_lines = lines[start_line - 1:end_line]
        content = '\n'.join(chunk_lines)

        return Chunk(
            content=content,
            start_line=start_line,
            end_line=end_line,
            file_path=file_path
        )

    def _chunk_by_lines(self, content: str, file_path: Optional[Path] = None) -> List[Chunk]:
        """Fallback: simple line-based chunking without overlap."""
        lines = content.splitlines()
        total_lines = len(lines)
        chunks = []

        start_line = 0
        while start_line < total_lines:
            end_line = min(start_line + self.max_chunk_lines, total_lines)
            chunk_lines = lines[start_line:end_line]
            chunk_content = '\n'.join(chunk_lines)

            chunks.append(Chunk(
                content=chunk_content,
                start_line=start_line + 1,
                end_line=end_line,
                file_path=file_path
            ))

            start_line = end_line

        return chunks


class FileStacker:
    """Stacks multiple small files into single chunks."""

    def __init__(self, max_chunk_lines: int = 150, stack_threshold: float = 0.5):
        self.max_chunk_lines = max_chunk_lines
        self.stack_threshold = stack_threshold
        self.chunker = ASTChunker(max_chunk_lines)

    def stack_files(self, files: List[Tuple[Path, str]]) -> List[Chunk]:
        """Stack multiple files into chunks.

        Args:
            files: List of (file_path, content) tuples

        Returns:
            List of Chunks, where some may contain multiple files
        """
        chunks = []
        current_files: List[FileContent] = []
        current_line_count = 0
        threshold_lines = int(self.max_chunk_lines * self.stack_threshold)

        for file_path, content in files:
            lines = content.splitlines()
            line_count = len(lines)

            # Large file: process separately with AST chunker
            if line_count > self.max_chunk_lines:
                # First, finalize any pending stacked files
                if current_files:
                    chunks.extend(self._create_stacked_chunks(current_files))
                    current_files = []
                    current_line_count = 0

                # Chunk the large file
                file_chunks = self.chunker.chunk_content(content, file_path)
                chunks.extend(file_chunks)
                continue

            # Check if adding this file would exceed threshold
            # We stack when under threshold, not when we'd exceed max
            if current_files and current_line_count + line_count > threshold_lines:
                # Finalize current stack
                chunks.extend(self._create_stacked_chunks(current_files))
                current_files = []
                current_line_count = 0

            # Add file to current stack
            current_files.append(FileContent(
                path=file_path,
                content=content,
                line_count=line_count
            ))
            current_line_count += line_count

        # Don't forget remaining files
        if current_files:
            chunks.extend(self._create_stacked_chunks(current_files))

        return chunks

    def _create_stacked_chunks(self, files: List[FileContent]) -> List[Chunk]:
        """Create chunks from stacked files."""
        if len(files) == 1:
            # Single file, no stacking needed
            f = files[0]
            return [Chunk(
                content=f.content,
                start_line=1,
                end_line=f.line_count,
                file_path=f.path,
                is_stacked=False
            )]

        # Multiple files: combine with file markers
        combined_parts = []
        for f in files:
            # Add file header
            header = f"# === FILE: {f.path.name} ===\n"
            combined_parts.append(header + f.content)

        combined_content = "\n\n".join(combined_parts)
        total_lines = len(combined_content.splitlines())

        return [Chunk(
            content=combined_content,
            start_line=1,
            end_line=total_lines,
            file_path=None,  # Multiple files
            is_stacked=True
        )]


def add_line_numbers(content: str, start_line: int = 1) -> str:
    """Add line numbers to code for LLM reference."""
    lines = content.splitlines()
    numbered_lines = []
    for i, line in enumerate(lines, start_line):
        numbered_lines.append(f"{i:4d}| {line}")
    return '\n'.join(numbered_lines)
