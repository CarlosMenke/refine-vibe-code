"""Base class for LLM-based checkers with chunking and parallel processing support."""

from pathlib import Path
from typing import List, Optional, TYPE_CHECKING
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..base import BaseChecker
from refine.core.results import Finding, Severity, FindingType, Location, Fix, FixType, Evidence
from refine.core.chunker import ASTChunker, add_line_numbers, FileStacker
from refine.providers import get_provider
from refine.config.loader import load_config

if TYPE_CHECKING:
    from refine.ui.printer import Printer


class LLMBaseChecker(BaseChecker):
    """Base class for LLM-based checkers with advanced chunking and parallel processing."""

    def __init__(self, name: str, description: str):
        super().__init__(name, description, is_classical=False)
        # Lazy-loaded config and chunker
        self._config = None
        self._chunker = None

    def _get_config(self):
        """Load config (no caching for now to debug)."""
        return load_config()

    def _get_chunker(self) -> ASTChunker:
        """Get or create the AST chunker with config settings."""
        if self._chunker is None:
            config = self._get_config()
            max_lines = config.chunking.max_chunk_lines
            self._chunker = ASTChunker(max_chunk_lines=max_lines)
        return self._chunker

    @property
    def max_chunk_lines(self) -> int:
        """Get max chunk lines from config."""
        return self._get_config().chunking.max_chunk_lines

    @property
    def use_ast_boundaries(self) -> bool:
        """Check if AST boundary chunking is enabled."""
        return self._get_config().chunking.use_ast_boundaries

    def _split_into_chunks(self, content: str, file_path: Optional[Path] = None) -> List[tuple]:
        """Split content into chunks with line offset information.

        Uses AST-based chunking if enabled, falling back to line-based chunking.
        No overlap is used - chunks are split at logical boundaries.

        Returns list of (chunk_content, start_line) tuples.
        """
        lines = content.splitlines()
        total_lines = len(lines)

        # Small files: return as single chunk
        if total_lines <= self.max_chunk_lines:
            return [(content, 1)]

        # Use AST-based chunking if enabled
        if self.use_ast_boundaries:
            chunker = self._get_chunker()
            chunks = chunker.chunk_content(content, file_path)

            result = []
            for chunk in chunks:
                # Add line numbers to help LLM identify positions
                numbered_content = add_line_numbers(chunk.content, chunk.start_line)
                result.append((numbered_content, chunk.start_line))
            return result

        # Fallback: simple line-based chunking without overlap
        chunks = []
        start_line = 0

        while start_line < total_lines:
            end_line = min(start_line + self.max_chunk_lines, total_lines)
            chunk_lines = lines[start_line:end_line]
            chunk_content = '\n'.join(chunk_lines)

            # Add line numbers to help LLM identify positions
            numbered_chunk = add_line_numbers(chunk_content, start_line + 1)
            chunks.append((numbered_chunk, start_line + 1))

            # Move to next chunk (no overlap)
            start_line = end_line

        return chunks

    def _analyze_chunk(
        self,
        provider,
        file_path: Path,
        chunk_content: str,
        start_line: int,
        content: str,
        printer: Optional["Printer"] = None
    ) -> List[Finding]:
        """Analyze a single chunk with the LLM provider."""
        prompt = self._create_analysis_prompt(file_path, chunk_content, start_line)

        if printer and printer.debug:
            printer.print_debug(f"LLM prompt for {file_path.name} (lines {start_line}+): {prompt[:200]}...")

        response = provider.analyze_code(prompt)

        if printer and printer.debug:
            printer.print_debug(f"LLM response for {file_path.name}: {response[:1000]}...")

        return self._parse_llm_response(response, file_path, content)

    def check_file(self, file_path: Path, content: str, printer: Optional["Printer"] = None) -> List[Finding]:
        """Use LLM to analyze code with chunking and parallel processing."""
        findings = []

        # Quick check for code content (subclasses can override)
        if not self._has_code_content(content):
            return findings

        try:
            # Get LLM provider
            provider = get_provider()

            # If provider is not available, return empty findings
            if not provider.is_available():
                return findings

            # Split large files into chunks to avoid response truncation
            chunks = self._split_into_chunks(content, file_path)
            seen_lines = set()  # Track line numbers to deduplicate findings

            config = self._get_config()
            use_parallel = getattr(config.chunking, 'parallel_chunks', True) and len(chunks) > 1
            max_workers = max(1, getattr(config.chunking, 'max_parallel_requests', 4))

            if use_parallel:
                # Process chunks in parallel for faster scanning
                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    future_to_chunk = {
                        executor.submit(
                            self._analyze_chunk,
                            provider,
                            file_path,
                            chunk_content,
                            start_line,
                            content,
                            printer
                        ): start_line
                        for chunk_content, start_line in chunks
                    }

                    for future in as_completed(future_to_chunk):
                        try:
                            chunk_findings = future.result()
                            for finding in chunk_findings:
                                line = finding.location.line_start
                                if line not in seen_lines:
                                    seen_lines.add(line)
                                    findings.append(finding)
                        except Exception as e:
                            if printer and printer.debug:
                                printer.print_debug(f"Chunk analysis failed: {e}")
            else:
                # Sequential processing (single chunk or parallel disabled)
                for chunk_content, start_line in chunks:
                    chunk_findings = self._analyze_chunk(
                        provider, file_path, chunk_content, start_line, content, printer
                    )
                    for finding in chunk_findings:
                        line = finding.location.line_start
                        if line not in seen_lines:
                            seen_lines.add(line)
                            findings.append(finding)

        except Exception as e:
            # Re-raise the exception so the auditor can show a proper warning
            # The auditor will catch this and display the LLM error warning box
            raise

        return findings

    def supports_batch(self) -> bool:
        """Check if this checker supports batch processing of multiple files."""
        config = self._get_config()
        return config.chunking.stack_small_files

    def check_files(
        self,
        files: List[tuple],
        printer: Optional["Printer"] = None
    ) -> List[Finding]:
        """Analyze multiple files together in batched chunks.

        This method stacks small files together to reduce API calls.

        Args:
            files: List of (file_path, content) tuples
            printer: Optional printer for debug output

        Returns:
            List of findings across all files
        """
        from refine.core.chunker import FileStacker

        config = self._get_config()
        stacker = FileStacker(
            max_chunk_lines=config.chunking.max_chunk_lines,
            stack_threshold=config.chunking.stack_threshold
        )

        # Stack files into chunks
        chunks = stacker.stack_files(files)

        if printer and printer.debug:
            printer.print_debug(
                f"Stacked {len(files)} files into {len(chunks)} chunks "
                f"(threshold: {config.chunking.stack_threshold * 100:.0f}%)"
            )

        findings = []
        try:
            provider = get_provider()
            if not provider.is_available():
                return findings

            seen_issues = set()  # Track (file, line) to deduplicate

            for chunk in chunks:
                # Add line numbers for LLM reference
                numbered_content = add_line_numbers(chunk.content, chunk.start_line)

                if chunk.is_stacked:
                    # Multiple files in this chunk
                    prompt = self._create_stacked_analysis_prompt(numbered_content)
                else:
                    # Single file chunk
                    prompt = self._create_analysis_prompt(
                        chunk.file_path, numbered_content, chunk.start_line
                    )

                if printer and printer.debug:
                    chunk_desc = "stacked" if chunk.is_stacked else chunk.file_path.name
                    printer.print_debug(f"Analyzing chunk ({chunk_desc}): {len(chunk.content)} chars")

                response = provider.analyze_code(prompt)

                if chunk.is_stacked:
                    # Parse stacked response (includes file names)
                    chunk_findings = self._parse_stacked_response(response, files)
                else:
                    chunk_findings = self._parse_llm_response(
                        response, chunk.file_path, chunk.content
                    )

                # Deduplicate
                for finding in chunk_findings:
                    key = (str(finding.location.file), finding.location.line_start)
                    if key not in seen_issues:
                        seen_issues.add(key)
                        findings.append(finding)

        except Exception as e:
            # Re-raise the exception so the auditor can show a proper warning
            # The auditor will catch this and display the LLM error warning box
            raise

        return findings

    # Abstract methods that subclasses must implement

    def _has_code_content(self, content: str) -> bool:
        """Quick check if file contains substantial code content."""
        raise NotImplementedError

    def _create_analysis_prompt(self, file_path: Path, content: str, start_line: int = 1) -> str:
        """Create a prompt for LLM analysis of a chunk."""
        raise NotImplementedError

    def _create_stacked_analysis_prompt(self, content: str) -> str:
        """Create prompt for analyzing stacked files."""
        raise NotImplementedError

    def _parse_llm_response(self, response: str, file_path: Path, content: str) -> List[Finding]:
        """Parse LLM response and create findings."""
        raise NotImplementedError

    def _parse_stacked_response(self, response: str, files: List[tuple]) -> List[Finding]:
        """Parse LLM response for stacked files."""
        raise NotImplementedError
