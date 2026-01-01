"""Main CLI entry point for Refine Vibe Code."""

import typer
from pathlib import Path
from typing import Optional

from .config.loader import load_config
from .core.engine import ScanEngine
from .ui.printer import Printer

app = typer.Typer(
    name="refine",
    help="CLI tool to identify AI-generated code and bad coding patterns",
    add_completion=True,
)


@app.command()
def scan(
    path: Path = typer.Argument(
        Path("."),
        help="Path to the directory or file to scan",
        exists=True,
    ),
    config: Optional[Path] = typer.Option(
        None,
        "--config",
        "-c",
        help="Path to configuration file",
    ),
    output_format: str = typer.Option(
        "rich",
        "--format",
        "-f",
        help="Output format: rich, json, or plain",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose",
        "-v",
        help="Enable verbose output",
    ),
    fix: bool = typer.Option(
        False,
        "--fix",
        help="Automatically fix simple issues (line deletions only)",
    ),
    include_patterns: Optional[list[str]] = typer.Option(
        None,
        "--include",
        help="File patterns to include (e.g., *.py)",
    ),
    exclude_patterns: Optional[list[str]] = typer.Option(
        None,
        "--exclude",
        help="File patterns to exclude",
    ),
    classical_only: bool = typer.Option(
        False,
        "--classical-only",
        help="Only run classical (AST-based) checkers",
    ),
    llm_only: bool = typer.Option(
        False,
        "--llm-only",
        help="Only run LLM-based checkers",
    ),
) -> None:
    """Scan code for AI-generated patterns and bad coding practices."""
    try:
        # Load configuration
        config_data = load_config(config)

        # Override config with CLI options if provided
        if include_patterns:
            config_data.scan.include_patterns = include_patterns
        if exclude_patterns:
            config_data.scan.exclude_patterns = exclude_patterns
        if classical_only:
            config_data.checkers.classical_only = True
        if llm_only:
            config_data.checkers.llm_only = True

        # Check LLM provider availability
        from .providers import get_provider
        provider = get_provider(config_data)
        llm_available = provider.is_available()

        if llm_only and not llm_available:
            typer.echo(
                "❌ Error: LLM-only mode requested but no LLM provider is available.\n"
                "\nTo use LLM-based checkers, you need to configure an LLM provider:\n"
                "\n1. For OpenAI: Set OPENAI_API_KEY environment variable or add api_key to refine.toml\n"
                "2. For Google Gemini: Set GOOGLE_API_KEY environment variable, set provider = \"google\" and model = \"gemini-2.0-flash-exp\" in refine.toml\n"
                "\nRun 'uv run refine init' to generate a configuration file.",
                err=True
            )
            raise typer.Exit(code=1)
        elif not classical_only and not llm_available and any("quality" in checker or "vibe" in checker for checker in config_data.checkers.enabled):
            # Print big warning about falling back to mock analysis
            typer.echo()
            typer.echo("╔══════════════════════════════════════════════════════════════════════════════╗")
            typer.echo("║                              ⚠️  WARNING ⚠️                               ║")
            typer.echo("║                                                                            ║")
            typer.echo("║  LLM-based checkers are enabled but no LLM provider is configured!       ║")
            typer.echo("║                                                                            ║")
            typer.echo("║  FALLING BACK TO HARDCODED MOCK ANALYSIS                                  ║")
            typer.echo("║                                                                            ║")
            typer.echo("║  This will only detect obvious patterns and may miss many issues.        ║")
            typer.echo("║  For proper AI-generated code detection, configure an LLM provider:     ║")
            typer.echo("║                                                                            ║")
            typer.echo("║  1. OpenAI:    Set OPENAI_API_KEY environment variable                    ║")
            typer.echo("║  2. Google:    Set GOOGLE_API_KEY + configure provider in refine.toml    ║")
            typer.echo("║                                                                            ║")
            typer.echo("║  Run 'uv run refine init' to generate a configuration file.              ║")
            typer.echo("╚══════════════════════════════════════════════════════════════════════════════╝")
            typer.echo()

        # Initialize printer
        printer = Printer(output_format=output_format, verbose=verbose, root_path=path)

        # Print header
        printer.print_header("Refine Vibe Code Scanner")

        # Initialize and run scan engine
        engine = ScanEngine(config=config_data, printer=printer)
        results = engine.scan(path)

        # Print results
        printer.print_results(results, fix=fix)

        # Exit with appropriate code
        if results.has_issues():
            import sys
            sys.exit(1)

    except Exception as e:
        typer.echo(f"Error: {e}", err=True)
        raise typer.Exit(code=1)


@app.command()
def init(
    output: Path = typer.Option(
        Path("refine.toml"),
        "--output",
        "-o",
        help="Output path for the configuration file",
    ),
) -> None:
    """Generate a default configuration file."""
    try:
        from .config.schema import RefineConfig

        # Create default config
        config = RefineConfig()

        # Write to file
        import tomllib
        if hasattr(config, 'model_dump_toml'):
            content = config.model_dump_toml()
        else:
            # Fallback for older pydantic versions
            content = "# Default Refine Vibe Code configuration\n\n"

        output.write_text(content)
        typer.echo(f"Configuration file created at: {output}")

    except Exception as e:
        typer.echo(f"Error creating config file: {e}", err=True)
        raise typer.Exit(code=1)


@app.command()
def version() -> None:
    """Show version information."""
    from . import __version__
    typer.echo(f"Refine Vibe Code v{__version__}")


if __name__ == "__main__":
    app()


