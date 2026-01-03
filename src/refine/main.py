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
    rich_markup_mode="rich",
    epilog="""
Output Format Example:

  [[bold red]HIGH[/bold red]] [[magenta]naming_vibe[/magenta]] [bold cyan]Poor variable naming convention[/bold cyan] [green](85.7%)[/green] [cyan]file_name.py:56[/cyan]

      [dim]Detailed explanation for the issue[/dim]

               [dim]56 |  code_example = problem ^ 2[/dim]
"""
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
    debug: Optional[bool] = typer.Option(
        None,
        "--debug",
        "-d",
        help="Enable debug output with detailed analysis information",
    ),
) -> None:
    """Scan code for AI-generated patterns and bad coding practices."""
    try:
        # Load configuration
        config_data = load_config(config, path)

        # Override config with CLI options if provided
        if include_patterns:
            config_data.scan.include_patterns = include_patterns
        if exclude_patterns:
            config_data.scan.exclude_patterns = exclude_patterns
        if classical_only:
            config_data.checkers.classical_only = True
        if llm_only:
            config_data.checkers.llm_only = True

        # Use debug from config if not explicitly set via CLI
        if debug is None:
            debug = config_data.output.debug

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
        printer = Printer(output_format=output_format, verbose=verbose, debug=debug, root_path=path)

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
    global_config: bool = typer.Option(
        False,
        "--global",
        help="Create global configuration file (~/.config/refine/refine.toml)",
    ),
) -> None:
    """Generate a default configuration file."""
    try:
        from .config.schema import RefineConfig
        from .config.loader import find_global_config_file

        # Determine output path
        if global_config:
            global_path = find_global_config_file()
            if global_path is None:
                # Create the directory if it doesn't exist
                import os
                config_dir = Path.home() / ".config" / "refine"
                config_dir.mkdir(parents=True, exist_ok=True)
                output = config_dir / "refine.toml"
            else:
                output = global_path
        elif output == Path("refine.toml") and not output.is_absolute():
            # Default to current directory
            output = Path.cwd() / output

        # Check if file already exists
        if output.exists():
            if not typer.confirm(f"Configuration file already exists at {output}. Overwrite?"):
                typer.echo("Configuration creation cancelled.")
                return

        # Create default config
        config = RefineConfig()

        # Write to file
        if hasattr(config, 'model_dump_toml'):
            content = config.model_dump_toml()
        else:
            # Fallback for older pydantic versions
            content = "# Default Refine Vibe Code configuration\n\n"

        output.write_text(content)

        config_type = "global" if global_config else "project"
        typer.echo(f"{config_type.title()} configuration file created at: {output}")

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


