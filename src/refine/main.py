"""Main CLI entry point for Refine Vibe Code."""

import os
import typer
from pathlib import Path
from typing import Optional

from rich.syntax import Syntax
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from pygments.lexers import get_lexer_by_name

from .config.loader import load_config, save_config, find_global_config_file
from .config.schema import RefineConfig
from .core.engine import ScanEngine
from .ui.printer import Printer


# Model options for each provider (first is default/recommended)
PROVIDER_MODELS = {
    "google": [
        ("gemini-2.0-flash-exp", "Latest experimental, fast"),
        ("gemini-2.0-pro-exp", "Most capable Gemini 2"),
        ("gemini-2.0-flash", "Stable fast model"),
        ("gemini-2.5-pro-exp-03-25", "Latest and most capable"),
    ],
    "openai": [
        ("gpt-4o-mini", "Fast and cost-effective"),
        ("gpt-4o", "Most capable GPT-4"),
        ("gpt-5", "Latest and most capable"),
        ("o1-mini", "Reasoning model, slower but thorough"),
    ],
    "claude": [
        ("claude-sonnet-4-20250514", "Latest Sonnet, best balance"),
        ("claude-3-5-sonnet-20241022", "Previous Sonnet, proven"),
        ("claude-3-5-haiku-20241022", "Fast and cost-effective"),
        ("claude-opus-4-20250514", "Most capable, premium"),
    ],
}

# Default config path
DEFAULT_CONFIG_PATH = "~/.config/refine/refine.toml"

GOOGLE_AI_STUDIO_URL = "https://aistudio.google.com/apikey"


def _get_global_config_path() -> Path:
    """Get the path for global config, creating directory if needed."""
    global_path = find_global_config_file()
    if global_path is None:
        # Respect XDG_CONFIG_HOME if set, otherwise use ~/.config
        xdg_config = os.environ.get("XDG_CONFIG_HOME")
        if xdg_config:
            config_dir = Path(xdg_config) / "refine"
        else:
            config_dir = Path.home() / ".config" / "refine"
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir / "refine.toml"
    return global_path


def interactive_api_setup(console: Console) -> Optional[RefineConfig]:
    """Interactive setup for API key configuration.

    Returns the updated config if successful, None if cancelled.
    """
    console.print()
    console.print(Panel.fit(
        "[bold cyan]API Key Setup[/bold cyan]\n\n"
        "To use LLM-based code analysis, you need an API key from one of the supported providers.",
        border_style="cyan"
    ))
    console.print()

    # Provider selection
    console.print("[bold]Select your LLM provider:[/bold]")
    console.print("  [cyan]1[/cyan]) Google Gemini [dim](Recommended - high free tier limits)[/dim]")
    console.print("  [cyan]2[/cyan]) OpenAI")
    console.print("  [cyan]3[/cyan]) Anthropic Claude")
    console.print()

    provider_choice = Prompt.ask(
        "Enter choice",
        choices=["1", "2", "3"],
        default="1"
    )

    provider_map = {"1": "google", "2": "openai", "3": "claude"}
    provider = provider_map[provider_choice]
    models = PROVIDER_MODELS[provider]

    # Show API key creation URL
    console.print()
    if provider == "google":
        console.print(f"[dim]Get your free API key at:[/dim] [link={GOOGLE_AI_STUDIO_URL}]{GOOGLE_AI_STUDIO_URL}[/link]")
        console.print("[dim]Google offers generous free tier limits for Gemini models.[/dim]")
    elif provider == "openai":
        console.print("[dim]Get your API key at:[/dim] [link=https://platform.openai.com/api-keys]https://platform.openai.com/api-keys[/link]")
    elif provider == "claude":
        console.print("[dim]Get your API key at:[/dim] [link=https://console.anthropic.com/settings/keys]https://console.anthropic.com/settings/keys[/link]")
    console.print()

    # Model selection
    console.print("[bold]Select model:[/bold]")
    for i, (model_name, description) in enumerate(models, 1):
        if i == 1:
            console.print(f"  [cyan]{i}[/cyan]) {model_name} [dim]({description})[/dim] [green](Recommended)[/green]")
        else:
            console.print(f"  [cyan]{i}[/cyan]) {model_name} [dim]({description})[/dim]")
    console.print(f"  [cyan]c[/cyan]) Custom model name")
    console.print()

    model_choice = Prompt.ask(
        "Enter choice",
        choices=[str(i) for i in range(1, len(models) + 1)] + ["c"],
        default="1"
    )

    if model_choice == "c":
        model = Prompt.ask("Enter model name", default=models[0][0])
    else:
        model = models[int(model_choice) - 1][0]

    # API key input
    api_key = Prompt.ask("API key")

    if not api_key.strip():
        console.print("[yellow]Setup cancelled - no API key provided.[/yellow]")
        return None

    # Load existing config or create new
    global_config_path = _get_global_config_path()
    try:
        config = load_config(global_config_path if global_config_path.exists() else None)
    except Exception:
        config = RefineConfig()

    # Update config
    config.llm.provider = provider
    config.llm.model = model
    config.llm.api_key = api_key.strip()

    # Save to global config
    save_config(config, global_config_path)

    console.print()
    console.print(f"[green]✓[/green] Configuration saved to [cyan]{global_config_path}[/cyan]")
    console.print()
    console.print("[dim]To change these settings later, run:[/dim]")
    console.print("  [cyan]refine --add-api-key[/cyan]")
    console.print(f"[dim]Or edit directly:[/dim] [cyan]{DEFAULT_CONFIG_PATH}[/cyan]")
    console.print()

    return config


def _print_syntax_highlighted_code_example(console: "Console") -> None:
    """Print syntax-highlighted code example for help text using the same method as printer.py."""
    code = "code_example = problem ^ 2"
    try:
        lexer = get_lexer_by_name("python")
        syntax = Syntax(
            code,
            lexer,
            theme="monokai",
            line_numbers=False,
            word_wrap=False,
            code_width=console.width - 8,  # Leave some margin like in printer.py
        )
        console.print(syntax)
    except Exception:
        # Fallback to plain text if syntax highlighting fails
        console.print(code)


app = typer.Typer(
    name="refine",
    help="CLI tool to identify AI-generated code and bad coding patterns",
    add_completion=False,
    rich_markup_mode="rich",
)


@app.callback(invoke_without_command=True)
def main_callback(
    ctx: typer.Context,
    add_api_key: bool = typer.Option(
        False,
        "--add-api-key",
        help="Configure or update your LLM API key",
    ),
):
    """Show help when no command is provided."""
    if add_api_key:
        console = Console()
        interactive_api_setup(console)
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        # Print the standard help
        typer.echo(ctx.get_help())

        # Print the output format example with syntax highlighting
        console = Console(width=120)

        console.print("\n[dim]Example command:[/dim]")
        console.print("  [cyan]refine scan src/[/cyan]")
        console.print()

        console.print("[dim]Output Format Example:[/dim]")

        # Create styled text for the example output line
        from rich.text import Text
        example_line = Text()
        example_line.append("[", style="bold red")
        example_line.append("PRIORITY", style="bold red")
        example_line.append("] ", style="bold red")
        example_line.append("[", style="magenta")
        example_line.append("vibe_naming", style="magenta")
        example_line.append("] ", style="magenta")
        example_line.append("Poor naming convention", style="bold cyan")
        example_line.append(" ", style="")
        example_line.append("(85.7%)", style="green")
        example_line.append(" ", style="")
        example_line.append("file_name.py:56", style="cyan")
        console.print("  ", end="")
        console.print(example_line, overflow="ellipsis")

        console.print("  [dim]Variable 'code_example' doesn't follow Python naming conventions.[/dim]")
        console.print("    56 | ", end="")

        # Print the syntax-highlighted code
        _print_syntax_highlighted_code_example(console)

        console.print()
        raise typer.Exit()


@app.command()
def scan(
    dir: Path = typer.Argument(
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
    """Scan DIR for AI-generated patterns and bad coding practices."""
    try:
        # Load configuration
        config_data = load_config(config, dir)

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

        # If LLM is not available and we need it, offer interactive setup
        if not llm_available and not classical_only:
            console = Console()
            console.print()
            console.print("[yellow]No API key configured for LLM-based analysis.[/yellow]")
            console.print()

            if Confirm.ask("Would you like to set up an API key now?", default=True):
                updated_config = interactive_api_setup(console)
                if updated_config:
                    # Reload config with new API key
                    config_data = load_config(config, dir)
                    provider = get_provider(config_data)
                    llm_available = provider.is_available()

        if llm_only and not llm_available:
            typer.echo(
                "LLM-only mode requested but no LLM provider is configured.\n"
                "Run 'refine --add-api-key' to configure your API key.",
                err=True
            )
            raise typer.Exit(code=1)
        elif not classical_only and not llm_available and any("quality" in checker or "vibe" in checker for checker in config_data.checkers.enabled):
            # Print beautiful warning about falling back to mock analysis
            # Initialize printer temporarily for this warning
            temp_printer = Printer(output_format="rich", verbose=False, debug=False, root_path=dir)
            temp_printer.print_llm_warning_box()

        # Initialize printer
        printer = Printer(output_format=output_format, verbose=verbose, debug=debug, root_path=dir)

        # Initialize and run scan engine
        engine = ScanEngine(config=config_data, printer=printer)
        results = engine.scan(dir)

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
                # Respect XDG_CONFIG_HOME if set, otherwise use ~/.config
                xdg_config = os.environ.get("XDG_CONFIG_HOME")
                if xdg_config:
                    config_dir = Path(xdg_config) / "refine"
                else:
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


