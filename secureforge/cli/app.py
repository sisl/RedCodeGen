import typer

from secureforge.language import DEFAULT_LANGUAGE, supported_languages, get_language_config

app = typer.Typer(
    name="sf",
    # help="A vulnerability research tool for LLM-based code generation",
    add_completion=True,
)

@app.callback(invoke_without_command=True)
def callback(
    ctx: typer.Context,
    lang: str = typer.Option(
        DEFAULT_LANGUAGE,
        "--lang",
        help=f"Target programming language ({', '.join(supported_languages())})",
    ),
):
    """A vulnerability research tool for LLM-based code generation."""
    # Validate language early
    try:
        get_language_config(lang)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e
    ctx.ensure_object(dict)
    ctx.obj["language"] = lang
    if ctx.invoked_subcommand is None:
        print(ctx.get_help())
