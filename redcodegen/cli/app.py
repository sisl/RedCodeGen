import typer

app = typer.Typer(
    name="rcg",
    # help="A vulnerability research tool for LLM-based code generation",
    add_completion=True,
)

@app.callback(invoke_without_command=True)
def callback(ctx: typer.Context):
    """A vulnerability research tool for LLM-based code generation."""
    if ctx.invoked_subcommand is None:
        print(ctx.get_help())
