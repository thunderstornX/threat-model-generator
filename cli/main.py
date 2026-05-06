"""``threat-model`` -- Click entry point.

Examples
--------
Generate a model in both formats (Markdown + Threat Dragon JSON):

    python -m cli.main \\
        --input eval/benchmarks/web_app.yaml \\
        --output out/web_app

Markdown only:

    python -m cli.main \\
        --input eval/benchmarks/web_app.yaml \\
        --output out/web_app.md \\
        --format markdown

Augment with the optional LLM (graceful fallback if no provider):

    python -m cli.main \\
        --input eval/benchmarks/web_app.yaml \\
        --output out/web_app \\
        --augment-with-llm
"""
from __future__ import annotations

from pathlib import Path

import click

from config import load_settings
from generator.formatter import write_outputs
from generator.modeller import model_system
from generator.parser import load_system


@click.command()
@click.option("--input", "input_path", required=True,
              type=click.Path(exists=True, dir_okay=False, path_type=Path),
              help="YAML system description.")
@click.option("--output", "output_path", required=True,
              type=click.Path(dir_okay=False, path_type=Path),
              help="Output stem (extension is added per format).")
@click.option("--format", "fmt",
              type=click.Choice(["markdown", "threatdragon", "both"],
                                  case_sensitive=False),
              default="both", show_default=True)
@click.option("--augment-with-llm", is_flag=True, default=False,
              help="Try Anthropic Claude / local Ollama for "
                   "additional threats (graceful fallback if neither "
                   "is reachable).")
def main(
    input_path: Path,
    output_path: Path,
    fmt: str,
    augment_with_llm: bool,
) -> None:
    """Generate a STRIDE threat model from a YAML system description."""
    settings = load_settings()
    system = load_system(input_path)
    click.echo(f"[*] threat-model: {system.name!r} "
               f"({len(system.components)} components)")
    if augment_with_llm:
        click.echo("[*] augmentation: enabled (graceful fallback)")
    else:
        click.echo("[*] augmentation: disabled (rules-only)")

    model = model_system(system, settings=settings,
                          augment_with_llm=augment_with_llm)
    written = write_outputs(system, model,
                              output_path=output_path, fmt=fmt)

    click.echo(f"[+] {model.threat_count} threat(s) generated")
    if model.augmentation:
        prov = model.augmentation.get("provider") or "rules-only"
        added = model.augmentation.get("added", 0)
        if augment_with_llm:
            click.echo(f"[+] augmentation: provider={prov} added={added}")
    for label, path in written.items():
        click.echo(f"[+] wrote ({label}) {path}")


if __name__ == "__main__":
    main()  # pragma: no cover
