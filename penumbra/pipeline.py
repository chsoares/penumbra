"""Pipeline runner — registry, resolution, and sequential pass execution."""

from __future__ import annotations

from rich.console import Console

from penumbra.spinner import MoonSpinner
from penumbra.types import Pass, PassConfig, PipelineType

_REGISTRY: dict[PipelineType, list[Pass]] = {}

console = Console(stderr=True)


def register_pipeline(pipeline_type: PipelineType, passes: list[Pass]) -> None:
    """Register an ordered list of passes for a pipeline type."""
    _REGISTRY[pipeline_type] = passes


def get_registered_passes(pipeline_type: PipelineType) -> list[Pass]:
    """Return all registered passes for a pipeline type."""
    return list(_REGISTRY.get(pipeline_type, []))


def resolve_passes(
    pipeline_type: PipelineType, requested_names: list[str] | None = None
) -> list[Pass]:
    """Resolve and validate pass names against the registry.

    If requested_names is None, return all registered passes for the pipeline.
    """
    available = _REGISTRY.get(pipeline_type, [])
    if not available:
        raise ValueError(f"No passes registered for pipeline '{pipeline_type.value}'")

    if requested_names is None:
        return list(available)

    by_name = {p.name: p for p in available}
    resolved: list[Pass] = []
    for name in requested_names:
        if name not in by_name:
            valid = ", ".join(by_name)
            raise ValueError(
                f"Unknown pass '{name}' for pipeline '{pipeline_type.value}'. "
                f"Available: {valid}"
            )
        resolved.append(by_name[name])
    return resolved


def run(data: bytes, passes: list[Pass], config: PassConfig) -> bytes:
    """Execute passes sequentially, folding data through each one."""
    spinner = MoonSpinner()
    if not config.verbose:
        spinner.start()

    try:
        result = data
        for p in passes:
            if config.verbose:
                console.print(f"  [dim]→ running pass:[/dim] [bold]{p.name}[/bold]")
            result = p.apply(result, config)
        return result
    finally:
        if not config.verbose:
            spinner.stop()
