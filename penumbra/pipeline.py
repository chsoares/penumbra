"""Pipeline runner — registry, resolution, and sequential pass execution."""

from __future__ import annotations

from penumbra.spinner import PassSpinner, write_done, write_fail
from penumbra.types import Pass, PassConfig, PipelineType

_REGISTRY: dict[PipelineType, list[Pass]] = {}


def register_pipeline(pipeline_type: PipelineType, passes: list[Pass]) -> None:
    """Register an ordered list of passes for a pipeline type."""
    _REGISTRY[pipeline_type] = passes


def get_registered_passes(pipeline_type: PipelineType) -> list[Pass]:
    """Return all registered passes for a pipeline type."""
    return list(_REGISTRY.get(pipeline_type, []))


def resolve_passes(
    pipeline_type: PipelineType,
    requested_names: list[str] | None = None,
    include_opt_in: list[str] | None = None,
) -> list[Pass]:
    """Resolve and validate pass names against the registry.

    If requested_names is None, return default passes (excluding opt-in).
    include_opt_in appends named opt-in passes to the default list.
    """
    available = _REGISTRY.get(pipeline_type, [])
    if not available:
        raise ValueError(f"No passes registered for pipeline '{pipeline_type.value}'")

    by_name = {p.name: p for p in available}

    if requested_names is not None:
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

    # Default: exclude opt-in passes, then append any explicitly included
    defaults = [p for p in available if not getattr(p, "opt_in", False)]
    if include_opt_in:
        for name in include_opt_in:
            if name in by_name:
                defaults.append(by_name[name])
    return defaults


def run(
    data: bytes,
    passes: list[Pass],
    config: PassConfig,
    output_path: str = "",
    *,
    silent: bool = False,
) -> bytes:
    """Execute passes sequentially with per-pass spinner animation.

    If silent=True, suppress the final 'payload cloaked' message.
    Used for intermediate stages in cross-pipeline routing.
    """
    result = data
    try:
        for p in passes:
            spinner = PassSpinner(p.name)
            spinner.start()
            ok = False
            try:
                result = p.apply(result, config)
                ok = True
            finally:
                spinner.stop(ok=ok, verbose=config.verbose)
        if not silent:
            write_done(output_path)
        return result
    except Exception:
        write_fail()
        raise
