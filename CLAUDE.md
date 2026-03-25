# Penumbra

Modular obfuscation toolkit with composable pass architecture.

## Architecture

```
Input file → Detector → Pipeline type → Resolve passes → Run passes → Output
```

- **Detector** (`penumbra/detector.py`): auto-detects file type via magic bytes, extension, shebang
- **Pipeline** (`penumbra/pipeline.py`): registry + sequential pass runner
- **Passes**: stateless transforms registered per pipeline type
- **CLI** (`penumbra/cli.py`): Typer single-command app
- **C# Worker** (`dotnet-worker/`): dnlib-based IL manipulation, split into `Passes/` directory

## Pass Contract

Every pass implements the `Pass` protocol (`penumbra/types.py`):
- `name: str` — unique identifier within its pipeline
- `apply(data: bytes, config: PassConfig) -> bytes` — **stateless, pure**

## Pipeline Sub-packages

| Package | Type | Status |
|---------|------|--------|
| `penumbra/ps/` | PS1 | Ready (amsi, rename, tokenize, encode, uac*, ps1-loader*) |
| `penumbra/dotnet/` | .NET IL | Ready (dinvoke, rename, encrypt-strings, flow, strip-debug, embed*, lolbas-*, clm-bypass*) |
| `penumbra/script/` | Python/Bash | Ready (wrap, encode) |
| `penumbra/shellcode/` | Raw shellcode | Ready (encrypt, loader, inject*) |
| `penumbra/vbs/` | VBScript | Ready (encode, wrap) |
| `penumbra/pe/` | Native PE | Stub |

\* = opt-in pass (activated via CLI flag)

## Development

```bash
uv sync --dev          # Install all deps
uv run pytest -v       # Run tests
uv run ruff check penumbra/   # Lint
uv run mypy penumbra/  # Type check
uv run penumbra --help # CLI help
```

## Adding a New Pass

1. Create class in `penumbra/<pipeline>/your_pass.py` implementing `Pass` protocol
2. Add instance to the pass list in `penumbra/<pipeline>/__init__.py`
3. Write tests in `tests/test_<pipeline>_<pass>.py`
4. Run `uv run pytest -v && uv run mypy penumbra/`

## Adding a New Pipeline

1. Create `penumbra/<name>/` directory with `__init__.py`
2. Add enum value to `PipelineType` in `penumbra/types.py`
3. Update extension/detection maps in `penumbra/detector.py`
4. Call `register_pipeline()` in `penumbra/<name>/__init__.py`
5. Import the package in `penumbra/cli.py` to trigger registration

## Code Style

- Python 3.11+, strict type hints everywhere
- Line length: 100 (`ruff` enforced)
- `mypy --strict` must pass
- English for all code and comments

## Security Scope

This tool is intended for **authorized security testing, red team operations, and educational research only**. Users are responsible for ensuring they have proper authorization before using this tool against any target.
