# Penumbra

A modular obfuscation toolkit for CTF and red team research.
Accepts binaries, source code, or scripts and produces obfuscated versions designed to evade signature-based detection.

> **Scope**: This project is intended for CTF competitions and authorized security research only.

---

## Project goals

- Accept multiple input types (.ps1, .exe/.dll, .cs/.csproj, .py, .sh, and other scripts)
- Auto-detect the input type and route to the correct pipeline
- Apply one or more obfuscation passes (pluggable architecture)
- Output a functional obfuscated version of the original

The design philosophy is **composable passes**: each transformation is a discrete, testable step. Passes can be chained and configured per pipeline.

---

## Language and runtime

- **Python 3.11+** — primary language for the CLI, orchestration, and script/PS1 pipelines
- **C# / .NET 8** — a small helper binary (`dotnet-worker`) handles IL-level manipulation via `dnlib`; invoked as a subprocess by the Python orchestrator
- Runs on **Linux** (primary target: Arch Linux). No Windows dependency.
- The .NET SDK must be available in PATH for the dotnet pipelines.

---

## Repository structure

```
penumbra/
├── CLAUDE.md
├── pyproject.toml
├── README.md
├── penumbra/
│   ├── __init__.py
│   ├── cli.py               # Entry point (Typer)
│   ├── detector.py          # Input type detection
│   ├── pipeline.py          # Pipeline runner (chains passes)
│   ├── ps/                  # PowerShell pipeline
│   │   ├── __init__.py
│   │   ├── encode.py        # Base64 / char-code encoding
│   │   ├── rename.py        # Variable and function renaming
│   │   ├── tokenize.py      # Token splitting / string fragmentation
│   │   └── amsi.py          # AMSI bypass patterns
│   ├── dotnet/              # .NET pipeline
│   │   ├── __init__.py
│   │   ├── il_worker.py     # Subprocess wrapper for dotnet-worker
│   │   └── roslyn.py        # Source-level AST transforms (Roslyn)
│   ├── script/              # Generic script pipeline
│   │   ├── __init__.py
│   │   ├── encode.py        # Base64 / hex wrapping
│   │   └── wrap.py          # eval/exec shell wrappers
│   └── pe/                  # Native PE pipeline (future)
│       ├── __init__.py
│       └── loader_gen.py    # Generate .NET/PS1 reflective loaders
├── dotnet-worker/           # C# project — IL manipulation via dnlib
│   ├── dotnet-worker.csproj
│   └── Program.cs
└── tests/
    ├── fixtures/            # Sample input files for each type
    └── test_*.py
```

---

## Pipelines

### PS1 (PowerShell)

Input: `.ps1` file

Passes (in order, all optional and configurable):
1. **encode** — wrap the entire script in a Base64 + `[System.Text.Encoding]` decode block, or use char-code concatenation for inline strings
2. **rename** — replace variable and function names with random identifiers using regex-based substitution
3. **tokenize** — split suspicious string literals (e.g. `"Invoke-Expression"`) into concatenated fragments using format strings or `-join` arrays
4. **amsi** — insert AMSI bypass patterns via string splitting of AMSI function names

This pipeline is pure Python. No external tool required.

### .NET — compiled assembly

Input: `.exe` or `.dll` (compiled .NET assembly)

The Python code invokes `dotnet-worker` as a subprocess, passing flags for which passes to apply.

The worker uses `dnlib` to:
1. **rename** — randomize type, method, and field names (skipping anything accessed via reflection if `--safe-rename` is set)
2. **encrypt-strings** — replace string literals with runtime-decrypted equivalents
3. **flow** — insert junk basic blocks and shuffle control flow
4. **strip-debug** — remove PDB info, debug attributes, and source file references

Output: a new `.exe` / `.dll` written to the output path.

### .NET — source code

Input: `.cs` file or `.csproj` directory

Uses the Roslyn compiler API (via a small C# helper or `dotnet-script`) to:
1. Parse the source into a syntax tree
2. Apply transformations directly on the AST (rename symbols, obfuscate string literals)
3. Compile the modified tree to a new assembly

This is safer than IL manipulation because rename conflicts from reflection can be caught at compile time.

### Script (generic)

Input: `.py`, `.sh`, or other interpreted scripts

Passes:
1. **encode** — Base64-encode the entire script and wrap in a decode + exec one-liner appropriate for the language
2. **wrap** — for bash, generate a self-extracting heredoc; for Python, generate a `exec(compile(...))` wrapper

### PE — native binaries (future / limited)

Input: `.exe` compiled from C/C++ (e.g., Mimikatz)

This pipeline does **not** attempt to obfuscate machine code directly. Instead it generates a **reflective loader** — a .NET or PS1 file that reads the target binary, loads it into memory via `VirtualAlloc` + `CreateThread`, and avoids writing the original binary to disk.

The original PE is embedded as an encrypted byte array inside the loader. The loader itself is then passed through the PS1 or .NET pipeline.

---

## CLI design

Built with **Typer**. No subcommands — the tool does one thing, so the input file is the direct argument.

```
penumbra <input_file> [options]

Options:
  --output, -o PATH         Output file path (default: <input>.obf.<ext>)
  --pipeline TEXT           Force a specific pipeline (ps, dotnet-il, dotnet-src, script, pe)
  --passes TEXT             Comma-separated list of passes to apply (default: all)
  --safe-rename             Skip renaming symbols that may be accessed via reflection
  --verbose, -v             Show each pass and its effect on file size / entropy
```

Example:
```
penumbra payload.ps1 --passes encode,tokenize,amsi -o payload.obf.ps1
penumbra tool.exe --pipeline dotnet-il --passes rename,encrypt-strings -o tool.obf.exe
penumbra bloodhound.exe --verbose
```

---

## Detection logic (`detector.py`)

Priority order:
1. Read magic bytes — `MZ` header → PE binary; check PE metadata for .NET CLR header → dotnet-il
2. File extension fallback — `.ps1`, `.cs`, `.csproj`, `.py`, `.sh`
3. Content heuristic — shebang line, `using System;`, `#!/usr/bin/env python`

Returns a `PipelineType` enum value.

---

## Code style

- All code, comments, variable names, and docstrings must be in **English**
- Type hints on all public functions
- Each pass must implement a common interface:
  ```python
  def apply(input: bytes, config: PassConfig) -> bytes: ...
  ```
- Passes must be stateless and pure (no side effects, no global mutation)
- Tests go in `tests/`, using `pytest`, with fixture files in `tests/fixtures/`

---

## Dependencies

Python:
- `typer` — CLI
- `rich` — terminal output
- `pefile` — PE parsing for the detector and PE pipeline

.NET worker:
- `dnlib` — IL manipulation (NuGet)
- `.NET 8 SDK` must be installed

---

## What to build first (MVP)

1. `detector.py` — input type detection
2. `pipeline.py` — pass runner
3. `ps/encode.py` — Base64 encoding pass for PS1 (simplest useful pass)
4. `cli.py` — minimal Typer CLI wiring it all together
5. One test with a fixture `.ps1` file

The dotnet-worker and PE loader generator come after the PS1 pipeline is solid.
