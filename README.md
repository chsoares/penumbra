# Penumbra

Modular obfuscation toolkit with composable pass architecture. Auto-detects file types and routes them through pipeline-specific obfuscation passes. Each pass is a stateless transform that can be chained, reordered, or cherry-picked.

> **Scope**: This tool is intended for authorized security testing, red team operations, and educational research only.

---

## Pipelines

| Pipeline | Input | Passes | Status |
|----------|-------|--------|--------|
| **PS1** | `.ps1` scripts | `amsi` `rename` `tokenize` `encode` | Ready |
| **DOTNET-IL** | `.exe` / `.dll` (.NET assemblies) | `rename` `encrypt-strings` `flow` `strip-debug` | Ready |
| Script | `.py` / `.sh` | — | Planned |
| PE | Native binaries | — | Planned |

### PS1 passes

- **amsi** — prepend AMSI bypass via reflection with self-obfuscated strings
- **rename** — replace user-defined variables and function names with random identifiers
- **tokenize** — fragment suspicious string literals (`Invoke-Expression`, `AmsiUtils`, etc.)
- **encode** — wrap everything in Base64 + `Invoke-Expression` decoder stub

### .NET IL passes

Powered by [dnlib](https://github.com/0xd4d/dnlib) via a C# subprocess worker:

- **rename** — randomize type, method, field, and property names (`--safe-rename` to skip reflection targets)
- **encrypt-strings** — XOR-encrypt string literals with injected IL-level decryptor
- **flow** — insert NOP padding and opaque predicates
- **strip-debug** — remove `DebuggableAttribute`, PDB info, compiler attributes

---

## Installation

### Prerequisites

| Dependency | Required for | Install (Arch Linux) | Install (other) |
|------------|-------------|---------------------|-----------------|
| **Python 3.11+** | Core | `sudo pacman -S python` | [python.org](https://www.python.org/) |
| **uv** | Package management | `sudo pacman -S uv` | [docs.astral.sh/uv](https://docs.astral.sh/uv/getting-started/installation/) |
| **.NET 8 SDK** | DOTNET-IL pipeline only | `sudo pacman -S dotnet-sdk-8.0` | [dotnet.microsoft.com](https://dotnet.microsoft.com/download) |
| **Nerd Font** | Terminal icons (optional) | Any [Nerd Font](https://www.nerdfonts.com/) in your terminal | Same |

> The .NET SDK is **only** needed if you use the `dotnet-il` pipeline. The PS1 pipeline is pure Python with zero external dependencies.

### Install as a tool (recommended)

```bash
# With uv (isolated, no venv needed)
uv tool install git+https://github.com/chsoares/penumbra.git

# Or with pipx
pipx install git+https://github.com/chsoares/penumbra.git
```

### Install for development

```bash
git clone https://github.com/chsoares/penumbra.git
cd penumbra
uv sync --dev
```

### Verify .NET SDK (if using dotnet-il)

```bash
dotnet --version   # Should print 8.x or higher
```

On first run of a dotnet-il pass, the worker will automatically restore NuGet packages and build. This takes a few seconds the first time only.

---

## Usage

```bash
# Obfuscate a PS1 script (auto-detects pipeline, runs all passes)
penumbra payload.ps1

# Output to a specific path
penumbra payload.ps1 -o out/payload.obf.ps1

# Cherry-pick passes
penumbra payload.ps1 --passes rename,encode

# Obfuscate a .NET assembly
penumbra implant.exe --verbose

# Force pipeline type
penumbra tool.dll --pipeline dotnet-il --passes rename,encrypt-strings

# Safe rename (skip symbols that might be accessed via reflection)
penumbra implant.exe --safe-rename
```

Default output: `<filename>.obf.<ext>` in the same directory.
