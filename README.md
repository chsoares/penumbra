# Penumbra

Modular obfuscation toolkit with composable pass architecture. Auto-detects file types and routes them through pipeline-specific obfuscation passes. Each pass is a stateless transform that can be chained, reordered, or cherry-picked.

> **Scope**: This tool is intended for authorized security testing, red team operations, and educational research only.

---

## Pipelines

| Pipeline | Input | Passes | Status |
|----------|-------|--------|--------|
| **PS1** | `.ps1` scripts | `amsi` `rename` `tokenize` `encode` + opt-in: `uac` `ps1-loader` | Ready |
| **DOTNET-IL** | `.exe` / `.dll` (.NET assemblies) | `dinvoke` `rename` `encrypt-strings` `flow` `strip-debug` `scrub-guid` + opt-in: `embed` `lolbas-*` `clm-bypass` | Ready |
| **Script** | `.py` / `.sh` | `wrap` `encode` | Ready |
| **Shellcode** | `.bin` / `.raw` | `encrypt` `loader` + opt-in: `inject` | Ready |
| **VBS** | `.vbs` / `.vbe` | `encode` `wrap` | Ready |
| PE | Native binaries | — | Planned |

### PS1 passes

- **amsi** — prepend AMSI bypass (configurable: `reflection`, `patch`, `context` via `--amsi-technique`)
- **rename** — replace user-defined variables and function names with random identifiers
- **tokenize** — fragment suspicious string literals (skips here-strings `@"..."@` to protect embedded C#)
- **encode** — wrap in Base64 + `Invoke-Expression` decoder stub with randomized variables
- **uac** *(opt-in)* — wrap payload in UAC bypass (`fodhelper`, `diskcleanup`, `computerdefaults` via `--uac`). Omits `.exe` from paths to evade Defender
- **ps1-loader** *(opt-in)* — wrap a .NET assembly in a PS1 reflective loader (`--ps1-loader`). Requires manual AMSI bypass before execution

### .NET IL passes

Powered by [dnlib](https://github.com/0xd4d/dnlib) via a C# subprocess worker:

- **dinvoke** — convert static `[DllImport]` PInvoke calls to runtime DInvoke resolution
- **rename** — randomize type, method, field, and property names. Use `--safe-rename` for reflection-heavy tools
- **encrypt-strings** — XOR-encrypt string literals (16-byte keys) with a runtime decryptor method
- **flow** — insert NOP padding to shift instruction offsets
- **strip-debug** — remove debug attributes and scrub identifying assembly metadata (`AssemblyCompany`, `AssemblyProduct`, `AssemblyTitle`, etc.)
- **scrub-guid** — regenerate assembly GUID and MVID to break signature-based fingerprinting
- **embed** *(opt-in)* — in-memory loader with encrypted payload (`--embed`). With `--host`, trojanizes an existing binary
- **lolbas-installutil** *(opt-in)* — InstallUtil.exe loader format (`--lolbas installutil`)
- **lolbas-regasm** *(opt-in)* — RegAsm.exe loader format (`--lolbas regasm`)
- **clm-bypass** *(opt-in)* — wrap PS1 in FullLanguage runspace exe (`--clm-bypass`). Requires Windows for compilation (uses GAC assembly)

### Shellcode passes

- **encrypt** — AES-256-CBC encryption via dotnet SDK
- **loader** — generate .NET Framework 4.7.2 exe with direct syscalls, AMSI bypass, sandbox evasion, payload fragmentation. Use `--format ps1` for PowerShell loader
- **inject** *(opt-in)* — remote process injection via CreateProcess + VirtualAllocEx + WriteProcessMemory + VirtualProtectEx + CreateRemoteThread (`--inject [process]`)

### Script passes

- **wrap** — wrap in a self-extracting heredoc (bash) or `exec(compile(...))` (Python)
- **encode** — Base64-encode with language-appropriate decoder

### VBS passes

- **encode** — XOR-encode each character with `Chr(Asc(Mid(...)) Xor key)` + `Execute`
- **wrap** — add `WScript.Shell` object creation

---

## Installation

### Prerequisites

| Dependency | Required for | Install (Arch Linux) | Install (other) |
|------------|-------------|---------------------|-----------------|
| **Python 3.11+** | Core | `sudo pacman -S python` | [python.org](https://www.python.org/) |
| **uv** | Package management | `sudo pacman -S uv` | [docs.astral.sh/uv](https://docs.astral.sh/uv/getting-started/installation/) |
| **.NET 8 SDK** | dotnet-il, shellcode, LOLBAS, CLM | `sudo pacman -S dotnet-sdk-8.0` | [dotnet.microsoft.com](https://dotnet.microsoft.com/download) |
| **Nerd Font** | Terminal icons (optional) | Any [Nerd Font](https://www.nerdfonts.com/) | Same |

> The PS1, Script, and VBS pipelines are pure Python with zero external dependencies.

### Install as a tool (recommended)

```bash
uv tool install git+https://github.com/chsoares/penumbra.git
```

### Install for development

```bash
git clone https://github.com/chsoares/penumbra.git
cd penumbra
uv sync --dev
```

---

## Usage

```bash
# Auto-detect pipeline, run all default passes
penumbra payload.ps1

# Specify output
penumbra payload.ps1 -o out/payload.obf.ps1

# Cherry-pick passes
penumbra payload.ps1 --passes rename,encode

# AMSI bypass technique
penumbra payload.ps1 --amsi-technique patch

# UAC bypass wrapper
penumbra payload.ps1 --uac fodhelper

# Shellcode: AES-encrypt + generate loader
penumbra payload.bin

# Shellcode: process injection
penumbra payload.bin --inject calc.exe

# .NET IL obfuscation
penumbra implant.exe

# In-memory loader
penumbra implant.exe --embed

# Trojanized
penumbra implant.exe --embed --host ./legit-tool.exe

# PS1 reflective loader (chain dotnet-il + PS1 loader)
penumbra Seatbelt.exe --ps1-loader --passes strip-debug

# LOLBAS output formats (AppLocker bypass)
penumbra implant.exe --lolbas installutil
penumbra implant.exe --lolbas regasm

# CLM bypass
penumbra script.ps1 --clm-bypass

# VBScript
penumbra payload.vbs

# Export C# project source instead of compiling (for cross-platform)
penumbra implant.exe --lolbas installutil --source
penumbra script.ps1 --clm-bypass --source
penumbra payload.bin --inject calc.exe --source
```

### `--source` flag

Passes that generate C# projects (LOLBAS, CLM bypass, inject, embed) normally compile with `dotnet publish`. On Linux, some passes fail because they reference Windows-only assemblies (e.g., `System.Management.Automation` for CLM bypass).

`--source` exports the generated project files (`.cs`, `.csproj`) to a directory instead of compiling. Transfer the directory to a Windows machine and compile there:

```bash
# On Linux
penumbra script.ps1 --clm-bypass --source -o CLMBypass.src

# Transfer CLMBypass.src/ to Windows, then:
dotnet publish CLMBypass.src -c Release
```

### Mutual exclusivity

- `--embed`, `--ps1-loader`, and `--lolbas` are mutually exclusive
- `--inject` and `--format` are mutually exclusive
- `--uac` requires PS1 pipeline
- `--clm-bypass` requires PS1 input
- `--inject` requires shellcode pipeline

---

## Documentation

See [`docs/`](docs/) for detailed guides:

- [AMSI Bypass Techniques](docs/amsi-bypass.md)
- [PS1 .NET Assembly Loader](docs/ps1-loader.md)
- [LOLBAS Output Formats](docs/lolbas.md)
- [Process Injection](docs/process-injection.md)
- [UAC Bypass](docs/uac-bypass.md)
- [CLM Bypass](docs/clm-bypass.md)
- [VBS Pipeline](docs/vbs-pipeline.md)
- [Pipeline Reference](docs/pipelines.md)
