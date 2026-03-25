# Penumbra

Modular obfuscation toolkit with composable pass architecture. Auto-detects file types and routes them through pipeline-specific obfuscation passes. Each pass is a stateless transform that can be chained, reordered, or cherry-picked.

> **Scope**: This tool is intended for authorized security testing, red team operations, and educational research only.

---

## Pipelines

| Pipeline | Input | Passes | Status |
|----------|-------|--------|--------|
| **PS1** | `.ps1` scripts | `amsi` `rename` `tokenize` `encode` + opt-in: `uac` `ps1-loader` | Ready |
| **DOTNET-IL** | `.exe` / `.dll` (.NET assemblies) | `dinvoke` `rename` `encrypt-strings` `flow` `strip-debug` + opt-in: `embed` `lolbas-*` `clm-bypass` | Ready |
| **Script** | `.py` / `.sh` | `wrap` `encode` | Ready |
| **Shellcode** | `.bin` / `.raw` | `encrypt` `loader` + opt-in: `inject` | Ready |
| **VBS** | `.vbs` / `.vbe` | `encode` `wrap` | Ready |
| PE | Native binaries | — | Planned |

### PS1 passes

- **amsi** — prepend AMSI bypass (configurable: `reflection`, `patch`, `context` via `--amsi-technique`)
- **rename** — replace user-defined variables and function names with plausible identifiers
- **tokenize** — fragment suspicious string literals (`Invoke-Expression`, `Assembly.Load`, `AmsiUtils`, `fodhelper`, etc.)
- **encode** — wrap everything in Base64 + `Invoke-Expression` decoder stub
- **uac** *(opt-in)* — wrap payload in UAC bypass (`fodhelper`, `diskcleanup`, `computerdefaults` via `--uac`)
- **ps1-loader** *(opt-in)* — wrap a .NET assembly in a PS1 reflective loader (`--ps1-loader`)

### Script passes

- **wrap** — wrap in a self-extracting heredoc (bash) or `exec(compile(...))` (Python)
- **encode** — Base64-encode the script with a language-appropriate exec one-liner

### Shellcode passes

- **encrypt** — AES-256-CBC encrypt the raw shellcode (not XOR — AES decryption uses Windows CNG APIs that look legitimate to AV, while XOR loops are a classic malware signature)
- **loader** — generate a .NET Framework 4.7.2 executable that decrypts and runs the shellcode in memory via direct syscalls (`NtAllocateVirtualMemory` + `NtCreateThreadEx` — bypasses EDR hooks on ntdll). Includes sandbox evasion (sleep acceleration, CPU count), HWBP+VEH AMSI bypass, plausible names, fragmented payload, and junk code. Use `--format ps1` for a PowerShell loader instead
- **inject** *(opt-in)* — remote process injection via `VirtualAllocEx` → `WriteProcessMemory` → `VirtualProtectEx` → `CreateRemoteThread` (`--inject [process]`)

### .NET IL passes

Powered by [dnlib](https://github.com/0xd4d/dnlib) via a C# subprocess worker:

- **dinvoke** — convert static `[DllImport]` PInvoke calls to runtime DInvoke resolution via `NativeLibrary.Load` + `Marshal.GetDelegateForFunctionPointer<T>`. Removes native function names and DLL names from the PE import table. Skips methods with complex marshalling (by-ref structs, callbacks)
- **rename** — randomize type, method, field, and property names using plausible identifiers (`GetServiceHandler`, `currentBuffer`) instead of random hex. Use `--safe-rename` to skip reflection targets
- **encrypt-strings** — XOR-encrypt string literals with a runtime decryptor method. Original strings disappear entirely from the binary
- **flow** — insert NOP padding to shift instruction offsets and defeat pattern matching
- **strip-debug** — remove `DebuggableAttribute`, PDB info, compiler attributes
- **embed** *(opt-in)* — wrap the obfuscated assembly in a new .NET loader that decrypts and loads the payload in-memory via `Assembly.Load(byte[])`. Enable with `--embed`. With `--host`, injects the payload into an existing legitimate .NET binary instead
- **lolbas-installutil** *(opt-in)* — InstallUtil.exe loader format (`--lolbas installutil`)
- **lolbas-regasm** *(opt-in)* — RegAsm.exe loader format (`--lolbas regasm`)
- **lolbas-rundll32** *(opt-in)* — RunDll32.exe loader format (`--lolbas rundll32`)
- **clm-bypass** *(opt-in)* — wrap PS1 payload in a FullLanguage runspace exe (`--clm-bypass`)

Default pass order: `dinvoke → rename → encrypt-strings → flow → strip-debug`

> The opt-in passes are activated via CLI flags because they change the output format (loader exe, dll, PS1 script, etc.).

### VBS passes

- **encode** — XOR-encode each character with a random key, decoded at runtime via `Chr(Asc(Mid(...)) Xor key)` + `Execute`
- **wrap** — add `WScript.Shell` object creation for process execution capability

#### Embed: standalone vs. trojanized

`--embed` alone generates a standalone loader targeting **.NET 8**, which requires the .NET runtime installed on the target. This is fine for dev/lab environments but **won't work on most target machines** (CTF boxes, engagements) where you can't install software.

`--embed --host` injects the payload into an existing .NET binary, **inheriting the host's target framework**. If the host is a .NET Framework 4.x assembly (like most offensive tools), the output runs on any Windows without installing anything — .NET Framework 4.x is pre-installed since Windows 7.

**For CTF/engagements, always use `--host`**:

```bash
# Download any small .NET Framework 4.x binary as a host
penumbra implant.exe --embed --host ./legit-tool.exe
```

---

## Installation

### Prerequisites

| Dependency | Required for | Install (Arch Linux) | Install (other) |
|------------|-------------|---------------------|-----------------|
| **Python 3.11+** | Core | `sudo pacman -S python` | [python.org](https://www.python.org/) |
| **uv** | Package management | `sudo pacman -S uv` | [docs.astral.sh/uv](https://docs.astral.sh/uv/getting-started/installation/) |
| **.NET 8 SDK** | DOTNET-IL pipeline only | `sudo pacman -S dotnet-sdk-8.0` | [dotnet.microsoft.com](https://dotnet.microsoft.com/download) |
| **Nerd Font** | Terminal icons (optional) | Any [Nerd Font](https://www.nerdfonts.com/) in your terminal | Same |

> The .NET SDK is needed for the `dotnet-il` and `shellcode` pipelines. The PS1, Script, and VBS pipelines are pure Python with zero external dependencies.

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

# Choose AMSI bypass technique (reflection, patch, or context)
penumbra payload.ps1 --amsi-technique patch

# UAC bypass wrapper (fodhelper, diskcleanup, computerdefaults)
penumbra payload.ps1 --uac fodhelper

# Obfuscate a Python or Bash script (auto-detects language)
penumbra exploit.py
penumbra reverse_shell.sh

# Obfuscate a VBScript file
penumbra payload.vbs

# Shellcode: AES-encrypt + generate loader with sandbox evasion + direct syscalls
penumbra payload.bin
penumbra payload.bin --format ps1 -o loader.ps1

# Shellcode: process injection mode
penumbra payload.bin --inject notepad.exe

# Obfuscate a .NET assembly (all default passes)
penumbra implant.exe

# With in-memory loader (payload never touches disk)
penumbra implant.exe --embed

# Trojanized — inject into a legitimate .NET binary
penumbra implant.exe --embed --host /path/to/legit-tool.exe

# PS1 reflective loader (obfuscate .NET → wrap in PS1 loader → obfuscate PS1)
penumbra Seatbelt.exe --ps1-loader -o Invoke-Seatbelt.ps1

# LOLBAS output formats (AppLocker bypass)
penumbra implant.exe --lolbas installutil
penumbra implant.exe --lolbas regasm
penumbra implant.exe --lolbas rundll32

# CLM bypass (wrap PS1 in FullLanguage runspace exe)
penumbra script.ps1 --clm-bypass

# Cherry-pick passes + embed
penumbra implant.exe --passes rename,encrypt-strings --embed

# Force pipeline type
penumbra tool.dll --pipeline dotnet-il --passes rename,encrypt-strings

# Safe rename (skip symbols that might be accessed via reflection)
penumbra implant.exe --safe-rename
```

Default output: `<filename>.obf.<ext>` in the same directory.

### Execution hints

When a payload requires a specific invocation command, Penumbra prints an execution hint after the done message:

```
🔮 payload cloaked → /path/to/output
   ⚡ run: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
```

### Mutual exclusivity

- `--embed`, `--ps1-loader`, and `--lolbas` are mutually exclusive
- `--inject` and `--format` are mutually exclusive
- `--uac` requires PS1 pipeline
- `--clm-bypass` requires PS1 input
- `--inject` requires shellcode pipeline

---

## Documentation

See [`docs/`](docs/) for detailed documentation on each feature:

- [AMSI Bypass Techniques](docs/amsi-bypass.md)
- [PS1 .NET Assembly Loader](docs/ps1-loader.md)
- [LOLBAS Output Formats](docs/lolbas.md)
- [Process Injection](docs/process-injection.md)
- [UAC Bypass](docs/uac-bypass.md)
- [CLM Bypass](docs/clm-bypass.md)
- [VBS Pipeline](docs/vbs-pipeline.md)
- [Pipeline Reference](docs/pipelines.md)
