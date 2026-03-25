# Pipeline Reference

## Architecture

```
Input file → Detector → Pipeline type → Resolve passes → Run passes → Output
```

Every pass implements the `Pass` protocol: `apply(data: bytes, config: PassConfig) -> bytes`. Passes are stateless and pure — given the same input and config, they produce the same output (modulo randomization).

## Pipeline Overview

### PS1 Pipeline (`--pipeline ps`)

**Auto-detection**: `.ps1`, `.psm1`, `.psd1` extensions; `pwsh`/`powershell` shebang

**Default passes** (in order):
1. `amsi` — Prepend AMSI bypass (configurable via `--amsi-technique`)
2. `rename` — Randomize variable and function names
3. `tokenize` — Fragment suspicious strings via concatenation/char-code
4. `encode` — Base64-encode with IEX decoder stub

**Opt-in passes**:
- `uac` — Wrap in UAC bypass (activated by `--uac`)
- `ps1-loader` — Generate PS1 .NET assembly loader (activated by `--ps1-loader`)

**Pass ordering with opt-in**:
```
amsi → rename → tokenize → encode → [uac]
```

### .NET IL Pipeline (`--pipeline dotnet-il`)

**Auto-detection**: MZ header + CLR data directory (PE files with .NET metadata)

**Default passes** (in order):
1. `dinvoke` — Convert PInvoke to runtime resolution
2. `rename` — Randomize types, methods, fields, properties
3. `encrypt-strings` — XOR-encrypt string literals with runtime decryptor
4. `flow` — NOP padding and opaque predicates
5. `strip-debug` — Remove debug attributes and PDB references

**Opt-in passes**:
- `embed` — In-memory loader with encrypted payload (activated by `--embed`)
- `lolbas-installutil` — InstallUtil format (activated by `--lolbas installutil`)
- `lolbas-regasm` — RegAsm format (activated by `--lolbas regasm`)
- `lolbas-rundll32` — RunDll32 format (activated by `--lolbas rundll32`)
- `clm-bypass` — CLM bypass exe (activated by `--clm-bypass`)

### Shellcode Pipeline (`--pipeline shellcode`)

**Auto-detection**: `.bin`, `.raw`, `.shellcode` extensions

**Default passes** (in order):
1. `encrypt` — AES-256-CBC encryption (output: `key || IV || ciphertext`)
2. `loader` — Generate C# exe or PS1 script (configurable via `--format`)

**Opt-in passes**:
- `inject` — Remote process injection (activated by `--inject`)

### Script Pipeline (`--pipeline script`)

**Auto-detection**: `.py`, `.sh`, `.bash` extensions; python/bash/sh shebang

**Default passes** (in order):
1. `wrap` — Language-aware execution wrapper
2. `encode` — Base64-encode with language-appropriate decoder

### VBS Pipeline (`--pipeline vbs`)

**Auto-detection**: `.vbs`, `.vbe` extensions

**Default passes** (in order):
1. `encode` — XOR-encode with Chr() runtime decoder
2. `wrap` — WScript.Shell execution wrapper

## Cross-Pipeline Routing

Some feature flags chain multiple pipelines:

### `--ps1-loader` (dotnet-il → PS1)

```
.NET assembly → [dotnet-il passes] → PS1 loader generation → [PS1 passes] → output.ps1
```

### `--clm-bypass` (PS1 → dotnet-il)

```
PS1 script → [PS1 passes] → CLM bypass exe generation → output.exe
```

## Mutual Exclusivity Rules

| Flag A | Flag B | Allowed? |
|--------|--------|----------|
| `--embed` | `--ps1-loader` | No |
| `--embed` | `--lolbas` | No |
| `--ps1-loader` | `--lolbas` | No |
| `--inject` | `--format` | No |
| `--clm-bypass` | `--embed` | No |
| `--clm-bypass` | `--ps1-loader` | No |
| `--clm-bypass` | `--lolbas` | No |
| `--uac` | (non-PS1 pipeline) | No |
| `--inject` | (non-shellcode pipeline) | No |

## Custom Pass Selection

Override default passes with `--passes`:

```bash
# Only run specific passes
penumbra payload.exe --passes rename,encrypt-strings

# Include opt-in pass by name
penumbra payload.exe --passes dinvoke,rename,embed
```
