# Pipeline Reference

## Architecture

```
Input file → Detector → Pipeline type → Resolve passes → Run passes → Output
```

Every pass implements the `Pass` protocol: `apply(data: bytes, config: PassConfig) -> bytes`.

## PS1 Pipeline (`--pipeline ps`)

**Auto-detection**: `.ps1`, `.psm1`, `.psd1` extensions

**Default passes**: `amsi` → `rename` → `tokenize` → `encode`

**Opt-in passes**:
- `uac` — UAC bypass wrapper (`--uac`)
- `ps1-loader` — PS1 .NET assembly loader (`--ps1-loader`)

## .NET IL Pipeline (`--pipeline dotnet-il`)

**Auto-detection**: MZ header + CLR data directory

**Default passes**: `dinvoke` → `rename` → `encrypt-strings` → `flow` → `strip-debug`

**Opt-in passes**:
- `embed` — in-memory loader (`--embed`)
- `lolbas-installutil` — InstallUtil format (`--lolbas installutil`)
- `lolbas-regasm` — RegAsm format (`--lolbas regasm`)
- `clm-bypass` — CLM bypass exe (`--clm-bypass`)

## Shellcode Pipeline (`--pipeline shellcode`)

**Auto-detection**: `.bin`, `.raw`, `.shellcode` extensions

**Default passes**: `encrypt` → `loader`

**Opt-in passes**:
- `inject` — remote process injection (`--inject`). Replaces `loader`.

## Script Pipeline (`--pipeline script`)

**Auto-detection**: `.py`, `.sh`, `.bash` extensions

**Default passes**: `wrap` → `encode`

## VBS Pipeline (`--pipeline vbs`)

**Auto-detection**: `.vbs`, `.vbe` extensions

**Default passes**: `encode` → `wrap`

## Cross-Pipeline Routing

### `--ps1-loader` (dotnet-il → PS1)

```
.NET assembly → [dotnet-il passes] → PS1 loader generation → output.ps1
```

### `--clm-bypass` (PS1 → dotnet-il)

```
PS1 script → [PS1 passes] → CLM bypass exe generation → output.exe
```

## `--source` Flag

Passes that generate C# projects (`--lolbas`, `--clm-bypass`, `--inject`, `--embed`) can export source instead of compiling:

```bash
penumbra implant.exe --lolbas installutil --source -o project.src
# Produces a directory with .cs and .csproj files
# Compile on Windows: dotnet publish project.src -c Release
```

Useful when the target framework requires Windows-only assemblies (CLM bypass) or when you want to customize the generated code.

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
| `--uac` | (non-PS1) | No |
| `--inject` | (non-shellcode) | No |
