# AMSI Bypass Techniques

## What is AMSI?

The Antimalware Scan Interface (AMSI) is a standardized Windows interface that allows applications to request runtime scanning of content by the installed antivirus product. PowerShell, VBScript, JScript, and .NET's `Assembly.Load()` all submit content to AMSI before execution.

When a PowerShell script runs, each script block is sent to AMSI for scanning. Similarly, when `[Reflection.Assembly]::Load(byte[])` is called, the loaded assembly bytes are scanned. This means that even if a payload is encrypted on disk, it can be detected at the moment of execution.

AMSI is implemented in `amsi.dll`, which is loaded into every PowerShell process. The key function is `AmsiScanBuffer`, which receives the content to scan and returns a verdict.

## Why does this matter?

Without an AMSI bypass, obfuscated payloads that look clean on disk will still be caught at runtime. This is especially critical for:

- PowerShell scripts that use `Invoke-Expression` or `Assembly.Load`
- .NET assemblies loaded reflectively via PS1 loaders
- Any script that performs suspicious operations at runtime

## Techniques Available

| Technique | Scope | Stealth | Use Case |
|-----------|-------|---------|----------|
| `reflection` | PS session only | Low (well-known) | Quick PS1 scripts, no Assembly.Load |
| `patch` | Process-wide (amsi.dll) | Medium | PS1 .NET loaders, reflective loading |
| `context` | PS session only | High (less common) | Alternative to reflection, harder to signature |

### `reflection` — amsiInitFailed

Sets `System.Management.Automation.AmsiUtils.amsiInitFailed` to `$true` via reflection. This tells PowerShell that AMSI initialization failed, so it skips all subsequent scans for the session.

**Limitation**: Only affects PowerShell's own AMSI integration. Does NOT disable AMSI scanning triggered by `Assembly.Load()`, which goes through a separate code path in the CLR.

### `patch` — AmsiScanBuffer memory patch

Uses `Add-Type` to call `GetProcAddress` on `amsi.dll` to find `AmsiScanBuffer`, then overwrites its first 6 bytes with:

```asm
mov eax, 0x80004005  ; E_FAIL
ret
```

This causes every call to `AmsiScanBuffer` in the process to immediately return `E_FAIL`, effectively disabling all AMSI scanning process-wide — including `Assembly.Load()`.

**Use this when**: Your payload uses `--ps1-loader` or any form of reflective .NET assembly loading.

### `context` — amsiContext corruption

Allocates a small buffer via `Marshal.AllocHGlobal(4)` and assigns it to the `amsiContext` field in `AmsiUtils`, then nulls the `amsiSession` field. This corrupts AMSI's internal state, causing `AmsiOpenSession` to return `E_INVALIDARG`.

**Advantage**: Less well-known than the other two techniques, making it harder to signature.

## Usage

```bash
# Default (reflection)
penumbra script.ps1

# Explicit technique selection
penumbra script.ps1 --amsi-technique patch
penumbra script.ps1 --amsi-technique context

# With PS1 loader (patch is used by default since Assembly.Load needs it)
penumbra Seatbelt.exe --ps1-loader
```

## How it Works

All three techniques are prepended to the script before other obfuscation passes run. The generated code uses:

- Randomized variable names (`$_<hex>`)
- String concatenation to split sensitive identifiers
- Different code structures on each generation

## Mutual Exclusivity / Compatibility

- `--amsi-technique` is valid only with the PS1 pipeline
- When using `--ps1-loader`, the default technique switches to `patch` (can be overridden)
- All three techniques are compatible with `--uac`, `--clm-bypass`, and standard PS1 passes
