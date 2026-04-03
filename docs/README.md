# Penumbra Documentation

Modular obfuscation toolkit with composable pass architecture.

## Quick Start

```bash
uv tool install git+https://github.com/chsoares/penumbra.git
penumbra payload.exe
```

## Pipelines

| Pipeline | Extensions | Default Passes |
|----------|-----------|----------------|
| PS1 | `.ps1`, `.psm1`, `.psd1` | amsi, rename, tokenize, encode |
| .NET IL | `.exe`/`.dll` (MZ+CLR) | dinvoke, rename, encrypt-strings, flow, strip-debug, scrub-guid |
| Script | `.py`, `.sh`, `.bash` | wrap, encode |
| Shellcode | `.bin`, `.raw`, `.shellcode` | encrypt, loader |
| VBS | `.vbs`, `.vbe` | encode, wrap |

## Feature Flags

| Flag | Pipeline | Description |
|------|----------|-------------|
| `--amsi-technique` | PS1 | AMSI bypass: `reflection`, `patch`, `context` |
| `--ps1-loader` | .NET IL | Wrap assembly in PS1 reflective loader |
| `--embed` | .NET IL | In-memory loader with encrypted payload |
| `--host <path>` | .NET IL | Trojanize existing .NET binary |
| `--lolbas <fmt>` | .NET IL | LOLBAS: `installutil`, `regasm` |
| `--uac <method>` | PS1 | UAC bypass: `fodhelper`, `diskcleanup`, `computerdefaults` |
| `--clm-bypass` | PS1 | Wrap PS1 in CLM bypass exe |
| `--inject [proc]` | Shellcode | Process injection mode |
| `--format <fmt>` | Shellcode | Output format: `exe`, `ps1` |
| `--source` | Any C# pass | Export project source instead of compiling |

## Documentation Pages

- [AMSI Bypass Techniques](amsi-bypass.md)
- [PS1 .NET Assembly Loader](ps1-loader.md)
- [LOLBAS Output Formats](lolbas.md)
- [Process Injection](process-injection.md)
- [UAC Bypass](uac-bypass.md)
- [CLM Bypass](clm-bypass.md)
- [VBS Pipeline](vbs-pipeline.md)
- [Pipeline Reference](pipelines.md)
