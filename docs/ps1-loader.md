# PS1 .NET Assembly Reflective Loader

## What is reflective loading?

Reflective loading is the technique of loading a .NET assembly entirely in memory, without writing it to disk. PowerShell's `[Reflection.Assembly]::Load(byte[])` method accepts raw bytes and loads them as a .NET assembly, making it possible to execute C# tools (like Seatbelt, SharpHound, Rubeus) from a PowerShell script.

## Why does this matter?

Many offensive .NET tools are well-signatured by AV products. By wrapping the assembly in a PS1 loader:

1. The assembly never touches disk — it's embedded as a compressed, encoded string
2. Penumbra's IL obfuscation passes run first, modifying the assembly
3. The result is a single `.ps1` file that can be executed directly

## Usage

```bash
# Wrap a .NET assembly in a PS1 loader
penumbra Seatbelt.exe --ps1-loader -o Invoke-Seatbelt.ps1

# Only run safe passes (for tools with heavy reflection like Seatbelt)
penumbra Seatbelt.exe --ps1-loader --passes strip-debug
```

**Important**: The generated script requires an AMSI bypass before execution. Penumbra generates a `.amsi.txt` file alongside the output with the bypass command to paste in PowerShell.

## How it Works

The `--ps1-loader` flag triggers a two-stage pipeline:

### Stage 1: .NET IL Obfuscation
The input assembly goes through the dotnet-il passes (configurable via `--passes`).

### Stage 2: PS1 Loader Generation
The obfuscated assembly is wrapped in a PowerShell script that:
1. Base64-decodes and DeflateStream-decompresses the embedded assembly
2. Calls `[Reflection.Assembly]::Load(byte[])` to load it
3. Redirects `[Console]::Out` to a `StringWriter` to capture output
4. Invokes the assembly's `EntryPoint` with `$args`
5. Restores the original output stream and prints the result

No PS1 obfuscation passes run on the loader — the assembly is already obfuscated by the IL passes, and additional PS1 passes (tokenize, encode) cause issues with large embedded payloads.

## AMSI Considerations

The `reflection` AMSI bypass (`amsiInitFailed`) does NOT protect `Assembly.Load()` calls — only the PS session. You need the `patch` bypass (which patches `amsi.dll` process-wide) before running the loader script. The `.amsi.txt` file contains this bypass.

## Mutual Exclusivity / Compatibility

- `--ps1-loader` is mutually exclusive with `--embed` and `--lolbas`
- Input must be a .NET assembly (auto-detected or `--pipeline dotnet-il`)
- Output is always `.ps1`
- Compatible with `--passes` to select which IL passes run
- Use `--safe-rename` or `--passes strip-debug` for reflection-heavy tools (Seatbelt, Rubeus)
