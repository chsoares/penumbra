# PS1 .NET Assembly Reflective Loader

## What is reflective loading?

Reflective loading is the technique of loading a .NET assembly entirely in memory, without writing it to disk. PowerShell's `[Reflection.Assembly]::Load(byte[])` method accepts raw bytes and loads them as a .NET assembly, making it possible to execute C# tools (like Seatbelt, SharpHound, Rubeus) from a PowerShell script.

This avoids dropping the binary to disk, where it could be detected by file-based AV scanning.

## Why does this matter?

Many offensive .NET tools are well-signatured by AV products. Even after IL-level obfuscation, dropping them to disk risks detection. By wrapping the assembly in a PS1 loader:

1. The assembly never touches disk — it's embedded as a compressed, encoded string
2. Penumbra's IL obfuscation passes run first, modifying the assembly
3. The PS1 wrapper adds AMSI bypass, variable randomization, and string obfuscation
4. The result is a single `.ps1` file that can be executed directly

## Usage

```bash
# Basic: wrap a .NET assembly in a PS1 loader
penumbra Seatbelt.exe --ps1-loader -o Invoke-Seatbelt.ps1

# With specific AMSI technique
penumbra Rubeus.exe --ps1-loader --amsi-technique context

# The output is a standalone PS1 script
powershell -ep bypass -File Invoke-Seatbelt.ps1
```

## How it Works

The `--ps1-loader` flag triggers a two-stage pipeline:

### Stage 1: .NET IL Obfuscation
The input assembly goes through the dotnet-il default passes:
1. **dinvoke** — Convert PInvoke to runtime resolution
2. **rename** — Randomize type/method/field names
3. **encrypt-strings** — XOR-encrypt string literals
4. **flow** — Insert opaque predicates and NOP padding
5. **strip-debug** — Remove debug attributes and PDB references

### Stage 2: PS1 Loader Generation
The obfuscated assembly is wrapped in a PowerShell script that:
1. Runs an AMSI bypass (defaults to `patch` since `Assembly.Load` needs process-wide bypass)
2. Base64-decodes and DeflateStream-decompresses the embedded assembly
3. Calls `[Reflection.Assembly]::Load(byte[])` to load it
4. Redirects `[Console]::Out` to a `StringWriter` to capture output
5. Invokes the assembly's `EntryPoint`
6. Restores the original output stream and prints the captured result

### Stage 3: PS1 Obfuscation
The generated PS1 script then goes through the PS1 default passes:
1. **amsi** — Prepend AMSI bypass
2. **rename** — Randomize PS1 variable names
3. **tokenize** — Fragment suspicious strings
4. **encode** — Base64-encode with IEX decoder

## Mutual Exclusivity / Compatibility

- `--ps1-loader` is mutually exclusive with `--embed` and `--lolbas`
- Compatible with `--amsi-technique` (overrides the AMSI technique used in the loader)
- Input must be a .NET assembly (auto-detected or `--pipeline dotnet-il`)
- Output is always `.ps1`
