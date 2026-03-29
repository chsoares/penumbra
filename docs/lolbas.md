# LOLBAS Output Formats

## What is LOLBAS?

LOLBAS (Living Off the Land Binaries and Scripts) refers to legitimate, Microsoft-signed binaries that can be abused for unintended purposes — such as executing arbitrary code. Because these binaries are signed by Microsoft and located in trusted paths like `C:\Windows\`, they are typically allowed by AppLocker policies.

## Techniques Available

| Format | Binary | Invocation | Output Type |
|--------|--------|-----------|-------------|
| `installutil` | InstallUtil.exe | `/logfile= /LogToConsole=false /U payload.exe` | `.exe` |
| `regasm` | RegAsm.exe | `/U payload.dll` | `.dll` |

Both are located in `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\`, which is typically in AppLocker's default allow rules.

### `installutil` — InstallUtil.exe

The payload class inherits `System.Configuration.Install.Installer` with `[RunInstaller(true)]` and overrides `Uninstall()`. When invoked with `/U`, InstallUtil calls the uninstall method, executing the payload.

### `regasm` — RegAsm.exe

The payload class is decorated with `[ComVisible(true)]` and `[Guid("...")]`, with a static method marked `[ComUnregisterFunction]`. When invoked with `/U`, RegAsm calls the COM unregister function.

## Usage

```bash
# InstallUtil format
penumbra implant.exe --lolbas installutil -o payload.exe

# RegAsm format
penumbra implant.exe --lolbas regasm -o payload.dll

# Export source instead of compiling (for cross-platform use)
penumbra implant.exe --lolbas installutil --source -o payload.src
```

Penumbra prints an execution hint after generation showing the exact command needed.

## How it Works

Both formats follow the same internal pattern:

1. XOR-encrypt the input assembly with a random 32-byte key
2. Fragment the encrypted payload across multiple C# classes
3. Generate 5-8 junk classes for entropy reduction
4. Include HWBP+VEH AMSI bypass
5. At runtime: reassemble fragments, XOR-decrypt, `Assembly.Load()`, invoke EntryPoint
6. Compile as net472 (available on all modern Windows without runtime install)

## Mutual Exclusivity / Compatibility

- `--lolbas` is mutually exclusive with `--embed` and `--ps1-loader`
- Valid only with .NET IL pipeline input
- All LOLBAS outputs target net472 for maximum compatibility
- Use `--source` on Linux to export and compile on Windows
