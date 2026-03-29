# PowerShell CLM Bypass

## What is CLM?

Constrained Language Mode (CLM) is a PowerShell security feature that restricts dangerous operations — `Add-Type`, .NET reflection, COM object creation. It's automatically enabled when AppLocker is configured.

## How the Bypass Works

The CLM bypass generates a compiled .NET executable (net472) that:

1. Creates a PowerShell `Runspace` via `RunspaceFactory.CreateRunspace()` — defaults to **FullLanguage mode**
2. Attaches a `PowerShell` object to the runspace
3. Decrypts the embedded PS1 payload (XOR-encrypted at build time)
4. Calls `AddScript()` with the decrypted payload
5. Invokes and writes results to the console

The key insight: programmatically created runspaces default to FullLanguage mode regardless of the system's CLM policy.

### Argument Mode

The generated exe supports passing a base64-encoded command via CLI:

```
CLMBypass.exe <base64_encoded_command>
```

## Usage

```bash
# Wrap PS1 in CLM bypass exe (requires Windows for compilation)
penumbra script.ps1 --clm-bypass -o CLMBypass.exe

# Export source for compilation on Windows
penumbra script.ps1 --clm-bypass --source -o CLMBypass.src
# Then on Windows: dotnet publish CLMBypass.src -c Release
```

## Platform Notes

The CLM bypass references `System.Management.Automation.dll` from the Windows GAC. This means:

- **Windows with dotnet SDK**: Compiles directly
- **Linux**: Use `--source` to export the project, then compile on Windows

The exe must still bypass AppLocker — place in `C:\Windows\Tasks\` or similar writable, allowed path.

## Mutual Exclusivity / Compatibility

- `--clm-bypass` requires PS1 input
- Mutually exclusive with `--embed`, `--ps1-loader`, `--lolbas`
- Targets net472 (uses GAC-resident `System.Management.Automation.dll`)
