# PowerShell CLM Bypass

## What is CLM?

Constrained Language Mode (CLM) is a PowerShell security feature that restricts the language elements available in a session. When enabled, CLM blocks:

- `Add-Type` (compiling C# at runtime)
- .NET reflection (`[Type]::GetMethod()`, etc.)
- COM object creation
- Most offensive PowerShell tooling

CLM is automatically enabled when AppLocker is configured with script rules, or when WDAC (Windows Defender Application Control) policies are active. It's one of the most effective defenses against PowerShell-based attacks.

## Why does this matter?

In environments with CLM, PowerShell scripts are severely limited. AMSI bypasses that use `Add-Type` or reflection won't work. Offensive tools like PowerView, Invoke-Mimikatz, etc., fail entirely. A CLM bypass is required to run any meaningful PowerShell tooling.

## How the Bypass Works

The CLM bypass generates a compiled .NET executable (net472) that:

1. Creates a PowerShell `Runspace` via `RunspaceFactory.CreateRunspace()` — this defaults to **FullLanguage mode** regardless of the system's CLM policy
2. Attaches a `PowerShell` object to the runspace
3. Decrypts the embedded PS1 payload (XOR-encrypted at build time)
4. Calls `AddScript()` with the decrypted payload
5. Invokes and writes results to the console

The key insight is that programmatically created runspaces default to FullLanguage mode. The CLM restriction only applies to the interactive PowerShell session and scripts loaded through the normal PowerShell host.

### Argument Mode

The generated exe also supports passing a base64-encoded command via command-line arguments:

```
clm_bypass.exe <base64_encoded_command>
```

This allows running arbitrary commands through the FullLanguage runspace without re-embedding.

## Usage

```bash
# Wrap a PS1 script in a CLM bypass exe
penumbra script.ps1 --clm-bypass -o bypass.exe

# The output is a .NET Framework 4.7.2 exe
# Copy to target and run:
bypass.exe

# Or pass a base64-encoded command:
bypass.exe <base64_command>
```

## Mutual Exclusivity / Compatibility

- `--clm-bypass` requires PS1 input
- Mutually exclusive with `--embed`, `--ps1-loader`, `--lolbas`
- The PS1 script goes through PS1 passes first, then gets wrapped in the CLM bypass exe
- The exe targets net472 (uses GAC-resident `System.Management.Automation.dll`)
- Must still bypass AppLocker for the exe itself — place in `C:\Windows\Tasks\` or similar writable, allowed path
