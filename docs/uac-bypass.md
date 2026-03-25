# UAC Bypass

## What is UAC?

User Account Control (UAC) is a Windows security mechanism that manages privilege elevation. Even when logged in as an administrator, processes run at **medium integrity** by default. UAC gates the transition to **high integrity** — requiring user consent via the familiar elevation prompt.

Certain auto-elevating binaries (marked with `autoElevate=true` in their manifest) skip this prompt, silently elevating to high integrity. UAC bypass techniques abuse these binaries to achieve elevation without user interaction.

## Why does this matter?

Many offensive operations require high integrity (e.g., accessing SAM, modifying protected registry keys, dumping credentials). If the operator already has an admin account but is running at medium integrity, a UAC bypass provides seamless elevation.

**Prerequisite**: The current user must be in the local Administrators group. UAC bypass does not escalate from a standard user to admin — it bypasses the consent prompt for an existing admin.

## Techniques Available

| Method | Mechanism | Cleanup Required | Detection Risk |
|--------|-----------|-----------------|---------------|
| `fodhelper` | Registry hijack (`ms-settings\Shell\Open\command`) | Yes (registry + file) | Medium (well-known) |
| `diskcleanup` | Environment variable hijack (`%windir%`) | Yes (env var + file) | Low (less common) |
| `computerdefaults` | Registry hijack (same as fodhelper) | Yes (registry + file) | Medium |

### `fodhelper` — FodHelper.exe

Creates a registry key at `HKCU:\Software\Classes\ms-settings\Shell\Open\command` with `DelegateExecute` set to empty string and the default value pointing to the payload. When `fodhelper.exe` launches, it reads this registry key and executes the command at high integrity.

### `diskcleanup` — SilentCleanup scheduled task

Sets the `windir` environment variable in `HKCU:\Environment` to `cmd.exe /K powershell -ep bypass -File <payload> & REM `. The SilentCleanup scheduled task (which runs at high integrity) uses `%windir%` in its path, so it executes the injected command.

### `computerdefaults` — ComputerDefaults.exe

Same registry hijack as `fodhelper` but triggers via `computerdefaults.exe` instead. Useful as an alternative when `fodhelper.exe` is monitored.

## Usage

```bash
# FodHelper (default)
penumbra payload.ps1 --uac fodhelper

# DiskCleanup
penumbra payload.ps1 --uac diskcleanup

# ComputerDefaults
penumbra payload.ps1 --uac computerdefaults
```

## How it Works

The UAC bypass pass runs **after** the encode pass, wrapping the final obfuscated payload:

1. Writes the obfuscated PS1 payload to `C:\Windows\Tasks\<random>.ps1`
2. Sets up the bypass mechanism (registry key or environment variable)
3. Triggers the auto-elevating binary
4. Sleeps 3 seconds to allow execution
5. Cleans up (removes registry keys/env vars and the temp script)

## Mutual Exclusivity / Compatibility

- `--uac` is only valid with the PS1 pipeline
- Compatible with all PS1 passes and `--amsi-technique`
- The UAC wrapper runs after encode, wrapping the fully obfuscated payload
- Not compatible with `--clm-bypass` (CLM bypass outputs an exe, not PS1)
