# Process Injection

## What is process injection?

Process injection is the technique of executing code within the address space of another running process. Instead of running shellcode in the current process (which may be suspicious), the shellcode is written into a legitimate process like `notepad.exe` and executed there. This makes the malicious activity appear to originate from a trusted process.

## Why does this matter?

Security products monitor process behavior. A `cmd.exe` process making network connections or accessing LSASS looks suspicious. But `notepad.exe` doing the same thing is harder to flag, since the injection source process can exit immediately after injection, leaving the shellcode running inside the target.

## Technique

Penumbra implements **classic remote process injection** using standard PInvoke APIs:

1. **Spawn target**: `Process.Start("notepad.exe")` with hidden window
2. **Open process**: `OpenProcess` with `PROCESS_ALL_ACCESS`
3. **Allocate memory**: `VirtualAllocEx` with `PAGE_READWRITE` (not RWX — avoids detection)
4. **Write shellcode**: `WriteProcessMemory` copies decrypted shellcode
5. **Change protection**: `VirtualProtectEx` to `PAGE_EXECUTE_READ` (W^X compliant)
6. **Execute**: `CreateRemoteThread` starts execution at the allocated address

This two-step memory protection approach (allocate RW, then change to RX) avoids allocating RWX memory, which is a common detection heuristic.

## Usage

```bash
# Default target (notepad.exe)
penumbra shellcode.bin --inject

# Custom target process
penumbra shellcode.bin --inject explorer.exe

# Output is a compiled .NET exe
# Run: payload.exe (spawns notepad and injects)
```

## How it Works

The generated C# executable includes:

1. **Sandbox evasion**: Sleep acceleration check (detects fast-forwarded sleeps) and CPU count check (detects single-CPU VMs)
2. **AMSI bypass**: HWBP+VEH patchless bypass
3. **AES decryption**: The shellcode is AES-256-CBC encrypted (key/IV from the encrypt pass)
4. **Payload fragmentation**: Encrypted payload split across multiple classes
5. **Junk code**: 5-8 fake classes with plausible names and low-entropy strings
6. **Injection**: Standard PInvoke injection into the target process

The input must be pre-encrypted shellcode (output of the `encrypt` pass), in the format:
`[32-byte key][16-byte IV][AES ciphertext]`

## Mutual Exclusivity / Compatibility

- `--inject` is mutually exclusive with `--format`
- Valid only with the shellcode pipeline
- Replaces the default `loader` pass (which does in-process execution)
- Compatible with the `encrypt` pass (runs before inject in the pipeline)
- Target process name is configurable; defaults to `notepad.exe`
