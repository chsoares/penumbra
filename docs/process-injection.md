# Process Injection

## What is process injection?

Process injection executes code within the address space of another running process. Instead of running shellcode in the current process, it's written into a legitimate process like `calc.exe` and executed there.

## Technique

Penumbra implements PE injection using standard PInvoke APIs:

1. **CreateProcess**: Spawns target process (configurable, default `notepad.exe`) with `DETACHED_PROCESS | CREATE_NO_WINDOW`
2. **VirtualAllocEx**: Allocates memory with `PAGE_READWRITE` (not RWX)
3. **WriteProcessMemory**: Copies decrypted shellcode
4. **VirtualProtectEx**: Changes protection to `PAGE_EXECUTE_READ` (W^X compliant)
5. **CreateRemoteThread**: Starts execution

## Usage

```bash
# Default target (notepad.exe)
penumbra shellcode.bin --inject

# Custom target process
penumbra shellcode.bin --inject calc.exe

# Export source for compilation on Windows
penumbra shellcode.bin --inject calc.exe --source -o inject.src
```

## How it Works

The generated C# executable includes:

1. **AMSI bypass**: HWBP+VEH patchless bypass
2. **AES decryption**: Shellcode is AES-256-CBC encrypted (from the `encrypt` pass)
3. **Payload fragmentation**: Encrypted payload split across multiple classes
4. **Junk code**: 5-8 fake classes with plausible names
5. **Injection**: PInvoke injection into the spawned target process

Input format: `[32-byte key][16-byte IV][AES ciphertext]` (output of `encrypt` pass).

## Mutual Exclusivity / Compatibility

- `--inject` is mutually exclusive with `--format`
- Valid only with the shellcode pipeline
- Replaces the default `loader` pass
- Use `--source` on Linux to export and compile on Windows
