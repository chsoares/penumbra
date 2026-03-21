# Next Steps — .NET IL Pipeline

Comparison against [MacroPack blog](https://blog.balliskit.com/obfuscation-and-weaponization-of-net-assemblies-using-macropack-77feb815489c) techniques.

## What we have

| Technique | Our pass | Notes |
|---|---|---|
| Symbol renaming | `rename` | Types, methods, fields, properties |
| String encryption | `encrypt-strings` | XOR + injected IL-level decryptor |
| Metadata stripping | `strip-debug` | PDB, `DebuggableAttribute`, compiler attributes |
| Control flow obfuscation | `flow` | NOP padding + opaque predicates |
| Reflection-safe renaming | `rename --safe-rename` | **Partial** — we skip symbols that appear as string literals. MacroPack instead renames everything and injects a runtime mapping dictionary that intercepts reflection calls transparently. Our approach is safer but less thorough |

## What's missing

### 1. DInvoke Mutation (highest impact)

Convert static `[DllImport("kernel32.dll")]` (PInvoke) into runtime dynamic resolution (DInvoke). Native function names (`VirtualAlloc`, `CreateRemoteThread`) and DLL names (`kernel32.dll`) disappear from the assembly metadata entirely.

**Why it matters**: PInvoke imports are the #1 static detection vector. AV/EDR scans for suspicious native API import combinations. With DInvoke, there's nothing to scan.

**Implementation**: Parse PInvoke signatures in IL, replace with delegate-based runtime resolution via `GetProcAddress` or API hashing. Requires injecting resolver code into the assembly.

**Complexity**: High.

### 2. In-Memory Embedding (high impact)

Wrap the obfuscated assembly inside a new .NET loader that loads the payload via `Assembly.Load(byte[])`. The original assembly never touches disk.

**Why it matters**: Defeats file-based scanning and EDR file-write hooks. Complicates forensic analysis.

**Implementation**: Generate a loader C# project that embeds the obfuscated assembly as an encrypted resource, extracts it at runtime, and loads it in-process.

**Complexity**: Medium.

### 3. Entropy Reduction (easy win)

Inflate the assembly with structured low-entropy padding to reduce Shannon entropy. Obfuscated/encrypted payloads tend toward ~8.0 bits/byte, which is a common AV heuristic flag.

**Why it matters**: Makes the binary look like legitimate software to entropy-based heuristics.

**Implementation**: Add structured padding data to the assembly. Configurable size parameter (`--inflate-size`).

**Complexity**: Low.

### 4. Heuristic-Bypass Naming (easy win)

Generate variable/function names that look plausible (`GetServiceHandler`, `ProcessDataItem`) instead of random hex (`_a8f3c2d1`). Purely random names are themselves an obfuscation signal.

**Why it matters**: Heuristic engines flag assemblies where all symbols are random gibberish.

**Implementation**: Combine programming verbs/nouns to generate realistic-looking identifiers. Apply to both .NET `rename` and PS1 `rename` passes.

**Complexity**: Low-medium.

### 5. Hide Console (trivial)

Set the PE subsystem to Windows GUI so no console window appears during execution.

**Why it matters**: Prevents visible indicators of suspicious activity.

**Implementation**: Flip the subsystem flag in the PE header via dnlib.

**Complexity**: Trivial.

## Suggested priority

1. DInvoke mutation — biggest evasion impact
2. In-memory embedding — second biggest
3. Entropy reduction — quick win
4. Heuristic-bypass naming — quick win
5. Hide console — trivial addition
