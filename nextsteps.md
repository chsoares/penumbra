# Next Steps — .NET IL Pipeline

Comparison against [MacroPack blog](https://blog.balliskit.com/obfuscation-and-weaponization-of-net-assemblies-using-macropack-77feb815489c) techniques and real-world VirusTotal results.

## Current results (SharpHound v2.11.0)

| Stage | VT detections | Notes |
|---|---|---|
| Original | 47/72 | Heavily signatured |
| After IL obfuscation (rename, encrypt-strings, flow, strip-debug) | 26/72 | No more BloodHound/SharpHound labels |
| After IL obfuscation + embed | 22/72 | Labels shifted to `MSIL.Krypt`, `Obfuscator` — identity hidden but loader pattern flagged |

## What we have

| Technique | Our pass | Default | Notes |
|---|---|---|---|
| DInvoke mutation | `dinvoke` | Yes | Converts PInvoke to runtime resolution. Conservative mode skips complex marshalling. Effective for tools with direct Win32 API calls (e.g., SharpKatz), not for high-level tools like SharpHound that use managed APIs |
| Symbol renaming | `rename` | Yes | Types, methods, fields, properties |
| String encryption | `encrypt-strings` | Yes | XOR + injected IL-level decryptor |
| Control flow obfuscation | `flow` | Yes | NOP padding + opaque predicates |
| Metadata stripping | `strip-debug` | Yes | PDB, `DebuggableAttribute`, compiler attributes |
| In-memory embedding | `embed` | **Opt-in** | XOR-encrypted payload + `Assembly.Load(byte[])` loader. Use via `--passes ...,embed` |
| Reflection-safe renaming | `rename --safe-rename` | — | Partial — skips symbols that appear as string literals |

## Embed delivery pipeline (next focus)

The `embed` pass hides payload identity (47→22 detections, no more BloodHound labels) but the loader itself gets flagged as `MSIL.Krypt` / `Obfuscator` because it's an obvious decrypt-and-load stub. The next improvements all target making the loader look legitimate.

### 1. Entropy reduction for the loader

Inflate the loader with structured low-entropy padding (fake classes, string arrays, resource files) to bring Shannon entropy down from ~7.5 to ~5.5 bits/byte.

**Why it matters**: Multiple VT vendors flag on entropy alone (`Suspicious.low.ml.score`, `Static AI - Malicious PE`).

**Implementation**: After generating the loader C# project, add fake source files with realistic code patterns before compiling. Configurable via `--inflate-size`.

**Complexity**: Low.

### 2. Payload fragmentation

Split the encrypted payload into multiple smaller Base64 chunks embedded as separate string constants or resource files, reconstructed at runtime.

**Why it matters**: A single 1.8MB Base64 string screams "encrypted payload". Multiple smaller strings distributed across classes look like normal application data.

**Implementation**: Split encrypted bytes into N chunks (configurable), generate N static fields across M fake classes, reassemble in `Main()`.

**Complexity**: Low-medium.

### 3. Trojanized assembly (`--host` flag) — IMPLEMENTED

Inject the loading code into an existing legitimate .NET assembly provided by the user.

```bash
penumbra implant.exe --embed --host /path/to/legit-tool.exe
```

**Execution model (Option B — payload replaces host)**:
- The host's `Main()` is hijacked: decrypt → `Assembly.Load` → `EntryPoint.Invoke(args)`
- The payload runs in the same terminal, receives the CLI args, behaves exactly like the original tool
- The host's original code **never executes** — it's purely camouflage for static analysis
- AV sees the host's full structure (types, methods, imports, strings, resources) + one extra embedded resource

**Why Option B over alternatives**:
- Option A (host runs, payload in background): payload needs args but they go to host. No way to see output or know when done
- Option C (env var trigger): adds complexity, risk of accidental execution of host
- Option B is what red teamers actually want: the binary looks like NuGet.exe to AV, but runs SharpHound when executed

**Host selection guidelines**:
- CLI host for CLI payloads (same Console subsystem, shares terminal naturally)
- GUI host for persistent payloads (implants/beacons that run in background)
- Prefer hosts with many types/methods/resources for maximum camouflage

### 4. Heuristic-bypass naming

Generate plausible identifiers (`GetServiceHandler`, `ProcessDataItem`) instead of random hex (`_a8f3c2d1`). Apply to both the `rename` pass and the `embed` loader's generated code.

**Why it matters**: Random gibberish names are themselves a detection signal for ML-based classifiers.

**Implementation**: Dictionary of programming verbs (`Get`, `Set`, `Process`, `Handle`, `Create`, `Update`) + nouns (`Service`, `Config`, `Data`, `Context`, `Manager`, `Factory`). Random combinations produce natural-looking names.

**Complexity**: Low.

### 5. Hide console

Set PE subsystem to Windows GUI in the loader output.

**Why it matters**: Console window appearing is a visible indicator.

**Implementation**: Flip subsystem flag in PE header via dnlib, or set `<OutputType>WinExe</OutputType>` in the loader's .csproj.

**Complexity**: Trivial.

### 6. Cross-pipeline embedding (PS1 → .NET → trojanized host)

Wrap an obfuscated PS1 script inside a .NET assembly that executes it via `System.Management.Automation`, then embed that assembly in a trojanized host.

```bash
penumbra payload.ps1 --embed --host NuGet.exe
# Internally: PS1 passes → .NET wrapper (PowerShell.Create().AddScript()) → encrypt → inject
```

**Why it matters**: Allows delivering PS1 payloads as trojanized .NET binaries. The PS1 never touches disk, never passes through `powershell.exe` (which is monitored by EDR), and the host binary looks legitimate.

**Implementation**:
- Detect cross-pipeline scenario: input is PS1 but `--embed`/`--host` targets .NET
- After PS1 passes, generate a minimal C# project that embeds the obfuscated PS1 as a string and calls `PowerShell.Create().AddScript(script).Invoke()`
- Compile to a .NET assembly, then feed into the normal embed/trojanize flow
- Requires `System.Management.Automation` NuGet package in the wrapper project

**Complexity**: Medium. The PS1-to-.NET wrapper is straightforward, the challenge is handling argument passing and output capture from the PowerShell runspace.

## Suggested priority

1. ~~Entropy reduction~~ — DONE (junk classes with low-entropy strings)
2. ~~Payload fragmentation~~ — DONE (8KB chunks across multiple classes)
3. ~~Heuristic-bypass naming~~ — DONE (plausible verb+noun identifiers)
4. ~~Trojanized assembly~~ — DONE (`--host` flag)
5. ~~Hide console~~ — DONE (WinExe subsystem)
6. Cross-pipeline embedding — next major feature
