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

### 3. Trojanized assembly (`--host` flag)

Instead of generating a loader from scratch, inject the loading code into an existing legitimate .NET assembly provided by the user.

```bash
penumbra implant.exe --passes rename,encrypt-strings,embed --host /path/to/legit-tool.exe
```

**Why it matters**: The loader inherits the legitimate app's structure, imports, strings, resources, and metadata — making it indistinguishable from a real application. AV sees a known-good tool with some extra code, not a naked loader stub.

**Implementation**:
- Load the host assembly with dnlib
- Inject the encrypted payload as an embedded resource
- Add a static constructor (`.cctor`) or hook an existing method to run the decryption + `Assembly.Load` code
- Preserve all original functionality of the host (it still works as the original tool)
- Accept host path via `PassConfig.extra["host"]`, exposed as `--host` CLI flag

**Complexity**: Medium-high. The main challenge is injecting code without breaking the host's existing functionality, especially if it has its own static constructors or initialization logic.

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

## Suggested priority

1. Entropy reduction — quick win, directly addresses `Static AI` / `ml.score` detections
2. Payload fragmentation — quick win, complements entropy reduction
3. Heuristic-bypass naming — quick win
4. Trojanized assembly — highest impact but most complex
5. Hide console — trivial
