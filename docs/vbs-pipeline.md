# VBScript Pipeline

## What is VBScript?

VBScript (Visual Basic Scripting Edition) is a scripting language built into Windows via the Windows Script Host (WSH). While deprecated in newer Windows versions, it remains present on most enterprise systems and is commonly used in phishing scenarios and initial access.

VBScript has its own AMSI integration, but unlike PowerShell, it lacks the reflection capabilities needed for runtime AMSI patching. The evasion strategy is therefore focused on string obfuscation to avoid signature matches.

## Why does this matter?

VBScript payloads are useful for:

- Initial access via phishing (`.vbs` attachments or embedded in documents)
- Environments where PowerShell is heavily monitored but VBS is not
- Legacy Windows systems where VBS is the primary scripting option

## Passes

The VBS pipeline has two passes that run in order:

### 1. `encode` — XOR Encoding

Each character of the payload is XOR'd with a random single-byte key. The output is a VBS script that decodes itself at runtime using a `For` loop with `Chr(Asc(Mid(...)) Xor key)`.

Features:
- Random XOR key (1-255) per generation
- Randomized variable names
- Runtime decoding via `Execute` statement

### 2. `wrap` — WScript.Shell Wrapper

Adds a `WScript.Shell` object creation around the payload, providing process execution capability to the decoded script.

## Usage

```bash
# Auto-detected from .vbs extension
penumbra payload.vbs

# Explicit pipeline selection
penumbra script.txt --pipeline vbs -o payload.vbs
```

## How it Works

Given an input VBS script:

```vbs
MsgBox "Hello World"
```

The encode pass produces:

```vbs
v12345678 = 42
vabcdef01 = "<xor_encoded_string>"
v98765432 = ""
For v11111111 = 1 To Len(vabcdef01)
    v98765432 = v98765432 & Chr(Asc(Mid(vabcdef01, v11111111, 1)) Xor v12345678)
Next
Execute v98765432
```

The wrap pass then adds the `WScript.Shell` object creation around it.

## Mutual Exclusivity / Compatibility

- VBS pipeline is standalone — no cross-pipeline flags apply
- Auto-detected from `.vbs` and `.vbe` extensions
- No AMSI bypass pass (VBScript lacks runtime patching capability; obfuscation is the primary evasion)

## Note on VBS AMSI

VBScript's AMSI integration scans the script content before execution. Since VBScript doesn't support `Add-Type` or reflection, there's no runtime way to patch AMSI from within a VBS script. The XOR encoding pass is the primary defense — it transforms the script content so that no individual line contains a detectable signature.
