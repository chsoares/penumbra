"""Subprocess wrapper for the dotnet-worker IL obfuscation tool."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

from penumbra.types import PassConfig

_WORKER_PROJECT = Path(__file__).resolve().parent / "worker"


def _invoke_worker(data: bytes, pass_name: str, config: PassConfig) -> bytes:
    """Write data to a temp file, run dotnet-worker, return the output bytes."""
    if not shutil.which("dotnet"):
        raise RuntimeError("dotnet SDK not found. Install .NET 8+ SDK.")

    tmp_in = tempfile.NamedTemporaryFile(suffix=".dll", delete=False)
    tmp_out = tempfile.NamedTemporaryFile(suffix=".dll", delete=False)
    tmp_in_path = Path(tmp_in.name)
    tmp_out_path = Path(tmp_out.name)
    tmp_in.close()
    tmp_out.close()

    try:
        tmp_in_path.write_bytes(data)
        cmd: list[str] = [
            "dotnet", "run", "--project", str(_WORKER_PROJECT),
            "--", "--input", str(tmp_in_path),
            "--output", str(tmp_out_path),
            "--passes", pass_name,
        ]
        if config.safe_rename and pass_name == "rename":
            cmd.append("--safe-rename")

        result = subprocess.run(cmd, capture_output=True)

        if result.returncode != 0:
            stderr_text = result.stderr.decode("utf-8", errors="replace")
            raise RuntimeError(
                f"dotnet-worker failed (exit {result.returncode}): {stderr_text}"
            )

        return tmp_out_path.read_bytes()
    finally:
        tmp_in_path.unlink(missing_ok=True)
        tmp_out_path.unlink(missing_ok=True)


class DotnetRenamePass:
    """Rename types, methods, fields, and properties to random identifiers."""

    @property
    def name(self) -> str:
        return "rename"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        return _invoke_worker(data, "rename", config)


class DotnetEncryptStringsPass:
    """Encrypt string literals with XOR and inject a decryptor helper."""

    @property
    def name(self) -> str:
        return "encrypt-strings"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        return _invoke_worker(data, "encrypt-strings", config)


class DotnetFlowPass:
    """Insert NOP padding and opaque predicates to obscure control flow."""

    @property
    def name(self) -> str:
        return "flow"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        return _invoke_worker(data, "flow", config)


class DotnetDInvokePass:
    """Mutate PInvoke imports to DInvoke runtime resolution."""

    @property
    def name(self) -> str:
        return "dinvoke"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        return _invoke_worker(data, "dinvoke", config)


class DotnetStripDebugPass:
    """Remove debug attributes, PDB state, and identifying metadata from the assembly."""

    @property
    def name(self) -> str:
        return "strip-debug"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        return _invoke_worker(data, "strip-debug", config)


class DotnetScrubGuidPass:
    """Regenerate assembly GUID and MVID to break signature-based fingerprinting."""

    @property
    def name(self) -> str:
        return "scrub-guid"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        return _invoke_worker(data, "scrub-guid", config)
