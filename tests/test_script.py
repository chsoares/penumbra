"""Tests for the script pipeline (Python/Bash encode + wrap)."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest

from penumbra.script.encode import ScriptEncodePass
from penumbra.script.wrap import ScriptWrapPass
from penumbra.types import Pass, PassConfig, PipelineType

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def hello_py_bytes() -> bytes:
    return (FIXTURES / "hello.py").read_bytes()


@pytest.fixture()
def hello_sh_bytes() -> bytes:
    return (FIXTURES / "hello.sh").read_bytes()


# ── Encode pass ─────────────────────────────────────────────────────────


def test_encode_pass_name() -> None:
    assert ScriptEncodePass().name == "encode"


def test_encode_python(hello_py_bytes: bytes) -> None:
    config = PassConfig(pipeline=PipelineType.SCRIPT)
    result = ScriptEncodePass().apply(hello_py_bytes, config)
    text = result.decode("utf-8")
    assert "base64" in text
    assert "exec(" in text
    # Extract and verify Base64 is reversible
    b64 = text.split("'")[1]
    assert base64.b64decode(b64) == hello_py_bytes


def test_encode_bash(hello_sh_bytes: bytes) -> None:
    config = PassConfig(pipeline=PipelineType.SCRIPT)
    result = ScriptEncodePass().apply(hello_sh_bytes, config)
    text = result.decode("utf-8")
    assert "base64 -d" in text
    assert text.startswith("#!/bin/bash")
    # Extract and verify Base64 is reversible
    b64 = text.split("'")[1]
    assert base64.b64decode(b64) == hello_sh_bytes


def test_encode_satisfies_protocol() -> None:
    assert isinstance(ScriptEncodePass(), Pass)


# ── Wrap pass ───────────────────────────────────────────────────────────


def test_wrap_pass_name() -> None:
    assert ScriptWrapPass().name == "wrap"


def test_wrap_python(hello_py_bytes: bytes) -> None:
    config = PassConfig(pipeline=PipelineType.SCRIPT)
    result = ScriptWrapPass().apply(hello_py_bytes, config)
    text = result.decode("utf-8")
    assert "exec(compile(" in text
    assert "Hello from Penumbra!" in text


def test_wrap_bash(hello_sh_bytes: bytes) -> None:
    config = PassConfig(pipeline=PipelineType.SCRIPT)
    result = ScriptWrapPass().apply(hello_sh_bytes, config)
    text = result.decode("utf-8")
    assert text.startswith("#!/bin/bash")
    assert "eval" in text
    assert "_PENUMBRA_" in text
    assert "Hello from Penumbra!" in text


def test_wrap_satisfies_protocol() -> None:
    assert isinstance(ScriptWrapPass(), Pass)


# ── Pipeline integration ────────────────────────────────────────────────


def test_full_script_pipeline_python(hello_py_bytes: bytes) -> None:
    """wrap → encode chain on Python."""
    config = PassConfig(pipeline=PipelineType.SCRIPT)
    result = ScriptWrapPass().apply(hello_py_bytes, config)
    result = ScriptEncodePass().apply(result, config)
    text = result.decode("utf-8")
    # Final output is a base64-encoded exec wrapper
    assert "exec(" in text
    assert "base64" in text


def test_full_script_pipeline_bash(hello_sh_bytes: bytes) -> None:
    """wrap → encode chain on Bash."""
    config = PassConfig(pipeline=PipelineType.SCRIPT)
    result = ScriptWrapPass().apply(hello_sh_bytes, config)
    result = ScriptEncodePass().apply(result, config)
    text = result.decode("utf-8")
    assert "base64 -d" in text
