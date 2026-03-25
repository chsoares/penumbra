"""Tests for PS1 UAC bypass pass."""

from __future__ import annotations

import pytest

from penumbra.ps.uac import UacBypassPass
from penumbra.types import PassConfig, PipelineType

_PAYLOAD = b"Write-Host 'hello from elevated context'"


class TestFodhelper:
    def test_generates_valid_ps1(self) -> None:
        cfg = PassConfig(pipeline=PipelineType.PS1, extra={"uac_method": "fodhelper"})
        result = UacBypassPass().apply(_PAYLOAD, cfg)
        text = result.decode("utf-8")
        assert "fodhelper" in text
        assert "ms-settings" in text
        assert "DelegateExecute" in text
        assert "Set-Content" in text
        assert "Remove-Item" in text

    def test_payload_embedded(self) -> None:
        cfg = PassConfig(pipeline=PipelineType.PS1, extra={"uac_method": "fodhelper"})
        result = UacBypassPass().apply(_PAYLOAD, cfg)
        text = result.decode("utf-8")
        assert "Write-Host 'hello from elevated context'" in text


class TestDiskCleanup:
    def test_generates_valid_ps1(self) -> None:
        cfg = PassConfig(pipeline=PipelineType.PS1, extra={"uac_method": "diskcleanup"})
        result = UacBypassPass().apply(_PAYLOAD, cfg)
        text = result.decode("utf-8")
        assert "SilentCleanup" in text
        assert "HKCU:\\Environment" in text
        assert "windir" in text
        assert "Remove-ItemProperty" in text


class TestComputerDefaults:
    def test_generates_valid_ps1(self) -> None:
        cfg = PassConfig(
            pipeline=PipelineType.PS1, extra={"uac_method": "computerdefaults"}
        )
        result = UacBypassPass().apply(_PAYLOAD, cfg)
        text = result.decode("utf-8")
        assert "computerdefaults" in text
        assert "ms-settings" in text
        assert "DelegateExecute" in text


class TestDefaultAndErrors:
    def test_default_is_fodhelper(self) -> None:
        cfg = PassConfig(pipeline=PipelineType.PS1)
        result = UacBypassPass().apply(_PAYLOAD, cfg)
        text = result.decode("utf-8")
        assert "fodhelper" in text

    def test_unknown_method_raises(self) -> None:
        cfg = PassConfig(pipeline=PipelineType.PS1, extra={"uac_method": "invalid"})
        with pytest.raises(ValueError, match="Unknown UAC method"):
            UacBypassPass().apply(_PAYLOAD, cfg)

    def test_is_opt_in(self) -> None:
        assert UacBypassPass.opt_in is True

    def test_pass_name(self) -> None:
        assert UacBypassPass().name == "uac"
