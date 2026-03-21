"""Script wrapper pass — wraps in heredoc (bash) or compile+exec (Python)."""

from __future__ import annotations

import secrets

from penumbra.types import PassConfig


def _detect_language(data: bytes) -> str:
    """Guess script language from shebang or content heuristics."""
    first_line = data.split(b"\n", 1)[0].decode("utf-8", errors="replace")
    if "python" in first_line:
        return "python"
    if "bash" in first_line or "sh" in first_line:
        return "bash"
    text = data.decode("utf-8", errors="replace")
    if "def " in text or "import " in text or "print(" in text:
        return "python"
    return "bash"


class ScriptWrapPass:
    """Wrap a script in a self-extracting heredoc (bash) or compile+exec (Python)."""

    @property
    def name(self) -> str:
        return "wrap"

    def apply(self, data: bytes, config: PassConfig) -> bytes:  # noqa: ARG002
        lang = _detect_language(data)
        source = data.decode("utf-8")

        if lang == "python":
            # exec(compile("""...""", '<string>', 'exec'))
            # Use a random variable name for the source
            var = "_" + secrets.token_hex(4)
            # Triple-quote the source, escaping any existing triple-quotes
            escaped = source.replace("\\", "\\\\").replace('"""', '\\"\\"\\"')
            stub = (
                f'{var} = """{escaped}"""\n'
                f"exec(compile({var}, '<string>', 'exec'))\n"
            )
        else:
            # Self-extracting heredoc for bash
            marker = "_PENUMBRA_" + secrets.token_hex(4).upper()
            stub = (
                "#!/bin/bash\n"
                f"eval \"$(cat <<'{marker}'\n"
                f"{source}"
                f"\n{marker}\n"
                ")\"\n"
            )

        return stub.encode("utf-8")
