"""Moon-phase spinner for long-running obfuscation passes."""

from __future__ import annotations

import itertools
import secrets
import sys
import threading

# Nerd Font moon phases: U+E3DD (full) → U+E3D4 (new) — waning cycle
_MOON_PHASES = [chr(c) for c in range(0xE3DD, 0xE3D3, -1)]

_VERBS = [
    "shrouding",
    "eclipsing",
    "obfuscating",
    "dimming",
    "cloaking",
    "veiling",
    "obscuring",
    "shadowing",
    "concealing",
    "wrapping",
]

_NOUNS = [
    "the payload",
    "signatures",
    "the bytecode",
    "symbol names",
    "detection logic",
    "static analysis",
    "the binary",
    "string literals",
    "control flow",
    "debug traces",
]

# ANSI colors (match cli.py palette)
_M = "\033[38;5;5m"    # magenta — moon
_T = "\033[38;5;240m"  # dark gray — text
_R = "\033[0m"         # reset


def _random_phrase() -> str:
    return f"{secrets.choice(_VERBS)} {secrets.choice(_NOUNS)}"


class MoonSpinner:
    """Animated moon-phase spinner that runs in a background thread."""

    def __init__(self, interval: float = 0.12) -> None:
        self._interval = interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._phrase = _random_phrase()
        self._phase_cycle = itertools.cycle(_MOON_PHASES)
        self._ticks = 0

    def _animate(self) -> None:
        while not self._stop_event.is_set():
            moon = next(self._phase_cycle)
            # Rotate phrase every full moon cycle
            if self._ticks > 0 and self._ticks % len(_MOON_PHASES) == 0:
                self._phrase = _random_phrase()
            line = f"\r  {_M}{moon} {_T}{self._phrase}...{_R}\033[K"
            sys.stderr.write(line)
            sys.stderr.flush()
            self._ticks += 1
            self._stop_event.wait(self._interval)

    def start(self) -> None:
        """Start the spinner animation."""
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the spinner and clear the line."""
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join()
        sys.stderr.write("\r\033[K")
        sys.stderr.flush()

    def __enter__(self) -> MoonSpinner:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()
