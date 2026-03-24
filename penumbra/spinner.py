"""Moon-phase spinner for long-running obfuscation passes."""

from __future__ import annotations

import itertools
import secrets
import sys
import threading
import time

# Full 28-frame lunar cycle using Nerd Font weather icons:
#   full → waning gibbous → third quarter → waning crescent →
#   new  → waxing crescent → first quarter → waxing gibbous → (repeat)
_MOON_PHASES = [
    "\ue3d5",                                                  # full
    "\ue3d6", "\ue3d7", "\ue3d8", "\ue3d9", "\ue3da", "\ue3db",  # waning gibbous 1-6
    "\ue3dc",                                                  # third quarter
    "\ue3dd", "\ue3de", "\ue3df", "\ue3e0", "\ue3e1", "\ue3e2",  # waning crescent 1-6
    "\ue3e3",                                                  # new
    "\ue3c8", "\ue3c9", "\ue3ca", "\ue3cb", "\ue3cc", "\ue3cd",  # waxing crescent 1-6
    "\ue3ce",                                                  # first quarter
    "\ue3cf", "\ue3d0", "\ue3d1", "\ue3d2", "\ue3d3", "\ue3d4",  # waxing gibbous 1-6
]

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
_M = "\033[38;5;5m"    # magenta — moon/icons
_T = "\033[38;5;240m"  # dark gray — text
_D = "\033[38;5;245m"  # light gray — dim details
_R = "\033[0m"         # reset

# Nerd Font icons
_CHECK = "\uf00c"          # pass completion checkmark
_DONE_ICON = "\U000f1829"  # final "payload cloaked" icon


def _random_phrase() -> str:
    return f"{secrets.choice(_VERBS)} {secrets.choice(_NOUNS)}"


class PassSpinner:
    """Animated spinner for a single pass execution."""

    def __init__(self, pass_name: str, interval: float = 0.12) -> None:
        self._pass_name = pass_name
        self._interval = interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._phrase = _random_phrase()
        self._phase_cycle = itertools.cycle(_MOON_PHASES)
        self._ticks = 0
        self._start_time = 0.0

    def _animate(self) -> None:
        while not self._stop_event.is_set():
            moon = next(self._phase_cycle)
            if self._ticks > 0 and self._ticks % len(_MOON_PHASES) == 0:
                self._phrase = _random_phrase()
            line = (
                f"\r{_M}{moon} {_T}{self._pass_name}"
                f" {_D}— {self._phrase}...{_R}\033[K"
            )
            sys.stderr.write(line)
            sys.stderr.flush()
            self._ticks += 1
            self._stop_event.wait(self._interval)

    def start(self) -> None:
        self._start_time = time.monotonic()
        self._thread = threading.Thread(target=self._animate, daemon=True)
        self._thread.start()

    def stop(self, ok: bool = True, verbose: bool = False) -> None:
        self._stop_event.set()
        if self._thread is not None:
            self._thread.join()
        elapsed = time.monotonic() - self._start_time
        if ok:
            detail = ""
            if verbose:
                detail = f" {_D}({elapsed:.1f}s){_R}"
            sys.stderr.write(
                f"\r{_M}{_CHECK} {_T}{self._pass_name}{detail}{_R}\033[K\n"
            )
        else:
            sys.stderr.write("\r\033[K")
        sys.stderr.flush()


def write_done(output_path: str = "") -> None:
    """Write the final 'payload cloaked.' message with output path."""
    path_str = f" {_D}→ {output_path}{_R}" if output_path else ""
    sys.stderr.write(f"\n{_M}{_DONE_ICON} {_T}payload cloaked{path_str}{_R}\n")
    sys.stderr.flush()


def write_fail() -> None:
    """Clear spinner line on failure."""
    sys.stderr.write("\r\033[K")
    sys.stderr.flush()
