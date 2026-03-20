"""Demo script — runs the moon spinner for 10 seconds so you can see the animation."""

import time

from penumbra.spinner import MoonSpinner

with MoonSpinner():
    time.sleep(10)
