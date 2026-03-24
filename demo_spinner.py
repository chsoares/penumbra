"""Demo script — shows the per-pass spinner output with fake passes."""

import time

from penumbra.spinner import PassSpinner, write_done

passes = ["rename", "encrypt-strings", "flow", "strip-debug", "embed"]

for name in passes:
    spinner = PassSpinner(name)
    spinner.start()
    # Simulate work (2s per pass)
    time.sleep(2)
    spinner.stop(ok=True, verbose=True)

write_done()
