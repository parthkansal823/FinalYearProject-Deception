"""Keep the machine awake for the duration of a long evaluation.

A multi-seed run takes hours, and if the laptop sleeps partway the open HTTP
connections between the traffic generator and the proxy are torn down. That
surfaces as `httpx.ReadTimeout` inside a draw, which looks exactly like a network
fault -- it cost one 100-seed run at draw 47 before `multiseed_eval` retried
draws, and a single sleep/resume later showed up as a 2.6-hour "draw".

This asserts the Windows execution-state flags that say "a task is running", the
same mechanism a video player or a backup tool uses. It changes no power settings
and needs no elevation: the request lives only as long as this process, so closing
it (or Ctrl-C) restores normal behaviour immediately.

    python -m tools.keep_awake                  # until Ctrl-C
    python -m tools.keep_awake --hours 8        # or a fixed window

On a non-Windows host it exits cleanly with a note rather than pretending to work.
"""
from __future__ import annotations

import argparse
import sys
import time

# SetThreadExecutionState flags (winbase.h)
ES_CONTINUOUS = 0x80000000        # the state stays until it is cleared
ES_SYSTEM_REQUIRED = 0x00000001   # do not sleep the system
ES_AWAYMODE_REQUIRED = 0x00000040  # keep running with the screen off


def main() -> None:
    ap = argparse.ArgumentParser(description="Stop the machine sleeping during a long run.")
    ap.add_argument("--hours", type=float, default=0.0,
                    help="release after this many hours (default: until interrupted)")
    ap.add_argument("--allow-screen-off", action="store_true", default=True,
                    help="let the display sleep; only the system is kept awake")
    args = ap.parse_args()

    if not sys.platform.startswith("win"):
        print("not Windows -- nothing to do. On Linux use systemd-inhibit, "
              "on macOS use caffeinate.")
        return

    import ctypes

    flags = ES_CONTINUOUS | ES_SYSTEM_REQUIRED
    if args.allow_screen_off:
        flags |= ES_AWAYMODE_REQUIRED

    if ctypes.windll.kernel32.SetThreadExecutionState(flags) == 0:
        print("!! SetThreadExecutionState failed; the machine may still sleep.")
        raise SystemExit(1)

    until = f"for {args.hours:g}h" if args.hours else "until interrupted"
    print(f"system sleep suppressed {until}. The display may still turn off; "
          f"the run keeps going.")
    print("Close this process (Ctrl-C) to restore normal power behaviour.")

    try:
        if args.hours:
            time.sleep(args.hours * 3600)
        else:
            while True:
                time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        # Drop the request; without this the state would persist for the process's
        # lifetime only, but clearing it explicitly is the documented contract.
        ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS)
        print("\nsleep suppression released.")


if __name__ == "__main__":
    main()
