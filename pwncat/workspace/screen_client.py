"""Run a workspace inside Screen and leave errors visible before it closes."""

from __future__ import annotations

import sys
import traceback


def main(argv=None):
    from .cli import main as workspace_main

    try:
        result = workspace_main(argv)
    except SystemExit as exc:
        result = exc.code if isinstance(exc.code, int) else 1
    except KeyboardInterrupt:
        result = 130
    except Exception:
        traceback.print_exc()
        result = 1
    if result:
        try:
            input("\nWorkspace exited with an error. Press Enter to close this window.")
        except (EOFError, KeyboardInterrupt):
            pass
    return result


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
