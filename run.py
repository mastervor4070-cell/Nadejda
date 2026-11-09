#!/usr/bin/env python3
"""Entry point used by the systemd unit and the /usr/local/bin wrapper."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nadejda.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
