#!/usr/bin/env python3
"""Measure baseline, stripped-only and protected releases."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from anti_rea.measurement import main

if __name__ == "__main__":
    raise SystemExit(main())
