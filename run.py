"""Convenience launcher so beginners can run:  python run.py --log data/auth.log"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from detection_engine.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
