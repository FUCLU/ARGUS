from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dotenv import load_dotenv

load_dotenv()

from argus.llm.client import APIError, FatalAPIError
from argus.stage3.runner import main


if __name__ == "__main__":
    try:
        main()
    except (APIError, FatalAPIError, FileNotFoundError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
