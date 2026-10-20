from __future__ import annotations

from dotenv import load_dotenv

load_dotenv()

from sinkkb.triage.client import APIError, FatalAPIError
from sinkkb.triage.runner import main


if __name__ == "__main__":
    try:
        main()
    except (APIError, FatalAPIError, FileNotFoundError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc
