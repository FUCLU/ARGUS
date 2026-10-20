from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Iterable


def read_jsonl(path: str | Path) -> list[dict]:
    out=[]
    with Path(path).open(encoding="utf-8") as f:
        for line in f:
            if line.strip(): out.append(json.loads(line))
    return out


def append_jsonl(path: str | Path, obj: dict) -> None:
    p=Path(path); p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj, ensure_ascii=False)+"\n")


def timestamped_run_output(stage: str, root: str | Path = "outputs/runs") -> Path:
    if stage not in {"stage2", "stage3"}:
        raise ValueError("stage must be stage2 or stage3")
    timestamp = datetime.now().astimezone().strftime("%Y-%m-%d_%H-%M-%S-%f")
    run_dir = Path(root) / timestamp
    run_dir.mkdir(parents=True, exist_ok=False)
    return run_dir / f"{stage}.jsonl"
