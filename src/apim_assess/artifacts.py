from __future__ import annotations

import hashlib
import os
import tempfile
from pathlib import Path

from apim_assess.models.snapshot import Model, Snapshot


def digest(snapshot: Snapshot) -> str:
    return hashlib.sha256(snapshot.model_dump_json().encode("utf-8")).hexdigest()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def write_model(path: Path, model: Model) -> None:
    write_text(path, model.model_dump_json(indent=2) + "\n")
