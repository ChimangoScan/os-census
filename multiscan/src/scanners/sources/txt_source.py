"""Plain-text target source: one image reference per line; blank lines and
``#`` comments are ignored."""
from __future__ import annotations
from collections.abc import Iterator

from ..models import Target
from .base import Source


class TxtSource(Source):
    """One image reference per line; `#` starts a comment."""

    def _iter(self) -> Iterator[Target]:
        for line in self.path.read_text().splitlines():
            line = line.split("#", 1)[0].strip()
            if line:
                yield Target(image=line)
