"""Target-inventory sources: read the list of containers to scan from a CSV
catalog, a JSONL feed or a plain text file of image references."""
from __future__ import annotations
from ..config import Config, ConfigError
from .base import Source
from .csv_source import CsvSource
from .jsonl_source import JsonlSource
from .txt_source import TxtSource

_SOURCES: dict[str, type[Source]] = {
    "csv": CsvSource, "jsonl": JsonlSource, "txt": TxtSource,
}


def get_source(cfg: Config) -> Source:
    """Build the target source for this run from ``config.source.type``."""
    kind = cfg.source.type
    try:
        return _SOURCES[kind](cfg)
    except KeyError:
        raise ConfigError(f"unknown source type '{kind}'; pick one of {sorted(_SOURCES)}")


__all__ = ["Source", "get_source"]
