"""Scanner adapters: one module per supported scanner.

Each adapter exposes a ``parse(out_dir, target) -> list[Finding]`` function that
converts that scanner's native output into normalized findings; see
:mod:`scanners.adapters.base` for the contract and the shared helpers, and
``config/scanners.yaml`` for how each scanner is invoked."""
from .base import ParseFn, RenderedSpec, ScannerSpec  # noqa: F401
from .registry import load_registry, select  # noqa: F401
