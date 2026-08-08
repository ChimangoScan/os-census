"""The adapter contract and the shared helpers every adapter uses.

A *scanner adapter* is a module under ``scanners.adapters`` exposing a single
``parse(out_dir: Path, target: Target) -> list[Finding]`` function that turns a
scanner's native output (already on disk under ``out_dir``) into normalized
:class:`~scanners.models.Finding` records. ``ScannerSpec`` is the registry
entry that says which Docker image to run, how to invoke it (argv templates),
and which output files the adapter should read. This module also provides the
small parsing helpers (``read_json``, ``read_jsonl``, ``cves_in``, ``f``) the
adapters share."""
from __future__ import annotations
import importlib, json, re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from ..models import Category, Finding, Mode, Severity, Target

# A parser turns a scanner's output directory into normalized findings.
ParseFn = Callable[[Path, Target], list[Finding]]

_PLACEHOLDER = re.compile(r"\{(\w+)\}")


@dataclass(frozen=True)
class ScannerSpec:
    """Static declaration of how to run one scanner and where to find its output.

    Loaded from ``config/scanners.yaml`` (see :func:`scanners.adapters.registry.load_registry`).
    Immutable: a run never mutates a spec, it only renders one via :meth:`render`.
    """

    name: str
    image: str
    mode: Mode
    argv: list[str] = field(default_factory=list)
    entrypoint: str | None = None
    user: str | None = None
    workdir: str | None = None
    outputs: list[str] = field(default_factory=list)       # filename templates under {out}
    capture_stdout: str | None = None                      # filename template for stdout
    extra_invocations: list[dict] = field(default_factory=list)
    needs: tuple[str, ...] = ()                            # capabilities the target must expose
    needs_tarball: bool = False                            # mount the `docker save` tar (at {tarball})
    needs_rootfs: bool = False                             # mount the flattened image filesystem (at {rootfs})
    needs_cache: str | None = None                         # persistent cache subdir; mounted at `cache_mount`
    cache_mount: str = "/cache"
    env: dict[str, str] = field(default_factory=dict)      # extra env vars passed into the scanner container
    ok_exit_codes: tuple[int, ...] = (0,)
    out_as_workdir: bool = False                           # mount {out} as the workdir, not /out
    timeout: int | None = None
    pull: bool = True
    enabled: bool = True
    parser: str = ""                                       # adapter module name (defaults to `name`)
    prepare: list[str] = field(default_factory=list)       # one-time docker argv to warm a cache (DBs, feeds)
    prepare_host: list[str] = field(default_factory=list)  # one-time host shell commands ({cache} expanded)

    def render(self, ctx: dict[str, Any]) -> "RenderedSpec":
        """Substitute ``{placeholder}`` tokens in argv/outputs with values from ``ctx``.

        ``ctx`` typically carries per-run paths (``out``, ``tarball``, ``rootfs``,
        ``cache_mount``, ...). Placeholders with no matching key in ``ctx`` are left
        untouched (see :func:`_fmt`), so a missing key fails later rather than here.
        """
        return RenderedSpec(
            spec=self,
            argv=[_fmt(a, ctx) for a in self.argv],
            extra=[[_fmt(a, ctx) for a in inv["argv"]] for inv in self.extra_invocations],
            outputs=[_fmt(o, ctx) for o in self.outputs],
            capture_stdout=_fmt(self.capture_stdout, ctx) if self.capture_stdout else None,
        )

    def load_parser(self) -> ParseFn:
        """Import this scanner's adapter module and return its ``parse`` function.

        The module name defaults to ``self.name`` unless ``self.parser`` overrides
        it (used when several scanner specs share one adapter implementation).
        Raises ``TypeError`` if the module has no callable ``parse``.
        """
        mod = importlib.import_module(f"scanners.adapters.{self.parser or self.name}")
        fn = getattr(mod, "parse", None)
        if not callable(fn):
            raise TypeError(f"adapter '{self.parser or self.name}' has no parse()")
        return fn


@dataclass
class RenderedSpec:
    """A :class:`ScannerSpec` with its ``{placeholder}`` tokens already substituted for one run."""

    spec: ScannerSpec
    argv: list[str]
    extra: list[list[str]]
    outputs: list[str]
    capture_stdout: str | None


def _fmt(s: str, ctx: dict[str, Any]) -> str:
    """Replace each ``{key}`` in ``s`` with ``ctx[key]``; unknown keys are left as-is."""
    return _PLACEHOLDER.sub(lambda m: str(ctx.get(m.group(1), m.group(0))), s)


# ── helpers shared by adapter parsers ───────────────────────────────────────

def read_json(p: Path) -> Any:
    """Parse ``p`` as JSON, returning ``None`` if the file is missing or malformed.

    Adapters call this on scanner output that may legitimately not exist (e.g. the
    scanner found nothing and wrote no file) or be truncated by a crashed scanner;
    ``None`` lets the caller treat both as "no findings" instead of raising.
    """
    try:
        return json.loads(p.read_text())
    except (OSError, json.JSONDecodeError):
        return None


def read_jsonl(p: Path):
    """Yield one parsed JSON object per non-blank line of ``p``.

    Missing files yield nothing. Individual malformed lines are skipped rather
    than aborting the whole scan, since some scanners emit partial/corrupt lines
    on timeout.
    """
    try:
        for line in p.read_text().splitlines():
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    except OSError:
        return


def endpoint_of(url_or_host: str) -> str:
    """Extract the host[:port] portion from a URL, or return the input unchanged if it has no scheme."""
    m = re.match(r"^\w+://([^/]+)", url_or_host or "")
    return m.group(1) if m else (url_or_host or "")


def cves_in(s: Any) -> list[str]:
    """Return every CVE-YYYY-NNNN... identifier found in ``str(s)``, case-insensitively."""
    return re.findall(r"CVE-\d{4}-\d{4,7}", str(s or ""), re.I)


def f(scanner: str, target: Target, **kw) -> Finding:
    """Construct a Finding pre-filled with target provenance (incl. IP)."""
    cat = kw.pop("category", Category.OTHER)
    sev = kw.pop("severity", Severity.UNKNOWN)
    return Finding(scanner=scanner, category=cat, severity=sev,
                   target_image=target.image, target_name=target.name, target_ip=target.ip, **kw)
