"""Core data model shared across the engine.

Defines the enums (``Severity``, ``Category``, ``Mode``) and the dataclasses
that flow through the pipeline: ``Target`` (a container to scan), ``Finding``
(one normalized result — the cross-scanner comparison unit), ``ScanInvocation``
(per-run metrics) and ``TargetReport`` (everything learned about one target).
Each has ``to_json`` / ``from_json`` so the model round-trips through the queue
and the on-disk corpus."""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any

from .util import slugify, normalize_image


class Severity(str, Enum):
    """The one severity scale every adapter normalizes its scanner's own vocabulary into."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, v: Any) -> "Severity":
        """Map a scanner's free-text severity/level word (any case, several synonyms) onto this scale. Unrecognized or missing input maps to UNKNOWN, never raises."""
        if v is None:
            return cls.UNKNOWN
        s = str(v).strip().lower()
        return {
            "critical": cls.CRITICAL, "crit": cls.CRITICAL,
            "high": cls.HIGH, "important": cls.HIGH, "error": cls.HIGH,
            "medium": cls.MEDIUM, "moderate": cls.MEDIUM, "warning": cls.MEDIUM, "warn": cls.MEDIUM,
            "low": cls.LOW, "minor": cls.LOW,
            "info": cls.INFO, "informational": cls.INFO, "negligible": cls.INFO,
            "none": cls.INFO, "log": cls.INFO, "note": cls.INFO, "unknown": cls.UNKNOWN,
        }.get(s, cls.UNKNOWN)

    @classmethod
    def from_cvss(cls, score: float | None) -> "Severity":
        """Bucket a numeric CVSS base score (0-10) into a Severity using the standard CVSS v3 rating thresholds (>=9 CRITICAL, >=7 HIGH, >=4 MEDIUM, >0 LOW, 0 or None -> INFO/UNKNOWN)."""
        if score is None:
            return cls.UNKNOWN
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFO


class Category(str, Enum):
    """The finding taxonomy every adapter's output is classified into, independent of which scanner produced it."""
    PKG_VULN = "pkg-vuln"          # CVE in an installed package / dependency
    SECRET = "secret"              # embedded credential / key / token
    IMAGE_CONFIG = "image-config"  # hardening / CIS / Dockerfile smell
    WEB_VULN = "web-vuln"          # finding from a DAST scanner over HTTP
    NETWORK_VULN = "network-vuln"  # finding from a network scanner (e.g. OpenVAS NVT)
    MALWARE = "malware"            # AV / YARA signature hit
    SBOM_COMPONENT = "sbom-component"  # inventory entry, not a finding
    OTHER = "other"


class Mode(str, Enum):
    """Whether a scanner inspects the image at rest (STATIC) or a running container (DYNAMIC)."""
    STATIC = "static"
    DYNAMIC = "dynamic"


@dataclass(frozen=True)
class Target:
    """One container image to scan, as read from the inventory source. Immutable; identity is `image` (normalized on construction), `name` is derived from it if not given explicitly."""
    image: str
    name: str = ""                 # slug; derived from image if empty
    ip: str | None = None          # known container IP (catalog) or assigned at runtime
    weight: float = 0.0            # priority; higher scanned first
    meta: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Normalize the image reference and derive `name` from it if not given explicitly (bypassing `frozen=True` via `object.__setattr__`, the standard pattern for post-init mutation on a frozen dataclass)."""
        object.__setattr__(self, "image", normalize_image(self.image))
        if not self.name:
            object.__setattr__(self, "name", slugify(self.image))

    def to_json(self) -> dict:
        """Serialize to the plain dict stored in queue jobs and the on-disk catalog."""
        return {"image": self.image, "name": self.name, "ip": self.ip,
                "weight": self.weight, "meta": self.meta}

    @classmethod
    def from_json(cls, d: dict) -> "Target":
        """Reconstruct a Target from its `to_json` dict; `d["image"]` is required, everything else defaults."""
        return cls(image=d["image"], name=d.get("name", ""), ip=d.get("ip"),
                   weight=float(d.get("weight", 0.0)), meta=dict(d.get("meta") or {}))


@dataclass
class Finding:
    """One normalized finding. `target_ip`/`endpoint` make vuln↔container correlation explicit."""
    scanner: str
    category: Category
    severity: Severity = Severity.UNKNOWN
    id: str = ""                   # CVE / rule id / NVT OID — the cross-scanner join key
    title: str = ""
    description: str = ""
    cvss: float | None = None
    package: str = ""
    version: str = ""
    fixed_version: str = ""
    ecosystem: str = ""
    location: str = ""             # file path / layer / URL path
    cves: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    # provenance
    target_image: str = ""
    target_name: str = ""
    target_ip: str | None = None
    endpoint: str = ""             # host:port for dynamic findings
    raw: dict[str, Any] = field(default_factory=dict)   # the original record, untouched

    def merge_key(self) -> tuple:
        """Identity used to deduplicate/correlate findings across scanners and re-runs: same category, id-or-title, package, and endpoint-or-location (all case-folded) are treated as the same underlying finding."""
        return (self.category.value, (self.id or self.title).lower(),
                self.package.lower(), (self.endpoint or self.location).lower())

    def to_json(self) -> dict:
        """Serialize to the compact dict persisted in report.json/the corpus, dropping the bulky `raw` field (kept only in the scanner's native output file)."""
        d = asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        # The original record is large — a vuln-heavy image has thousands of
        # findings, each with a multi-KB raw entry. It's preserved verbatim in
        # the scanner's native output file under out/<slug>/<scanner>/; the
        # normalized view (report.json, the queue DB, the corpus) carries the
        # actionable fields only, so the central store stays GB- not TB-scale.
        d.pop("raw", None)
        return d

    @classmethod
    def from_json(cls, d: dict) -> "Finding":
        """Reconstruct a Finding from its `to_json` dict; `raw` will be empty since it is never serialized."""
        return cls(
            scanner=d.get("scanner", ""), category=Category(d.get("category", "other")),
            severity=Severity(d.get("severity", "unknown")), id=d.get("id", ""),
            title=d.get("title", ""), description=d.get("description", ""), cvss=d.get("cvss"),
            package=d.get("package", ""), version=d.get("version", ""),
            fixed_version=d.get("fixed_version", ""), ecosystem=d.get("ecosystem", ""),
            location=d.get("location", ""), cves=list(d.get("cves") or []),
            references=list(d.get("references") or []), target_image=d.get("target_image", ""),
            target_name=d.get("target_name", ""), target_ip=d.get("target_ip"),
            endpoint=d.get("endpoint", ""), raw=d.get("raw") or {})


@dataclass
class ScanInvocation:
    """Metrics for a single scanner run against a single target."""
    scanner: str
    target_name: str
    target_image: str
    target_ip: str | None = None
    mode: str = ""
    image_ref: str = ""            # scanner docker image actually used
    started_at: str = ""
    wall_seconds: float = 0.0
    exit_code: int | None = None
    status: str = "ok"             # ok | nonzero-ok | error | timeout | skipped
    error: str = ""
    peak_cpu_pct: float = 0.0
    peak_mem_mb: float = 0.0
    stdout_bytes: int = 0
    stderr_bytes: int = 0
    output_bytes: int = 0
    findings: int = 0
    findings_by_severity: dict[str, int] = field(default_factory=dict)
    artifacts: list[str] = field(default_factory=list)

    def to_json(self) -> dict:
        """Serialize the full invocation record, including its native output-file byte counts and exit status."""
        return asdict(self)


@dataclass
class TargetReport:
    """Everything we learned about one target. Persisted as <slug>/report.json."""
    target: Target
    started_at: str = ""
    finished_at: str = ""
    scanned_image_digest: str = ""   # registry digest (`repo@sha256:...`) actually pulled — moving tags like :latest drift
    container_ip: str | None = None
    open_ports: list[int] = field(default_factory=list)
    http_endpoints: list[str] = field(default_factory=list)
    invocations: list[ScanInvocation] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    skipped_reason: str = ""

    def to_json(self) -> dict:
        """Serialize the whole per-target report as written to `<slug>/report.json`."""
        return {
            "target": self.target.to_json(),
            "started_at": self.started_at, "finished_at": self.finished_at,
            "scanned_image_digest": self.scanned_image_digest,
            "container_ip": self.container_ip, "open_ports": self.open_ports,
            "http_endpoints": self.http_endpoints,
            "invocations": [i.to_json() for i in self.invocations],
            "findings": [f.to_json() for f in self.findings],
            "skipped_reason": self.skipped_reason,
        }
