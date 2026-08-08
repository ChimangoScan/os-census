"""Run-configuration model.

A run is described by a YAML file mapped onto the ``Config`` dataclass tree
(queue, source, scanners, workers, output, runtime, imports, cluster). Every
field has a built-in default, so a config need only override what differs.
Unknown keys are rejected (typo protection) and all relative paths resolve
against the repository ``root``."""
from __future__ import annotations
import os
from dataclasses import dataclass, field, fields
from pathlib import Path
from typing import Any

import yaml


def _merge(base: dict, over: dict) -> dict:
    out = dict(base)
    for k, v in (over or {}).items():
        out[k] = _merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _coerce(cls, d: dict):
    """Build a dataclass from a dict, ignoring unknown keys (forward/back compat)."""
    known = {f.name for f in fields(cls)}
    extra = set(d) - known
    if extra:
        raise ConfigError(f"{cls.__name__}: unknown keys {sorted(extra)}")
    return cls(**{k: v for k, v in d.items() if k in known})


class ConfigError(Exception):
    """Raised for any malformed run configuration: unknown top-level section, unknown key within a section, or a section that isn't a mapping."""
    pass


@dataclass
class QueueCfg:
    """Which job-queue backend a run uses: in-process `sqlite` (single host) or `http` (multi-host, pointed at `url`/`bind`)."""
    backend: str = "sqlite"
    sqlite_path: str = "work/queue.db"
    url: str = "http://127.0.0.1:8900"
    bind: str = "0.0.0.0:8900"
    token: str = ""


@dataclass
class SourceCfg:
    """Where the target inventory comes from and how to map its columns onto a `Target`."""
    type: str = "csv"
    path: str = "data/inventory.csv"
    image_column: str = "Image"
    ip_column: str = "IP"
    name_column: str = "Container"
    meta_columns: list[str] = field(default_factory=lambda: ["Category", "Type", "Port"])
    limit: int = 0


@dataclass
class ScannersCfg:
    """Which scanners to run: the registry file to load, an `only`/`skip` allow/deny list, and whether static and/or dynamic phases run at all."""
    registry: str = "config/scanners.yaml"
    only: list[str] = field(default_factory=list)
    skip: list[str] = field(default_factory=list)
    static: bool = True
    dynamic: bool = True


@dataclass
class WorkersCfg:
    """Worker-pool sizing and the timings that drive the worker-death recovery path (heartbeat interval, staleness threshold before `reset_stale()` reclaims a job, retry budget per job)."""
    count: int = 4
    scan_timeout: int = 1200
    job_attempts: int = 3
    heartbeat_seconds: int = 30
    stale_minutes: int = 15
    worker_id: str = ""


@dataclass
class OutputCfg:
    """Where results and caches are written, and whether a re-run may reuse a scanner's prior non-empty output (`skip_done`) instead of re-scanning."""
    dir: str = "out"
    keep_image_tarball: bool = False
    cache_dir: str = "cache"
    skip_done: bool = True              # on re-run, reuse a scanner's existing non-empty output
                                        # (scanner-granular resume; delete out/ or set false to force)


@dataclass
class RuntimeCfg:
    """Docker/container-runtime tuning: the scan network and container resource limits, which ports get probed/treated as HTTP for dynamic discovery, pull retry/backoff and account rotation, and image-size/disk-pressure guards."""
    network: str = "scannet"
    subnet: str = "172.28.0.0/16"
    startup_wait: int = 8
    health_timeout: int = 90
    probe_ports: list[int] = field(default_factory=lambda: [
        80, 443, 8080, 8443, 8000, 3000, 5000, 8888, 9000, 9090, 9200, 5601,
        8161, 15672, 3306, 5432, 27017, 6379, 11211, 9042, 5984, 2181, 9092,
        22, 21, 23, 25, 143, 389, 636])
    http_ports: list[int] = field(default_factory=lambda: [
        80, 443, 8080, 8443, 8000, 3000, 5000, 8888, 9000, 9090, 9200, 5601,
        8983, 5984])
    hardened: bool = True
    mem_limit: str = "1g"
    pids_limit: int = 512
    cpu_quota: int = 0
    scan_parallelism: int = 4               # scanners run concurrently per target (per worker)
    pull_retries: int = 4
    pull_backoff: int = 30
    max_image_mb: int = 12000
    prune_every: int = 25
    remove_image_after: bool = False        # `docker rmi` the target image once scanned (bounds disk)
    dockerhub_user: str = ""                 # `docker login` before pulling (raises the rate limit)
    dockerhub_token: str = ""
    dockerhub_accounts: str = ""             # JSON list of {username,password}; rotated on a pull rate-limit
    nvd_api_key: str = ""                    # passed to dependency-check's `prepare` (NVD throttles without one)


@dataclass
class ImportsCfg:
    """External data merged into the corpus outside the scan pipeline (currently just an OpenVAS export path)."""
    openvas: str = ""


@dataclass
class ClusterCfg:
    """Multi-host cluster deployment settings used by the cluster driver scripts (which hosts, how workers are distributed, how they're reached)."""
    hosts: list[str] = field(default_factory=lambda: ["host1", "host2"])
    remote_dir: str = "~/scanners"
    workers_per_host: int = 4
    use_uv: bool = True
    reverse_tunnel: bool = True


@dataclass
class Config:
    """The full run configuration, built from a YAML file merged over per-section defaults. Load with `Config.load`; access resolved paths via `out_dir`/`cache_dir`/`queue_db`/`path()`."""
    queue: QueueCfg = field(default_factory=QueueCfg)
    source: SourceCfg = field(default_factory=SourceCfg)
    scanners: ScannersCfg = field(default_factory=ScannersCfg)
    workers: WorkersCfg = field(default_factory=WorkersCfg)
    output: OutputCfg = field(default_factory=OutputCfg)
    runtime: RuntimeCfg = field(default_factory=RuntimeCfg)
    imports: ImportsCfg = field(default_factory=ImportsCfg)
    cluster: ClusterCfg = field(default_factory=ClusterCfg)
    root: Path = field(default_factory=lambda: Path.cwd())

    # absolute-path helpers (all config paths are relative to `root`)
    def path(self, p: str) -> Path:
        """Resolve a possibly-relative config path against `root`; an absolute or `~`-prefixed path is returned as-is."""
        q = Path(p).expanduser()
        return q if q.is_absolute() else (self.root / q)

    @property
    def out_dir(self) -> Path:
        """Resolved output directory (`output.dir` relative to `root`)."""
        return self.path(self.output.dir)
    @property
    def cache_dir(self) -> Path:
        """Resolved cache directory (`output.cache_dir` relative to `root`)."""
        return self.path(self.output.cache_dir)
    @property
    def queue_db(self) -> Path:
        """Resolved SQLite queue database path (`queue.sqlite_path` relative to `root`)."""
        return self.path(self.queue.sqlite_path)

    _SECTIONS = {
        "queue": QueueCfg, "source": SourceCfg, "scanners": ScannersCfg,
        "workers": WorkersCfg, "output": OutputCfg, "runtime": RuntimeCfg,
        "imports": ImportsCfg, "cluster": ClusterCfg,
    }

    @classmethod
    def load(cls, path: str | os.PathLike | None) -> "Config":
        """Build a Config from a YAML file, merged over each section's dataclass defaults; `path=None` yields the all-defaults Config rooted at the current directory.

        `root` is inferred as the YAML file's parent directory, or its
        grandparent when the file lives in a `config/` subdirectory (so
        relative paths inside the config resolve against the repo root, not
        the config directory). Raises `ConfigError` on a missing file, an
        unknown top-level section, an unknown key within a section, or a
        section that isn't a mapping.
        """
        data: dict[str, Any] = {}
        root = Path.cwd()
        if path:
            p = Path(path).expanduser().resolve()
            if not p.is_file():
                raise ConfigError(f"config not found: {p}")
            data = yaml.safe_load(p.read_text()) or {}
            root = p.parent.parent if p.parent.name == "config" else p.parent
        cfg = cls(root=root)
        for name, sub in cls._SECTIONS.items():
            if name in data:
                if not isinstance(data[name], dict):
                    raise ConfigError(f"section '{name}' must be a mapping")
                setattr(cfg, name, _coerce(sub, _merge(_section_dict(getattr(cfg, name)), data[name])))
        unknown = set(data) - set(cls._SECTIONS)
        if unknown:
            raise ConfigError(f"unknown top-level sections {sorted(unknown)}")
        return cfg


def _section_dict(obj) -> dict:
    """Flatten a config-section dataclass instance back to a plain dict, so it can be merged with the corresponding YAML overrides."""
    return {f.name: getattr(obj, f.name) for f in fields(obj)}
