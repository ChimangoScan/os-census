"""Shared figure styling: one fixed colour per scanner, used in every figure.

The colour map is global and unique: each catalogued scanner gets its own
colour, so a scanner looks identical in every plot and any two scanners are
always distinguishable.
"""

AXIS_LABEL = {
    "pkg-vuln": "package vuln (SCA)", "sbom-component": "SBOM",
    "secret": "secrets", "other": "SAST", "image-config": "image config",
    "malware": "malware", "web-vuln": "web (DAST)", "network-vuln": "network",
}

# Full catalogue per axis (stable; includes tools that may report 0 findings).
AXIS_SCANNERS = {
    "sbom-component": ["syft", "cdxgen"],
    "pkg-vuln": ["trivy", "grype", "osv", "clair", "dependency-check",
                 "govulncheck", "pip-audit"],
    "image-config": ["dockle", "checkov", "kube-linter"],
    "secret": ["trufflehog", "gitleaks", "detect-secrets", "whispers"],
    "other": ["semgrep", "bandit", "gosec", "brakeman", "njsscan", "find-sec-bugs"],
    "malware": ["clamav", "yara", "yarahunter"],
    "web-vuln": ["nuclei", "nikto", "zap", "wpscan", "droopescan", "jaeles",
                 "arachni", "sqlmap", "httpx"],
    "network-vuln": ["nmap", "openvas", "testssl"],
}

# 40 distinct hues (matplotlib tab10 + tab20 light + tab20b); one per scanner.
_PALETTE = [
    "#1f77b4", "#ff7f0e", "#2ca02c", "#d62728", "#9467bd", "#8c564b",
    "#e377c2", "#7f7f7f", "#bcbd22", "#17becf", "#aec7e8", "#ffbb78",
    "#98df8a", "#ff9896", "#c5b0d5", "#c49c94", "#f7b6d2", "#9edae5",
    "#dbdb8d", "#393b79", "#5254a3", "#6b6ecf", "#9c9ede", "#637939",
    "#8ca252", "#b5cf6b", "#cedb9c", "#8c6d31", "#bd9e39", "#e7ba52",
    "#e7cb94", "#843c39", "#ad494a", "#d6616b", "#e7969c", "#7b4173",
    "#a55194", "#ce6dbd", "#de9ed6", "#aa4499",
]
_FALLBACK = "#9aa0a6"


def _build() -> dict:
    seen = []
    for scanners in AXIS_SCANNERS.values():
        for s in scanners:
            if s not in seen:
                seen.append(s)
    return {s: _PALETTE[i % len(_PALETTE)] for i, s in enumerate(seen)}


SCANNER_COLOR = _build()


def color(scanner: str) -> str:
    return SCANNER_COLOR.get(scanner, _FALLBACK)
