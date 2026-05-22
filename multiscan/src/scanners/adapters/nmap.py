from __future__ import annotations
import xml.etree.ElementTree as ET
from pathlib import Path

from ..models import Category, Severity, Target
from .base import cves_in, f


def parse(out: Path, t: Target) -> list[Finding]:
    p = out / f"{t.name}.nmap.xml"
    try:
        tree = ET.parse(p)
    except (OSError, ET.ParseError):
        return []
    res = []
    root = tree.getroot()
    for host in root.findall("host"):
        addr_el = host.find("address[@addrtype='ipv4']")
        ip = addr_el.get("addr", t.ip or t.name) if addr_el is not None else (t.ip or t.name)
        for port_el in host.findall("ports/port"):
            proto = port_el.get("protocol", "tcp")
            portid = port_el.get("portid", "")
            state_el = port_el.find("state")
            if state_el is not None and state_el.get("state") != "open":
                continue
            svc_el = port_el.find("service")
            svc_name = svc_el.get("name", "") if svc_el is not None else ""
            svc_product = svc_el.get("product", "") if svc_el is not None else ""
            svc_version = svc_el.get("version", "") if svc_el is not None else ""
            ep = f"{ip}:{portid}"
            for script_el in port_el.findall("script"):
                sid = script_el.get("id", "")
                output = script_el.get("output", "")
                sev = Severity.INFO
                if any(k in output.lower() for k in ("vulnerable", "exploitable", "critical")):
                    sev = Severity.HIGH
                elif any(k in output.lower() for k in ("warning", "weak", "deprecated")):
                    sev = Severity.MEDIUM
                res.append(f("nmap", t, category=Category.NETWORK_VULN,
                             severity=sev, id=f"nmap:{sid}",
                             title=f"NSE {sid} on {proto}/{portid}",
                             description=output[:1000],
                             location=f"{proto}/{portid}",
                             endpoint=ep,
                             cves=cves_in(output),
                             raw={"script": sid, "output": output, "port": portid,
                                  "proto": proto, "service": svc_name, "ip": ip}))
            # Always surface the open port itself as an info finding
            res.append(f("nmap", t, category=Category.NETWORK_VULN,
                         severity=Severity.INFO,
                         id=f"open-port:{proto}/{portid}",
                         title=f"Open port {proto}/{portid} ({svc_name})",
                         description=f"{svc_product} {svc_version}".strip(),
                         location=f"{proto}/{portid}",
                         endpoint=ep,
                         version=svc_version,
                         raw={"port": portid, "proto": proto, "service": svc_name,
                              "product": svc_product, "version": svc_version, "ip": ip}))
    return res
