"""Adapter for find-sec-bugs (SpotBugs plugin for Java security bugs).

Unlike most adapters here, find-sec-bugs' native report is XML (SpotBugs'
format), not JSON, so this adapter parses ``find-sec-bugs.xml`` with
``xml.etree.ElementTree`` instead of ``read_json``. Every bug is filed under
``Category.OTHER`` since find-sec-bugs' bug categories don't map onto our
finding categories."""
from __future__ import annotations
import xml.etree.ElementTree as ET
from pathlib import Path

from ..models import Category, Finding, Severity, Target
from .base import f

# SpotBugs priority: 1=high, 2=medium/normal, 3=low, 4/5=informational
_PRIORITY = {"1": Severity.HIGH, "2": Severity.MEDIUM, "3": Severity.LOW}


def _sev(bug: ET.Element) -> Severity:
    """Map a SpotBugs ``priority`` attribute (1-5) to our severity scale."""
    return _PRIORITY.get(bug.get("priority", ""), Severity.UNKNOWN)


def _location(bug: ET.Element) -> str:
    """Best-effort ``class:line[-line]`` (or bare class) location for one BugInstance."""
    src = bug.find(".//SourceLine")
    if src is not None:
        cls = src.get("classname", "")
        start = src.get("start", "")
        end = src.get("end", "")
        if cls:
            return f"{cls.replace('.', '/')}:{start}" + (f"-{end}" if end and end != start else "")
    cls_el = bug.find("Class")
    if cls_el is not None:
        return cls_el.get("classname", "")
    return ""


def parse(out: Path, t: Target) -> list[Finding]:
    """Turn ``find-sec-bugs.xml`` under ``out`` into findings for target ``t``. Returns ``[]`` if the file is missing or not well-formed XML."""
    xml_file = out / "find-sec-bugs.xml"
    try:
        tree = ET.parse(xml_file)
    except (ET.ParseError, OSError):
        return []
    root = tree.getroot()
    res = []
    for bug in root.findall("BugInstance"):
        bug_type = bug.get("type", "")
        priority = bug.get("priority", "")
        rank = bug.get("rank", "")
        category = bug.get("category", "")
        msg_el = bug.find("LongMessage") or bug.find("ShortMessage")
        msg = (msg_el.text or "") if msg_el is not None else bug_type
        loc = _location(bug)
        class_el = bug.find("Class")
        cls_name = class_el.get("classname", "") if class_el is not None else ""
        res.append(f("find-sec-bugs", t,
                     category=Category.OTHER,
                     severity=_sev(bug),
                     id=bug_type,
                     title=msg[:200] or bug_type,
                     description=msg[:1000],
                     location=loc,
                     raw={"type": bug_type, "priority": priority, "rank": rank,
                          "category": category, "class": cls_name, "message": msg}))
    return res
