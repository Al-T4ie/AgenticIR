"""MITRE ATT&CK mapping for an incident's findings.

Specialists cite technique ids (`T1059.001`). On their own those are opaque:
knowing an incident touched T1071.001 tells a responder nothing that the
finding text did not, and it certainly does not tell them how far along the
kill chain the intrusion got. Grouping the cited techniques by tactic does —
credential access next to lateral movement next to exfiltration is a shape you
can read in a second.

The lookup is a curated table rather than the full ATT&CK corpus. The corpus is
megabytes and would need fetching, and this runs behind a strict CSP with no
outbound calls on a page render. What is here covers what a SOC actually sees;
anything unrecognised is reported as unmapped rather than guessed at, because a
confidently wrong tactic is worse than an honest gap.

Sub-techniques fall back to their parent when not listed individually, which is
correct: T1059.009 is still Command and Scripting Interpreter, still execution.
"""

from __future__ import annotations

import re
from typing import Any

# Kill-chain order. This is the axis the whole view is built on — a responder
# reads left to right and sees how far the intrusion progressed.
TACTICS: list[tuple[str, str]] = [
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Dev"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Priv Esc"),
    ("defense-evasion", "Defense Evasion"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command & Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
]

_TACTIC_LABELS = dict(TACTICS)

# id -> (name, tactics). Only entries whose tactic assignment is certain.
TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    # ── Reconnaissance ──
    # The first two lanes had no entries at all, so anything an analyst cited
    # from the pre-compromise half of the chain rendered as a bare `T####`.
    # Domain-age and registrar checks land here constantly during triage.
    "T1595": ("Active Scanning", ("reconnaissance",)),
    "T1592": ("Gather Victim Host Information", ("reconnaissance",)),
    "T1589": ("Gather Victim Identity Information", ("reconnaissance",)),
    "T1590": ("Gather Victim Network Information", ("reconnaissance",)),
    "T1591": ("Gather Victim Org Information", ("reconnaissance",)),
    "T1598": ("Phishing for Information", ("reconnaissance",)),
    "T1597": ("Search Closed Sources", ("reconnaissance",)),
    "T1596": ("Search Open Technical Databases", ("reconnaissance",)),
    "T1593": ("Search Open Websites/Domains", ("reconnaissance",)),
    "T1594": ("Search Victim-Owned Websites", ("reconnaissance",)),
    # ── Resource development ──
    "T1650": ("Acquire Access", ("resource-development",)),
    "T1583": ("Acquire Infrastructure", ("resource-development",)),
    "T1583.001": ("Domains", ("resource-development",)),
    "T1586": ("Compromise Accounts", ("resource-development",)),
    "T1584": ("Compromise Infrastructure", ("resource-development",)),
    "T1587": ("Develop Capabilities", ("resource-development",)),
    "T1585": ("Establish Accounts", ("resource-development",)),
    "T1588": ("Obtain Capabilities", ("resource-development",)),
    "T1608": ("Stage Capabilities", ("resource-development",)),
    # ── Initial access ──
    "T1189": ("Drive-by Compromise", ("initial-access",)),
    "T1190": ("Exploit Public-Facing Application", ("initial-access",)),
    "T1133": ("External Remote Services", ("initial-access", "persistence")),
    "T1200": ("Hardware Additions", ("initial-access",)),
    "T1566": ("Phishing", ("initial-access",)),
    "T1566.001": ("Spearphishing Attachment", ("initial-access",)),
    "T1566.002": ("Spearphishing Link", ("initial-access",)),
    "T1566.003": ("Spearphishing via Service", ("initial-access",)),
    "T1091": ("Replication Through Removable Media", ("initial-access", "lateral-movement")),
    "T1195": ("Supply Chain Compromise", ("initial-access",)),
    # ── Execution ──
    "T1059": ("Command and Scripting Interpreter", ("execution",)),
    "T1059.001": ("PowerShell", ("execution",)),
    "T1059.003": ("Windows Command Shell", ("execution",)),
    "T1059.004": ("Unix Shell", ("execution",)),
    "T1059.005": ("Visual Basic", ("execution",)),
    "T1059.006": ("Python", ("execution",)),
    "T1059.007": ("JavaScript", ("execution",)),
    "T1609": ("Container Administration Command", ("execution",)),
    "T1610": ("Deploy Container", ("execution", "defense-evasion")),
    "T1106": ("Native API", ("execution",)),
    "T1129": ("Shared Modules", ("execution",)),
    "T1072": ("Software Deployment Tools", ("execution", "lateral-movement")),
    "T1569": ("System Services", ("execution",)),
    "T1569.002": ("Service Execution", ("execution",)),
    "T1204": ("User Execution", ("execution",)),
    "T1204.001": ("Malicious Link", ("execution",)),
    "T1204.002": ("Malicious File", ("execution",)),
    "T1047": ("Windows Management Instrumentation", ("execution",)),
    "T1203": ("Exploitation for Client Execution", ("execution",)),
    "T1053": ("Scheduled Task/Job", ("execution", "persistence", "privilege-escalation")),
    "T1053.005": ("Scheduled Task", ("execution", "persistence", "privilege-escalation")),
    # ── Persistence ──
    "T1098": ("Account Manipulation", ("persistence", "privilege-escalation")),
    "T1547": (
        "Boot or Logon Autostart Execution",
        ("persistence", "privilege-escalation"),
    ),
    "T1547.001": (
        "Registry Run Keys / Startup Folder",
        ("persistence", "privilege-escalation"),
    ),
    "T1176": ("Browser Extensions", ("persistence",)),
    "T1136": ("Create Account", ("persistence",)),
    "T1543": ("Create or Modify System Process", ("persistence", "privilege-escalation")),
    "T1543.003": ("Windows Service", ("persistence", "privilege-escalation")),
    "T1546": ("Event Triggered Execution", ("persistence", "privilege-escalation")),
    "T1137": ("Office Application Startup", ("persistence",)),
    "T1505": ("Server Software Component", ("persistence",)),
    "T1505.003": ("Web Shell", ("persistence",)),
    # ── Privilege escalation ──
    "T1548": ("Abuse Elevation Control Mechanism", ("privilege-escalation", "defense-evasion")),
    "T1611": ("Escape to Host", ("privilege-escalation",)),
    "T1068": ("Exploitation for Privilege Escalation", ("privilege-escalation",)),
    "T1574": (
        "Hijack Execution Flow",
        ("persistence", "privilege-escalation", "defense-evasion"),
    ),
    # ── Defense evasion ──
    "T1197": ("BITS Jobs", ("defense-evasion", "persistence")),
    "T1140": ("Deobfuscate/Decode Files or Information", ("defense-evasion",)),
    "T1562": ("Impair Defenses", ("defense-evasion",)),
    "T1562.001": ("Disable or Modify Tools", ("defense-evasion",)),
    "T1070": ("Indicator Removal", ("defense-evasion",)),
    "T1070.001": ("Clear Windows Event Logs", ("defense-evasion",)),
    "T1070.004": ("File Deletion", ("defense-evasion",)),
    "T1036": ("Masquerading", ("defense-evasion",)),
    "T1112": ("Modify Registry", ("defense-evasion",)),
    "T1027": ("Obfuscated Files or Information", ("defense-evasion",)),
    "T1027.010": ("Command Obfuscation", ("defense-evasion",)),
    "T1055": ("Process Injection", ("defense-evasion", "privilege-escalation")),
    "T1218": ("System Binary Proxy Execution", ("defense-evasion",)),
    "T1218.005": ("Mshta", ("defense-evasion",)),
    "T1218.011": ("Rundll32", ("defense-evasion",)),
    "T1078": (
        "Valid Accounts",
        ("initial-access", "persistence", "privilege-escalation", "defense-evasion"),
    ),
    "T1078.004": (
        "Cloud Accounts",
        ("initial-access", "persistence", "privilege-escalation", "defense-evasion"),
    ),
    "T1497": ("Virtualization/Sandbox Evasion", ("defense-evasion", "discovery")),
    # ── Credential access ──
    "T1110": ("Brute Force", ("credential-access",)),
    "T1555": ("Credentials from Password Stores", ("credential-access",)),
    "T1056": ("Input Capture", ("credential-access", "collection")),
    "T1556": (
        "Modify Authentication Process",
        ("credential-access", "defense-evasion", "persistence"),
    ),
    "T1621": ("Multi-Factor Authentication Request Generation", ("credential-access",)),
    "T1003": ("OS Credential Dumping", ("credential-access",)),
    "T1003.001": ("LSASS Memory", ("credential-access",)),
    "T1528": ("Steal Application Access Token", ("credential-access",)),
    "T1558": ("Steal or Forge Kerberos Tickets", ("credential-access",)),
    "T1552": ("Unsecured Credentials", ("credential-access",)),
    "T1550": (
        "Use Alternate Authentication Material",
        ("defense-evasion", "lateral-movement"),
    ),
    "T1550.001": ("Application Access Token", ("defense-evasion", "lateral-movement")),
    # ── Discovery ──
    "T1087": ("Account Discovery", ("discovery",)),
    "T1010": ("Application Window Discovery", ("discovery",)),
    "T1217": ("Browser Information Discovery", ("discovery",)),
    "T1526": ("Cloud Service Discovery", ("discovery",)),
    "T1482": ("Domain Trust Discovery", ("discovery",)),
    "T1083": ("File and Directory Discovery", ("discovery",)),
    "T1135": ("Network Share Discovery", ("discovery",)),
    "T1201": ("Password Policy Discovery", ("discovery",)),
    "T1120": ("Peripheral Device Discovery", ("discovery",)),
    "T1069": ("Permission Groups Discovery", ("discovery",)),
    "T1057": ("Process Discovery", ("discovery",)),
    "T1012": ("Query Registry", ("discovery",)),
    "T1018": ("Remote System Discovery", ("discovery",)),
    "T1518": ("Software Discovery", ("discovery",)),
    "T1518.001": ("Security Software Discovery", ("discovery",)),
    "T1082": ("System Information Discovery", ("discovery",)),
    "T1614": ("System Location Discovery", ("discovery",)),
    "T1016": ("System Network Configuration Discovery", ("discovery",)),
    "T1049": ("System Network Connections Discovery", ("discovery",)),
    "T1033": ("System Owner/User Discovery", ("discovery",)),
    "T1007": ("System Service Discovery", ("discovery",)),
    "T1124": ("System Time Discovery", ("discovery",)),
    # ── Lateral movement ──
    "T1570": ("Lateral Tool Transfer", ("lateral-movement",)),
    "T1021": ("Remote Services", ("lateral-movement",)),
    "T1021.001": ("Remote Desktop Protocol", ("lateral-movement",)),
    "T1021.002": ("SMB / Windows Admin Shares", ("lateral-movement",)),
    "T1021.006": ("Windows Remote Management", ("lateral-movement",)),
    "T1080": ("Taint Shared Content", ("lateral-movement",)),
    # ── Collection ──
    "T1560": ("Archive Collected Data", ("collection",)),
    "T1530": ("Data from Cloud Storage", ("collection",)),
    "T1213": ("Data from Information Repositories", ("collection",)),
    "T1005": ("Data from Local System", ("collection",)),
    "T1039": ("Data from Network Shared Drive", ("collection",)),
    "T1074": ("Data Staged", ("collection",)),
    "T1114": ("Email Collection", ("collection",)),
    "T1113": ("Screen Capture", ("collection",)),
    # ── Command and control ──
    "T1071": ("Application Layer Protocol", ("command-and-control",)),
    "T1071.001": ("Web Protocols", ("command-and-control",)),
    "T1071.004": ("DNS", ("command-and-control",)),
    "T1132": ("Data Encoding", ("command-and-control",)),
    "T1568": ("Dynamic Resolution", ("command-and-control",)),
    "T1573": ("Encrypted Channel", ("command-and-control",)),
    "T1008": ("Fallback Channels", ("command-and-control",)),
    "T1105": ("Ingress Tool Transfer", ("command-and-control",)),
    "T1104": ("Multi-Stage Channels", ("command-and-control",)),
    "T1095": ("Non-Application Layer Protocol", ("command-and-control",)),
    "T1571": ("Non-Standard Port", ("command-and-control",)),
    "T1572": ("Protocol Tunneling", ("command-and-control",)),
    "T1090": ("Proxy", ("command-and-control",)),
    "T1219": ("Remote Access Software", ("command-and-control",)),
    "T1102": ("Web Service", ("command-and-control",)),
    # ── Exfiltration ──
    "T1020": ("Automated Exfiltration", ("exfiltration",)),
    "T1030": ("Data Transfer Size Limits", ("exfiltration",)),
    "T1048": ("Exfiltration Over Alternative Protocol", ("exfiltration",)),
    "T1041": ("Exfiltration Over C2 Channel", ("exfiltration",)),
    "T1567": ("Exfiltration Over Web Service", ("exfiltration",)),
    "T1029": ("Scheduled Transfer", ("exfiltration",)),
    "T1537": ("Transfer Data to Cloud Account", ("exfiltration",)),
    # ── Impact ──
    "T1485": ("Data Destruction", ("impact",)),
    "T1486": ("Data Encrypted for Impact", ("impact",)),
    "T1499": ("Endpoint Denial of Service", ("impact",)),
    "T1490": ("Inhibit System Recovery", ("impact",)),
    "T1498": ("Network Denial of Service", ("impact",)),
    "T1489": ("Service Stop", ("impact",)),
}

_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "informational": 0}


def normalise(raw: str) -> str:
    """Pull a technique id out of whatever the model wrote.

    Specialists cite these inconsistently — "T1059.001", "t1059.001",
    "T1059.001 (PowerShell)". A citation that cannot be read as an id is
    reported unmapped rather than silently dropped.
    """
    text = str(raw or "").strip().upper()
    match = re.search(r"T\d{4}(?:\.\d{3})?", text)
    return match.group(0) if match else text


def describe(technique_id: str) -> tuple[str, tuple[str, ...], bool]:
    """(name, tactics, exact). Falls back to the parent for sub-techniques."""
    if technique_id in TECHNIQUES:
        name, tactics = TECHNIQUES[technique_id]
        return name, tactics, True
    if "." in technique_id:
        parent = technique_id.split(".", 1)[0]
        if parent in TECHNIQUES:
            # The parent's name, unqualified. Callers flag the inexactness with
            # `exact`; folding it into the string wraps every such label onto a
            # second line, and there are a lot of them.
            name, tactics = TECHNIQUES[parent]
            return name, tactics, False
    return "", (), False


def summarise(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Group the techniques cited by findings into the kill chain.

    Each technique carries the findings that cited it, so the view can be dug
    into rather than just counted.
    """
    by_technique: dict[str, dict[str, Any]] = {}
    unmapped: dict[str, list[dict[str, Any]]] = {}

    for finding in findings or []:
        for raw in finding.get("mitre_techniques", []) or []:
            tid = normalise(raw)
            if not _ID.match(tid):
                unmapped.setdefault(str(raw)[:60], []).append(finding)
                continue
            name, tactics, exact = describe(tid)
            if not tactics:
                unmapped.setdefault(tid, []).append(finding)
                continue
            entry = by_technique.setdefault(
                tid,
                {"id": tid, "name": name, "tactics": tactics, "exact": exact, "findings": []},
            )
            if finding not in entry["findings"]:
                entry["findings"].append(finding)

    lanes = []
    for key, label in TACTICS:
        hits = [t for t in by_technique.values() if key in t["tactics"]]
        hits.sort(key=lambda t: (-_worst(t["findings"]), t["id"]))
        lanes.append(
            {
                "key": key,
                "label": label,
                "techniques": hits,
                "count": len(hits),
                "severity": _severity_label(_worst_of_all(hits)),
            }
        )

    observed = [lane for lane in lanes if lane["count"]]
    return {
        "lanes": lanes,
        "observed": observed,
        "techniques": sorted(by_technique.values(), key=lambda t: t["id"]),
        "technique_count": len(by_technique),
        "tactic_count": len(observed),
        "unmapped": [{"label": k, "findings": v} for k, v in sorted(unmapped.items())],
        "empty": not by_technique and not unmapped,
    }


def _worst(findings: list[dict[str, Any]]) -> int:
    return max(
        (_SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 0) for f in findings),
        default=0,
    )


def _worst_of_all(techniques: list[dict[str, Any]]) -> int:
    return max((_worst(t["findings"]) for t in techniques), default=-1)


def _severity_label(rank: int) -> str:
    for label, value in _SEVERITY_RANK.items():
        if value == rank:
            return label
    return ""


def tactic_label(key: str) -> str:
    return _TACTIC_LABELS.get(key, key)
