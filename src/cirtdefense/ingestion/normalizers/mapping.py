"""Tables de correspondance partagees par les normaliseurs.

Regrouper ces tables evite que deux sources classent differemment la meme
menace, ce qui casserait la correlation des incidents.
"""

from __future__ import annotations

from ...domain.enums import Severity

CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "bruteforce": (
        "brute force",
        "bruteforce",
        "authentication failure",
        "failed password",
        "multiple failed",
        "password spray",
    ),
    "malware": ("malware", "trojan", "ransomware", "virus", "backdoor", "cryptolocker"),
    "exfiltration": ("exfiltration", "data transfer", "large upload", "dns tunnel"),
    "lateral_movement": (
        "lateral movement",
        "psexec",
        "smb admin",
        "pass the hash",
        "remote service creation",
    ),
    "privilege_escalation": ("privilege escalation", "sudo", "uac bypass", "token manipulation"),
    "c2": ("command and control", "c2", "beacon", "callback"),
    "web_attack": ("sql injection", "sqli", "xss", "path traversal", "web shell"),
    "scan": ("port scan", "nmap", "reconnaissance", "sweep"),
    "dos": ("denial of service", "ddos", "syn flood"),
    "policy_violation": ("policy violation", "unauthorized software"),
}

SEVERITY_BY_LEVEL: dict[int, Severity] = {
    0: Severity.INFO,
    1: Severity.INFO,
    2: Severity.INFO,
    3: Severity.LOW,
    4: Severity.LOW,
    5: Severity.MEDIUM,
    6: Severity.MEDIUM,
    7: Severity.MEDIUM,
    8: Severity.HIGH,
    9: Severity.HIGH,
    10: Severity.HIGH,
    11: Severity.HIGH,
    12: Severity.CRITICAL,
    13: Severity.CRITICAL,
    14: Severity.CRITICAL,
    15: Severity.CRITICAL,
}

SEVERITY_ALIASES: dict[str, Severity] = {
    "informational": Severity.INFO,
    "info": Severity.INFO,
    "notice": Severity.INFO,
    "low": Severity.LOW,
    "minor": Severity.LOW,
    "warning": Severity.LOW,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "average": Severity.MEDIUM,
    "high": Severity.HIGH,
    "major": Severity.HIGH,
    "error": Severity.HIGH,
    "critical": Severity.CRITICAL,
    "severe": Severity.CRITICAL,
    "emergency": Severity.CRITICAL,
    "alert": Severity.CRITICAL,
}


def classify_category(*texts: str) -> str:
    """Deduit la famille de menace a partir des libelles de la source.

    La correspondance la plus longue l'emporte, et non la premiere trouvee :
    « command and control » doit primer sur « trojan » dans un libelle qui
    contient les deux, sans quoi le classement dependrait de l'ordre de
    declaration du dictionnaire. A egalite de longueur, l'ordre alphabetique
    tranche pour que la fonction reste deterministe.

    Le repli est `unknown` et non une categorie plausible : une categorie
    inventee orienterait le choix du playbook sur une base non fondee.
    """
    haystack = " ".join(t.lower() for t in texts if t)
    best: tuple[int, str] | None = None
    for category, keywords in sorted(CATEGORY_KEYWORDS.items()):
        for keyword in keywords:
            if keyword in haystack and (best is None or len(keyword) > best[0]):
                best = (len(keyword), category)
    return best[1] if best else "unknown"


def severity_from_level(
    level: int | float | str | None, default: Severity = Severity.MEDIUM
) -> Severity:
    if level is None:
        return default
    if isinstance(level, str):
        alias = SEVERITY_ALIASES.get(level.strip().lower())
        if alias:
            return alias
        try:
            level = float(level)
        except ValueError:
            return default
    return SEVERITY_BY_LEVEL.get(int(level), default)
