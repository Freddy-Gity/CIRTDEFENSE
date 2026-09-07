"""Scénarios de menaces **absentes** du catalogue CIRT.

Le catalogue couvre 22 types. Une plateforme nationale en rencontrera
d'autres, et c'est précisément ce cas qu'il faut pouvoir éprouver : que fait
le système devant ce qu'il ne connaît pas ?

Ces scénarios ne sont donc rattachés à aucune ligne du catalogue — c'est leur
raison d'être. Chacun porte un jeu d'indicateurs différent, pour montrer que
le confinement de repli ne déduit rien du type d'attaque mais tout de ce qui
est observé : selon qu'un compte, une adresse externe, un domaine ou un port
figure dans l'événement, la réponse change.

Ils restent inoffensifs au même titre que les autres : ils fabriquent la
charge utile qu'un collecteur émettrait, ils n'attaquent rien.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


def _maintenant() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(slots=True)
class ScenarioInconnu:
    """Une menace que le catalogue ne connaît pas."""

    code: str
    source: str
    title: str
    narrative: str
    """Ce que le scénario raconte, et ce qu'il permet d'observer."""
    indicateurs_attendus: tuple[str, ...]
    """Les indicateurs présents, qui détermineront la réponse de repli."""
    payload_builder: Any = field(repr=False, default=None)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "source": self.source,
            "title": self.title,
            "narrative": self.narrative,
            "indicators": list(self.indicateurs_attendus),
            "catalogued": False,
        }


def _arp() -> dict[str, Any]:
    return {
        "timestamp": _maintenant(),
        "rule": {
            "level": 12,
            "description": "ARP cache poisoning: duplicate MAC for gateway on VLAN 20",
            "groups": ["network", "spoofing"],
        },
        "agent": {"id": "srv-db-01", "name": "srv-db-01", "ip": "10.0.2.20"},
        "data": {"srcip": "203.0.113.44", "dstuser": ""},
    }


def _chaine_approvisionnement() -> dict[str, Any]:
    return {
        "timestamp": _maintenant(),
        "rule": {
            "level": 13,
            "description": "Post-install script from newly published dependency "
            "opened an outbound connection",
            "groups": ["supply_chain", "package_manager"],
        },
        "agent": {"id": "srv-app-01", "name": "srv-app-01", "ip": "10.0.2.30"},
        "data": {
            "srcip": "10.0.2.30",
            "dstip": "198.51.100.77",
            "dstuser": "svc-build",
            "dstport": 8443,
        },
    }


def _consentement_oauth() -> dict[str, Any]:
    return {
        "timestamp": _maintenant(),
        "rule": {
            "level": 11,
            "description": "Third-party application granted mailbox-wide "
            "delegated consent outside change window",
            "groups": ["identity", "oauth"],
        },
        "agent": {"id": "srv-mail-01", "name": "srv-mail-01", "ip": "10.0.2.50"},
        "data": {"dstuser": "a.mbarga", "srcip": "192.0.2.201"},
    }


def _protocole_industriel() -> dict[str, Any]:
    return {
        "timestamp": _maintenant(),
        "rule": {
            "level": 12,
            "description": "Unsolicited Modbus write command to building management controller",
            "groups": ["ics", "modbus"],
        },
        "agent": {"id": "fw-dmz-01", "name": "fw-dmz-01", "ip": "10.0.0.1"},
        "data": {"srcip": "198.51.100.14", "dstport": 502},
    }


def _dns_rebinding() -> dict[str, Any]:
    return {
        "timestamp": _maintenant(),
        "alert": {
            "signature": "Short-TTL record alternating between public and RFC1918 address",
            "category": "dns anomaly",
            "severity": 2,
        },
        "src_ip": "10.0.5.114",
        "dest_ip": "203.0.113.9",
        "dns": {"rrname": "collecte-interne.exemple-inconnu.cm"},
        "in_iface": "bureautique",
    }


INCONNUS: tuple[ScenarioInconnu, ...] = (
    ScenarioInconnu(
        code="Z1",
        source="wazuh",
        title="Empoisonnement de cache ARP sur le VLAN de production",
        narrative="Aucune ligne du catalogue ne couvre l'usurpation ARP. Seule "
        "l'adresse externe est exploitable : le repli bloque, et rien d'autre.",
        indicateurs_attendus=("adresse source externe", "hôte de criticité 5"),
        payload_builder=_arp,
    ),
    ScenarioInconnu(
        code="Z2",
        source="wazuh",
        title="Dépendance fraîchement publiée ouvrant une connexion sortante",
        narrative="Compromission de chaîne d'approvisionnement : le catalogue "
        "l'ignore. Quatre indicateurs sont présents, la réponse est plus large.",
        indicateurs_attendus=("destination externe", "compte de service", "port", "hôte"),
        payload_builder=_chaine_approvisionnement,
    ),
    ScenarioInconnu(
        code="Z3",
        source="wazuh",
        title="Consentement OAuth délégué hors fenêtre de changement",
        narrative="Abus d'identité applicative, absent du catalogue. Le compte "
        "impliqué ouvre des gestes durables qui attendront une confirmation.",
        indicateurs_attendus=("compte utilisateur", "adresse source externe", "hôte critique"),
        payload_builder=_consentement_oauth,
    ),
    ScenarioInconnu(
        code="Z4",
        source="wazuh",
        title="Écriture Modbus non sollicitée vers un automate de gestion",
        narrative="Protocole industriel hors périmètre du catalogue. Sans compte "
        "impliqué, le repli se limite au réseau et au port.",
        indicateurs_attendus=("adresse source externe", "port"),
        payload_builder=_protocole_industriel,
    ),
    ScenarioInconnu(
        code="Z5",
        source="suricata",
        title="Enregistrement DNS à TTL court alternant public et privé",
        narrative="Réattribution DNS : le catalogue ne la connaît pas. Le nom de "
        "domaine observé permet un blocage de résolution, réversible.",
        indicateurs_attendus=("domaine", "destination externe"),
        payload_builder=_dns_rebinding,
    ),
)

PAR_CODE: dict[str, ScenarioInconnu] = {s.code: s for s in INCONNUS}


def get_inconnu(code: str) -> ScenarioInconnu | None:
    return PAR_CODE.get(code.upper())


def lister_inconnus() -> list[dict[str, Any]]:
    return [s.to_dict() for s in INCONNUS]


def build_payload_inconnu(code: str) -> dict[str, Any]:
    scenario = get_inconnu(code)
    if scenario is None:
        raise KeyError(f"scénario inconnu '{code}' ; codes valides : {sorted(PAR_CODE)}")
    return scenario.payload_builder()
