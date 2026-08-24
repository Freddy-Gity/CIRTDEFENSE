"""Interface en ligne de commande : exploitation, recette et demonstration."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .config import get_settings
from .logging_setup import configure_logging
from .orchestration.policy_compiler import PolicyCompiler
from .platform import build_platform


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="cirtd",
        description="CIRTDEFENSE — orchestration autonome de la reponse aux incidents",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Afficher la posture d'autonomie et l'etat du systeme")

    serve = sub.add_parser("serve", help="Demarrer l'API")
    serve.add_argument("--host", default=None)
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--reload", action="store_true")

    ingest = sub.add_parser("ingest", help="Ingerer un evenement et executer la reponse")
    ingest.add_argument("source", help="wazuh, suricata, syslog, generic_json")
    ingest.add_argument("file", help="Fichier JSON (ou '-' pour l'entree standard)")

    loop = sub.add_parser("control-loop", help="Executer un passage de la boucle EF-25")
    loop.add_argument("--json", action="store_true")

    compile_cmd = sub.add_parser(
        "compile-policy", help="Compiler une politique en langage naturel (EF-15)"
    )
    compile_cmd.add_argument("file", help="Fichier texte contenant la politique")
    compile_cmd.add_argument("--activate", action="store_true")

    catalog = sub.add_parser("catalog", help="Afficher le catalogue de reversibilite")
    catalog.add_argument("--autonomous-only", action="store_true")

    audit = sub.add_parser("audit", help="Consulter et verifier le journal d'audit")
    audit.add_argument("--incident", default=None)
    audit.add_argument("--verify", action="store_true")
    audit.add_argument("--limit", type=int, default=30)

    breaker = sub.add_parser("breaker", help="Coupe-circuit global (EF-26)")
    breaker.add_argument("action", choices=["status", "trip", "reset"])
    breaker.add_argument("--reason", default="operation manuelle en ligne de commande")

    args = parser.parse_args(argv)
    configure_logging()

    if args.command == "serve":
        return _serve(args)

    platform = build_platform()
    try:
        return _dispatch(args, platform)
    finally:
        platform.close()


def _dispatch(args: argparse.Namespace, platform: Any) -> int:
    match args.command:
        case "status":
            _print(platform.status())
        case "ingest":
            payload = _read_json(args.file)
            result = platform.ingest_and_respond(args.source, payload)
            if result is None:
                print("Evenement non traite : duplique, ou mis en file (mode degrade).")
                return 0
            _print(result.to_dict())
        case "control-loop":
            _print(platform.engine.run_control_loop().to_dict())
        case "compile-policy":
            report = PolicyCompiler().compile(Path(args.file).read_text(encoding="utf-8"))
            _print(report.to_dict())
            if report.unparsed_sentences:
                print(
                    f"\nATTENTION : {len(report.unparsed_sentences)} consigne(s) non "
                    "compilee(s), sans aucun effet sur le moteur.",
                    file=sys.stderr,
                )
            if args.activate:
                platform.policies.save(report.policy)
                platform.engine.set_policy(report.policy)
                print(f"\nPolitique activee (empreinte {report.policy.checksum()}).")
            return 1 if report.unparsed_sentences else 0
        case "catalog":
            entries = (
                platform.catalog.autonomous_subset()
                if args.autonomous_only
                else platform.catalog.all()
            )
            _print([e.to_dict() for e in entries])
        case "audit":
            if args.verify:
                verification = platform.ledger.verify_chain()
                _print(verification.to_dict())
                return 0 if verification.valid else 2
            entries = (
                platform.ledger.incident_timeline(args.incident)
                if args.incident
                else platform.ledger.query(limit=args.limit)
            )
            _print([e.to_dict() for e in entries])
        case "breaker":
            match args.action:
                case "status":
                    _print(platform.breaker.status().to_dict())
                case "trip":
                    _print(platform.breaker.trip(args.reason, actor="cli:admin").to_dict())
                case "reset":
                    _print(
                        platform.breaker.reset(actor="cli:admin", reason=args.reason).to_dict()
                    )
    return 0


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "cirtdefense.main:app",
        host=args.host or settings.api_host,
        port=args.port or settings.api_port,
        reload=args.reload,
    )
    return 0


def _read_json(path: str) -> dict[str, Any]:
    raw = sys.stdin.read() if path == "-" else Path(path).read_text(encoding="utf-8")
    return json.loads(raw)


def _print(data: Any) -> None:
    print(json.dumps(data, indent=2, ensure_ascii=False, default=str))


if __name__ == "__main__":
    raise SystemExit(main())
