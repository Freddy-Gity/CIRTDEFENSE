"""Assemblage de la plateforme : un seul endroit ou les pieces se branchent.

Regrouper le cablage ici a une consequence pratique importante : la posture
d'autonomie effective d'un deploiement se lit en un seul fichier. Un auditeur
n'a pas a parcourir le code pour savoir si le systeme agit reellement, avec
quels actuateurs et sous quelle politique.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from typing import Any

from .actuators import ActuatorRegistry
from .actuators import edr as edr_module
from .actuators import firewall as firewall_module
from .actuators import iam as iam_module
from .actuators import network as network_module
from .actuators import notify as notify_module
from .audit.ledger import AuditLedger
from .audit.notifier import AnalystNotifier
from .config import Settings, get_settings
from .degraded.queue import DegradedSpool
from .detection.infra.health import HealthProbe, StaticProbe
from .detection.infra.monitors import InfrastructureMonitor
from .detection.infra.post_action_watch import PostActionWatcher
from .detection.ueba.baseline import BaselineStore
from .detection.ueba.scorer import UebaScorer
from .domain.policy import IRREVERSIBLE_GUARD, ResponsePolicy
from .enrichment.rag import EnrichmentService
from .ingestion.adapter import IngestionAdapter
from .logging_setup import log_with
from .orchestration.circuit_breaker import CircuitBreaker
from .orchestration.engine import OrchestrationEngine, OrchestrationResult
from .orchestration.executor import Executor
from .orchestration.planner import Planner
from .orchestration.policy_compiler import PolicyCompiler
from .orchestration.portfolio import PortfolioService
from .orchestration.reversibility import ReversibilityCatalog
from .orchestration.rollback import RollbackService
from .persistence.db import connect, init_schema
from .persistence.repositories import (
    ActionRepository,
    BreakerRepository,
    DecisionRepository,
    EventRepository,
    IncidentRepository,
    NotificationRepository,
    PolicyRepository,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class Platform:
    """Toutes les pieces assemblees, prêtes a l'emploi."""

    settings: Settings
    connection: sqlite3.Connection
    ledger: AuditLedger
    events: EventRepository
    incidents: IncidentRepository
    decisions: DecisionRepository
    actions: ActionRepository
    policies: PolicyRepository
    notifications: NotificationRepository
    adapter: IngestionAdapter
    enrichment: EnrichmentService
    planner: Planner
    catalog: ReversibilityCatalog
    registry: ActuatorRegistry
    executor: Executor
    watcher: PostActionWatcher
    rollback: RollbackService
    breaker: CircuitBreaker
    engine: OrchestrationEngine
    portfolio: PortfolioService
    notifier: AnalystNotifier
    spool: DegradedSpool
    ueba: UebaScorer
    monitor: InfrastructureMonitor
    probe: HealthProbe
    degraded: bool = False

    # -- chaine nominale ----------------------------------------------------

    def ingest_and_respond(self, source: str, payload: dict[str, Any]) -> OrchestrationResult | None:
        """Point d'entree unique : de la charge brute a l'action executee.

        En mode degrade, l'evenement est mis en file et rien n'est execute :
        agir sans pouvoir observer l'effet de son action reviendrait a
        desactiver EF-25 en silence.
        """
        if self.degraded:
            self.spool.enqueue(source, payload)
            return None

        result = self.adapter.ingest(source, payload)
        if not result.accepted or result.event is None or result.incident is None:
            return None
        return self.engine.handle(result.event, result.incident)

    def replay_spool(self) -> dict[str, Any]:
        report = self.spool.replay(self.ingest_and_respond)
        return report.to_dict()

    def enter_degraded_mode(self, reason: str) -> None:
        self.degraded = True
        log_with(logger, logging.WARNING, "entree en mode degrade", reason=reason)

    def leave_degraded_mode(self) -> dict[str, Any]:
        self.degraded = False
        return self.replay_spool()

    def status(self) -> dict[str, Any]:
        breaker = self.breaker.status()
        return {
            "version": "3.0.0",
            "environment": self.settings.env,
            "site_id": self.settings.site_id,
            "autonomy": {
                "enabled": self.settings.autonomy.enabled,
                "actuation_mode": self.settings.autonomy.actuation_mode,
                "effective": self.settings.autonomy.enabled and breaker.autonomy_active,
            },
            "circuit_breaker": breaker.to_dict(),
            "degraded_mode": self.degraded,
            "spool_size": self.spool.size(),
            "policy": {
                "policy_id": self.engine.policy.policy_id,
                "version": self.engine.policy.version,
                "checksum": self.engine.policy.checksum(),
                "rules": len(self.engine.policy.rules),
            },
            "catalog": {
                "total": len(self.catalog.all()),
                "autonomously_executable": len(self.catalog.autonomous_subset()),
            },
            "knowledge_base": self.enrichment.corpus_size(),
            "playbooks": self.planner.categories(),
            "actuators": self.registry.describe(),
            "audit_chain": self.ledger.verify_chain().to_dict(),
        }

    def close(self) -> None:
        self.connection.close()


def build_platform(
    settings: Settings | None = None,
    *,
    db_path: str | None = None,
    probe: HealthProbe | None = None,
    policy_text: str | None = None,
) -> Platform:
    """Cable la plateforme. `db_path=':memory:'` donne une instance jetable."""
    settings = settings or get_settings()
    connection = connect(db_path or settings.db_path)
    init_schema(connection)

    ledger = AuditLedger(connection)
    events = EventRepository(connection)
    incidents = IncidentRepository(connection)
    decisions = DecisionRepository(connection)
    actions = ActionRepository(connection)
    policies = PolicyRepository(connection)
    notifications = NotificationRepository(connection)

    mode = settings.autonomy.actuation_mode
    registry = ActuatorRegistry()
    registry.register(firewall_module.build(mode))
    registry.register(edr_module.build(mode))
    registry.register(iam_module.build(mode))
    registry.register(network_module.build(mode))
    notification_actuator = notify_module.build(mode, notifications)
    registry.register(notification_actuator)

    catalog = ReversibilityCatalog()
    health_probe = probe or StaticProbe()
    watcher = PostActionWatcher(health_probe)
    monitor = InfrastructureMonitor(health_probe)

    executor = Executor(
        registry, actions, ledger, watcher, catalog, actuation_mode=mode
    )
    rollback = RollbackService(
        registry, actions, ledger, watcher, catalog, incidents,
        max_latency_seconds=settings.autonomy.rollback_max_latency_seconds,
    )
    breaker = CircuitBreaker(
        BreakerRepository(connection), actions, ledger,
        enabled=settings.autonomy.circuit_breaker_enabled,
        rollback_threshold=settings.autonomy.breaker_rollback_threshold,
        failure_threshold=settings.autonomy.breaker_error_threshold,
        window_seconds=settings.autonomy.breaker_window_seconds,
    )

    policy = _load_or_compile_policy(policies, policy_text)
    enrichment = EnrichmentService.from_directory(
        settings.knowledge_dir, settings.grounding_min_score
    )
    planner = Planner.from_directory(settings.playbook_dir, catalog)
    notifier = AnalystNotifier(notification_actuator)

    engine = OrchestrationEngine(
        enrichment=enrichment,
        planner=planner,
        executor=executor,
        rollback=rollback,
        breaker=breaker,
        policy=policy,
        incidents=incidents,
        decisions=decisions,
        actions=actions,
        ledger=ledger,
        notifier=notifier,
        autonomy_enabled=settings.autonomy.enabled,
    )

    platform = Platform(
        settings=settings,
        connection=connection,
        ledger=ledger,
        events=events,
        incidents=incidents,
        decisions=decisions,
        actions=actions,
        policies=policies,
        notifications=notifications,
        adapter=IngestionAdapter(events, incidents, ledger),
        enrichment=enrichment,
        planner=planner,
        catalog=catalog,
        registry=registry,
        executor=executor,
        watcher=watcher,
        rollback=rollback,
        breaker=breaker,
        engine=engine,
        portfolio=PortfolioService(incidents, actions),
        notifier=notifier,
        spool=DegradedSpool(settings.degraded_spool, settings.degraded_max_items),
        ueba=UebaScorer(BaselineStore(settings.degraded_spool.parent / "baselines.json")),
        monitor=monitor,
        probe=health_probe,
    )

    log_with(
        logger, logging.INFO, "plateforme demarree",
        autonomy_enabled=settings.autonomy.enabled,
        actuation_mode=mode,
        circuit_breaker=settings.autonomy.circuit_breaker_enabled,
        policy_checksum=policy.checksum(),
    )
    return platform


def _load_or_compile_policy(
    repository: PolicyRepository, policy_text: str | None
) -> ResponsePolicy:
    """Compile la politique fournie, sinon applique la politique minimale.

    La politique minimale ne contient que le garde-fou d'irreversibilite : elle
    autorise toute action reversible du catalogue. C'est la posture v3.0 dans
    sa forme la plus large, et elle est explicitement journalisee comme telle
    au demarrage plutot que subie par defaut.
    """
    if policy_text:
        report = PolicyCompiler().compile(policy_text)
        repository.save(report.policy)
        if report.unparsed_sentences:
            log_with(
                logger, logging.WARNING,
                "des consignes de politique n'ont pas ete compilees et resteront sans effet",
                unparsed=report.unparsed_sentences,
            )
        return report.policy

    stored = repository.active()
    if stored:
        log_with(logger, logging.INFO, "politique active rechargee depuis la base",
                 version=stored.get("version"), checksum=stored.get("checksum"))

    return ResponsePolicy(
        policy_id="default",
        version="1",
        rules=[IRREVERSIBLE_GUARD],
        source_text="",
        default_effect="allow",
        author="systeme",
    )
