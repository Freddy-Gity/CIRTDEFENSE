"""Compilation de la politique en langage naturel (EF-15)."""

from __future__ import annotations

import pytest

from cirtdefense.domain.action import ActionSpec
from cirtdefense.domain.enums import Reversibility
from cirtdefense.orchestration.policy_compiler import PolicyCompiler


@pytest.fixture
def compiler() -> PolicyCompiler:
    return PolicyCompiler()


def _action(verb="block_ip", actuator="firewall", target="41.202.1.9", **kwargs) -> ActionSpec:
    kwargs.setdefault("reversibility", Reversibility.REVERSIBLE)
    kwargs.setdefault("rollback_verb", "unblock_ip")
    return ActionSpec(verb=verb, actuator=actuator, target=target, **kwargs)


class TestReconnaissance:
    def test_interdiction_simple(self, compiler):
        policy = compiler.compile("Ne jamais bloquer une adresse interne").policy
        assert not policy.evaluate(_action(target="10.0.0.5"), {}).allowed
        assert policy.evaluate(_action(target="41.202.1.9"), {}).allowed

    def test_plage_cidr_survit_au_decoupage(self, compiler):
        """Régression : le decoupage en phrases coupait sur tous les points et
        detruisait toute adresse écrite dans une politique."""
        report = compiler.compile("Ne jamais bloquer une adresse de la plage 172.16.0.0/12")
        contraintes = report.policy.to_dict()["rules"][1]["constraints"]
        assert any("172" in c for c in contraintes)

    def test_seuil_de_criticite(self, compiler):
        policy = compiler.compile("Interdire l'isolement des machines de criticité 5").policy
        action = _action(
            verb="isolate_host",
            actuator="edr",
            target="srv-01",
            reversibility=Reversibility.PARTIALLY_REVERSIBLE,
            rollback_verb="release_host",
        )
        assert not policy.evaluate(action, {"asset.criticality": 5}).allowed
        assert policy.evaluate(action, {"asset.criticality": 2}).allowed

    def test_rayon_d_impact(self, compiler):
        policy = compiler.compile("Refuser toute action dont le rayon d'impact depasse 10").policy
        assert not policy.evaluate(_action(blast_radius=15), {}).allowed
        assert policy.evaluate(_action(blast_radius=2), {}).allowed

    def test_insensibilite_aux_accents(self, compiler):
        avec = compiler.compile("Interdire l'isolement des machines de criticité 5").policy
        sans = compiler.compile("Interdire l'isolement des machines de criticité 5").policy
        assert avec.checksum() == sans.checksum()


class TestRefusDeDeviner:
    def test_phrase_non_reconnue_est_signalee(self, compiler):
        """Une consigne mal comprise doit être rapportée, jamais approximée :
        sinon la politique paraîtrait appliquée sans l'être."""
        report = compiler.compile("Faites en sorte que tout se passe bien")
        assert report.unparsed_sentences == ["Faites en sorte que tout se passe bien"]
        assert not report.fully_compiled

    def test_avertissement_explicite(self, compiler):
        report = compiler.compile("Soyez prudents avec les serveurs")
        assert any("AUCUN effet" in w for w in report.warnings)

    def test_consigne_sans_condition_n_est_pas_compilee(self, compiler):
        """« Ne rien faire » sans condition identifiable serait une règle
        s'appliquant à tout : trop dangereuse pour être devinee."""
        assert not compiler.compile("Ne jamais rien faire de dangereux").fully_compiled


class TestGardeFouStructurel:
    def test_garde_fou_toujours_present(self, compiler):
        """Aucune politique ne peut autoriser une action irréversible."""
        report = compiler.compile("Autoriser toutes les actions sans exception")
        irreversible = ActionSpec(verb="wipe_disk", actuator="edr", target="srv-01")
        assert not report.policy.evaluate(irreversible, {}).allowed

    def test_garde_fou_prioritaire(self, compiler):
        report = compiler.compile("Autoriser le blocage")
        rules = report.policy.to_dict()["rules"]
        assert rules[0]["rule_id"] == "R-GUARD-IRREVERSIBLE"


class TestTracabilite:
    def test_empreinte_stable(self, compiler):
        texte = "Ne jamais bloquer une adresse interne"
        assert (
            compiler.compile(texte).policy.checksum() == compiler.compile(texte).policy.checksum()
        )

    def test_empreinte_change_avec_la_politique(self, compiler):
        a = compiler.compile("Ne jamais bloquer une adresse interne").policy
        b = compiler.compile("Ne jamais isoler une machine de criticité 5").policy
        assert a.checksum() != b.checksum()

    def test_phrase_source_conservee(self, compiler):
        """L'analyste doit lire la consigne d'origine, pas seulement sa
        traduction en prédicats."""
        phrase = "Ne jamais bloquer une adresse interne"
        verdict = compiler.compile(phrase).policy.evaluate(_action(target="10.0.0.5"), {})
        assert verdict.rule_text == phrase


class TestCouvertureDuVocabulaire:
    """Toute action exécutable doit être exprimable dans une politique.

    Un verbe absent du vocabulaire est une action que l'administrateur ne peut
    pas interdire : le moteur pourrait l'exécuter sans qu'aucune consigne ne
    puisse s'y opposer. C'est le genre d'écart qui s'installe silencieusement
    à chaque ajout d'actuateur.
    """

    def test_tout_verbe_autonome_est_exprimable(self):
        from cirtdefense.orchestration.policy_compiler import VERB_SYNONYMS
        from cirtdefense.orchestration.reversibility import ReversibilityCatalog

        verbes = {e.verb for e in ReversibilityCatalog().autonomous_subset()}
        manquants = sorted(verbes - set(VERB_SYNONYMS))
        assert not manquants, (
            f"verbes exécutables mais non interdictibles par politique : {manquants}"
        )

    def test_chaque_synonyme_est_reconnu(self, compiler):
        """Un synonyme déclare mais non reconnu par le compilateur serait un
        piege : l'administrateur croirait sa consigne appliquée."""
        from cirtdefense.orchestration.policy_compiler import VERB_SYNONYMS

        non_reconnus = []
        for verbe, synonymes in VERB_SYNONYMS.items():
            for synonyme in synonymes:
                report = compiler.compile(f"Ne jamais {synonyme} sur une adresse interne")
                if not report.fully_compiled:
                    non_reconnus.append((verbe, synonyme))
        assert not non_reconnus, f"synonymes non compilés : {non_reconnus}"
