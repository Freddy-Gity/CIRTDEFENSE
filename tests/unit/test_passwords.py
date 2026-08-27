"""Hachage des mots de passe — PBKDF2, bibliothèque standard uniquement."""

from __future__ import annotations

import pytest

from cirtdefense.security.passwords import hash_password, needs_rehash, verify_password
from cirtdefense.security.tokens import new_session_token, token_fingerprint


class TestHachage:
    def test_aller_retour(self) -> None:
        encoded = hash_password("un mot de passe correct")
        assert verify_password("un mot de passe correct", encoded)

    def test_mauvais_mot_de_passe_rejete(self) -> None:
        encoded = hash_password("le bon")
        assert not verify_password("le mauvais", encoded)

    def test_deux_hachages_du_meme_mot_diffèrent(self) -> None:
        """Le sel est aléatoire : deux empreintes du même mot ne sont pas égales."""
        assert hash_password("identique") != hash_password("identique")

    def test_format_stocke(self) -> None:
        encoded = hash_password("x" * 12)
        algo, iterations, sel, digest = encoded.split("$")
        assert algo == "pbkdf2_sha256"
        assert int(iterations) >= 100_000
        assert sel and digest

    def test_mot_de_passe_vide_refuse(self) -> None:
        with pytest.raises(ValueError):
            hash_password("")

    def test_empreinte_corrompue_ne_leve_pas(self) -> None:
        assert not verify_password("peu importe", "n'importe quoi")

    def test_besoin_de_rehash_selon_iterations(self) -> None:
        faible = hash_password("secret-costaud", iterations=50_000)
        assert needs_rehash(faible)
        assert not needs_rehash(hash_password("secret-costaud"))


class TestJetons:
    def test_jeton_unique_et_url_safe(self) -> None:
        a, b = new_session_token(), new_session_token()
        assert a != b
        assert a.replace("-", "").replace("_", "").isalnum()

    def test_empreinte_stable_et_irreversible(self) -> None:
        jeton = new_session_token()
        assert token_fingerprint(jeton) == token_fingerprint(jeton)
        assert jeton not in token_fingerprint(jeton)
