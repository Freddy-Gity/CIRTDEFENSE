"""Application FastAPI."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from .api.deps import get_platform
from .api.routes import (
    actions,
    admin,
    assistant,
    audit,
    auth,
    demo,
    events,
    health,
    incidents,
    monitoring,
    pending,
    policy,
    qualifications,
    users,
)
from .config import get_settings
from .logging_setup import configure_logging

DESCRIPTION = """
Plateforme d'orchestration **autonome** de la réponse aux incidents de
sécurité — CDCF/CDCT v3.0.

La plateforme exécute les actions correctives sans validation humaine
préalable (EF-07). Les garde-fous qui remplacent cette validation sont :

- le catalogue de réversibilité : seule une action annulable est exécutée (EF-14) ;
- la garde de non-invention : pas d'action sur un contexte non documenté (EF-04) ;
- la politique de réponse compilée par l'administrateur (EF-15) ;
- la boucle de contrôle fermée : annulation autonome sur dégradation (EF-25) ;
- le coupe-circuit global (EF-26) ;
- le journal d'audit immuable, seule trace de ce que le système a fait seul.

L'analyste est notifie **après** coup et peut annuler ; il ne valide rien en amont.
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    platform = get_platform()
    app.state.platform = platform
    yield
    platform.close()


VUES_CLIENT = (
    "/",
    "/login",
    "/register",
    "/accueil",
    "/dashboard",
    "/incidents/portfolio",
    "/monitoring",
    "/reversibility-catalog",
    "/demo",
    "/assistant",
    "/reports",
    "/audit-log",
    "/settings",
)


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="CIRTDEFENSE",
        version="3.0.0",
        description=DESCRIPTION,
        lifespan=lifespan,
    )

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(users.router)
    app.include_router(events.router)
    app.include_router(incidents.router)
    app.include_router(actions.router)
    app.include_router(policy.router)
    app.include_router(policy.catalog_router)
    app.include_router(audit.router)
    app.include_router(audit.notifications_router)
    app.include_router(admin.router)
    app.include_router(demo.router)
    app.include_router(assistant.router)
    app.include_router(monitoring.router)
    app.include_router(pending.router)
    app.include_router(qualifications.router)

    # L'interface est cherchee **a cote du paquet installe**, pas a cote du
    # repertoire courant. La distinction compte : un `pip install` non editable,
    # ou un `pip install -e` pointant sur un ancien clone, fait servir cette
    # ancienne interface quoi qu'on tire dans le dossier ou l'on travaille. Le
    # chemin retenu est donc journalise au demarrage et expose sur /health.
    web_root = Path(__file__).resolve().parents[2] / "web"
    app.state.web_root = web_root

    def _page() -> HTMLResponse:
        page = web_root / "index.html"
        if not page.exists():
            return HTMLResponse(
                "<h1>CIRTDEFENSE v3.0</h1><p>Interface introuvable : "
                f"<code>{page}</code>.<p>Documentation : <a href='/docs'>/docs</a></p>"
            )
        html = page.read_text(encoding="utf-8")

        # Empreinte du script dans l'adresse : sans elle, un navigateur peut
        # continuer a servir l'ancien `app.js` apres une mise a jour, et
        # l'interface parait ne pas avoir bouge.
        script = web_root / "static" / "app.js"
        if script.exists():
            html = html.replace(
                'src="/static/app.js"', f'src="/static/app.js?v={int(script.stat().st_mtime)}"'
            )
        return HTMLResponse(html, headers={"Cache-Control": "no-store"})

    # Application a page unique : la navigation se fait cote client par
    # l'History API. Le serveur rend donc la même page pour chacune de ses
    # routes, sans quoi un lien profond ou un rafraichissement donnerait 404.
    for chemin in VUES_CLIENT:
        app.add_api_route(
            chemin,
            _page,
            methods=["GET"],
            response_class=HTMLResponse,
            include_in_schema=False,
        )

    if (web_root / "static").is_dir():
        app.mount("/static", StaticFiles(directory=web_root / "static"), name="static")
    else:
        logging.getLogger(__name__).warning(
            "interface absente : %s introuvable — le paquet installe ne pointe "
            "probablement pas sur ce depot",
            web_root / "static",
        )

    app.state.settings = settings
    return app


app = create_app()
