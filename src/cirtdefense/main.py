"""Application FastAPI."""

from __future__ import annotations

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
    demo,
    events,
    health,
    incidents,
    monitoring,
    policy,
)
from .config import get_settings
from .logging_setup import configure_logging

DESCRIPTION = """
Plateforme d'orchestration **autonome** de la réponse aux incidents de
sécurité — CDCF/CDCT v3.0.

La plateforme exécute les actions correctives sans validation humaine
préalable (EF-07). Les garde-fous qui remplacent cette validation sont :

- le catalogue de réversibilité : seule une action annulable est exécutée (EF-14) ;
- la garde de non-invention : pas d'action sur un contexte non documente (EF-04) ;
- la politique de réponse compilée par l'administrateur (EF-15) ;
- la boucle de contrôle fermee : annulation autonome sur dégradation (EF-25) ;
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

    def _page() -> str:
        page = Path(__file__).resolve().parents[2] / "web" / "index.html"
        if page.exists():
            return page.read_text(encoding="utf-8")
        return "<h1>CIRTDEFENSE v3.0</h1><p>Documentation : <a href='/docs'>/docs</a></p>"

    # L'interface est une application a page unique : la navigation se fait
    # cote client par l'History API. Le serveur doit donc rendre la meme page
    # pour chacune de ses routes, sans quoi un lien profond ou un simple
    # rafraichissement renverrait une 404.
    for chemin in VUES_CLIENT:
        app.add_api_route(
            chemin,
            lambda: HTMLResponse(_page()),
            methods=["GET"],
            response_class=HTMLResponse,
            include_in_schema=False,
        )

    web_root = Path(__file__).resolve().parents[2] / "web"
    if (web_root / "static").is_dir():
        app.mount("/static", StaticFiles(directory=web_root / "static"), name="static")

    app.state.settings = settings
    return app


app = create_app()
