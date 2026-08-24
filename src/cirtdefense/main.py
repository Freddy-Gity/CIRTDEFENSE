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
    policy,
)
from .config import get_settings
from .logging_setup import configure_logging

DESCRIPTION = """
Plateforme d'orchestration **autonome** de la reponse aux incidents de
securite — CDCF/CDCT v3.0.

La plateforme execute les actions correctives sans validation humaine
prealable (EF-07). Les garde-fous qui remplacent cette validation sont :

- le catalogue de reversibilite : seule une action annulable est executee (EF-14) ;
- la garde de non-invention : pas d'action sur un contexte non documente (EF-04) ;
- la politique de reponse compilee par l'administrateur (EF-15) ;
- la boucle de controle fermee : annulation autonome sur degradation (EF-25) ;
- le coupe-circuit global (EF-26) ;
- le journal d'audit immuable, seule trace de ce que le systeme a fait seul.

L'analyste est notifie **apres** coup et peut annuler ; il ne valide rien en amont.
"""


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    platform = get_platform()
    app.state.platform = platform
    yield
    platform.close()


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

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def dashboard() -> str:
        page = Path(__file__).resolve().parents[2] / "web" / "index.html"
        if page.exists():
            return page.read_text(encoding="utf-8")
        return "<h1>CIRTDEFENSE v3.0</h1><p>Documentation : <a href='/docs'>/docs</a></p>"

    web_root = Path(__file__).resolve().parents[2] / "web"
    if (web_root / "static").is_dir():
        app.mount("/static", StaticFiles(directory=web_root / "static"), name="static")

    app.state.settings = settings
    return app


app = create_app()
