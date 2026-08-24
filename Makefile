.PHONY: help install dev test test-recette lint format run demo seed clean docker docker-up

PYTHON ?= python3

help:  ## Afficher cette aide
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

install:  ## Installer la plateforme
	$(PYTHON) -m pip install -e .

dev:  ## Installer avec les outils de developpement
	$(PYTHON) -m pip install -e ".[dev]"

test:  ## Executer toute la suite de tests
	$(PYTHON) -m pytest

test-recette:  ## Executer les seuls criteres de recette (CDCF §5)
	$(PYTHON) -m pytest tests/acceptance -v

lint:  ## Verifier le style et les types
	$(PYTHON) -m ruff check src tests
	$(PYTHON) -m mypy src

format:  ## Reformater le code
	$(PYTHON) -m ruff format src tests scripts
	$(PYTHON) -m ruff check --fix src tests

run:  ## Demarrer l'API sur http://localhost:8000
	$(PYTHON) -m uvicorn cirtdefense.main:app --reload --host 0.0.0.0 --port 8000

demo:  ## Rejouer le scenario de demonstration
	$(PYTHON) scripts/demo_attaque.py

demo-pas-a-pas:  ## Demonstration avec pause entre chaque etape
	$(PYTHON) scripts/demo_attaque.py --pas-a-pas

seed:  ## Alimenter la base avec un jeu d'incidents varie
	$(PYTHON) scripts/seed_demo.py

clean:  ## Supprimer les artefacts locaux
	rm -rf data .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true

docker:  ## Construire l'image
	docker build -t cirtdefense:3.0 .

docker-up:  ## Demarrer la pile complete
	docker compose up --build
