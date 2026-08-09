SHELL := /bin/bash
.DEFAULT_GOAL := help
COMPOSE := docker compose
TF := terraform -chdir=infra/terraform
PY := .venv/bin/python

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-22s\033[0m %s\n", $$1, $$2}'

# ── Local development ────────────────────────────────────────────────────────
.PHONY: venv
venv: ## Create the local virtualenv and install dev dependencies
	uv venv --python 3.11 .venv
	uv pip install --python $(PY) -e ".[dev]"

.PHONY: env
env: ## Create .env from the example if it does not exist
	@test -f .env || (cp .env.example .env && echo "Created .env — edit it before 'make up'")

.PHONY: up
up: env ## Start the local stack (api, postgres, redis, n8n)
	$(COMPOSE) up -d --build
	@echo "API      → http://localhost:8000/ui"
	@echo "API docs → http://localhost:8000/docs"
	@echo "n8n      → http://localhost:5678"

.PHONY: up-ollama
up-ollama: env ## Start the local stack including Ollama
	$(COMPOSE) --profile ollama up -d --build

.PHONY: down
down: ## Stop the local stack
	$(COMPOSE) down

.PHONY: clean
clean: ## Stop the stack and delete all local data volumes
	$(COMPOSE) down -v

.PHONY: logs
logs: ## Tail logs from all services
	$(COMPOSE) logs -f --tail=100

.PHONY: logs-api
logs-api: ## Tail API logs
	$(COMPOSE) logs -f --tail=200 api

.PHONY: shell
shell: ## Shell into the API container
	$(COMPOSE) exec api sh

.PHONY: psql
psql: ## Open psql against the local database
	$(COMPOSE) exec postgres psql -U $${POSTGRES_USER:-agenticir} -d $${POSTGRES_DB:-agenticir}

# ── Quality ──────────────────────────────────────────────────────────────────
.PHONY: fmt
fmt: ## Format and autofix
	$(PY) -m ruff format app tests
	$(PY) -m ruff check --fix app tests

.PHONY: lint
lint: ## Lint and type-check
	$(PY) -m ruff check app tests
	$(PY) -m ruff format --check app tests
	$(PY) -m mypy app || true

.PHONY: test
test: ## Run the test suite
	$(PY) -m pytest -q

.PHONY: check
check: lint test ## Lint + test

# ── Agent utilities ──────────────────────────────────────────────────────────
.PHONY: demo
demo: ## Run a sample investigation locally (needs an LLM key in .env)
	$(PY) -m app.cli demo --file examples/alert-suspicious-powershell.json --yes

.PHONY: graph
graph: ## Print the graph topology as mermaid
	$(PY) -m app.cli graph

.PHONY: smoke
smoke: ## Probe a running deployment (BASE_URL=... API_KEY=...)
	@bash infra/scripts/smoke-test.sh

.PHONY: e2e
e2e: ## Drive one incident end to end and grade the deployment (BASE_URL=... API_KEY=...)
	@python3 infra/scripts/e2e_scenario.py $(ARGS)

.PHONY: e2e-surface
e2e-surface: ## The same harness, contract and ops checks only — no LLM spend
	@python3 infra/scripts/e2e_scenario.py --surface-only

# ── Infrastructure ───────────────────────────────────────────────────────────
.PHONY: tf-init
tf-init: ## terraform init
	$(TF) init

.PHONY: tf-plan
tf-plan: ## terraform plan
	$(TF) plan

.PHONY: tf-apply
tf-apply: ## Provision the Hetzner server and install Coolify
	$(TF) apply

.PHONY: tf-destroy
tf-destroy: ## Destroy the Hetzner infrastructure
	$(TF) destroy

.PHONY: tf-output
tf-output: ## Show Terraform outputs
	$(TF) output

.PHONY: coolify-wait
coolify-wait: ## Block until Coolify finishes installing on the new server
	@bash infra/scripts/wait-for-coolify.sh

.PHONY: coolify-deploy
coolify-deploy: ## Create/update the Coolify resources and deploy (needs COOLIFY_* env)
	$(PY) infra/coolify/bootstrap.py

.PHONY: coolify-redeploy
coolify-redeploy: ## Trigger a redeploy of the existing Coolify resource
	$(PY) infra/coolify/bootstrap.py --deploy-only

.PHONY: provision
provision: tf-apply coolify-wait coolify-deploy ## Full path: server → Coolify → app
	@echo "Provisioning complete. See 'make tf-output' for URLs."
