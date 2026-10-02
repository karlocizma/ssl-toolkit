.DEFAULT_GOAL := help
.PHONY: help install dev-backend dev-frontend test test-backend test-frontend build up down logs rebuild clean cli

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

install: ## Install backend and frontend dependencies
	cd backend && python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
	cd frontend && npm ci

dev-backend: ## Run the Flask dev server on :5000
	cd backend && . .venv/bin/activate && python app.py

dev-frontend: ## Run the React dev server on :3000 (proxies /api to :5000)
	cd frontend && npm start

test: test-backend test-frontend ## Run all tests

test-backend: ## Backend tests (ACME integration tests need Pebble, see CONTRIBUTING.md)
	cd backend && . .venv/bin/activate && python -m pytest -q

test-frontend: ## Frontend tests plus the strict production build used in CI
	cd frontend && CI=true npm test -- --watchAll=false && CI=true npm run build

build: ## Build the Docker images
	docker compose build

up: ## Start the full stack in the background (http://localhost)
	docker compose up -d --build

down: ## Stop the stack
	docker compose down

logs: ## Follow the logs
	docker compose logs -f

rebuild: ## Force-rebuild the frontend image (fixes the "default nginx page" cache problem)
	./scripts/rebuild-frontend.sh

cli: ## Example: make cli ARGS="check example.com"
	./bin/ssl-toolkit $(ARGS)

clean: ## Remove build output and caches
	rm -rf frontend/build backend/.pytest_cache backend/.coverage
	find backend -name __pycache__ -type d -prune -exec rm -rf {} +
