# Local development for 4mica-core.
# See deployment/dev_stack.sh for what each step does.

STACK := deployment/dev_stack.sh

.PHONY: help infra-up dev-up dev-down dev-down-all deploy env migrate core status logs vk \
        test-core test-sdk-unit test-sdk test

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Stack lifecycle
# ---------------------------------------------------------------------------

infra-up: ## Start pg + anvil + contracts + migrations (no core-service; enough for core tests)
	@$(STACK) infra

dev-up: ## Start full stack: infra + core-service (needed for SDK e2e tests)
	@$(STACK) up

dev-down: ## Stop core + anvil (keeps postgres and its data)
	@$(STACK) down

dev-down-all: ## Stop everything including postgres
	@$(STACK) down --all

deploy: ## (Re)deploy contracts and regenerate .env
	@$(STACK) deploy

env: ## Regenerate .env from the last deployed contract address
	@$(STACK) env

migrate: ## Run database migrations
	@$(STACK) migrate

core: ## Run core-service in the foreground (infra must already be up)
	@$(STACK) core

status: ## Show what's running
	@$(STACK) status

logs: ## Tail logs: make logs (core) or make logs S=anvil
	@$(STACK) logs $(or $(S),core)

vk: ## Print on-chain VK words for BLS_PRIVATE_KEY (or: make vk KEY=0x..)
	@BLS_PRIVATE_KEY=$(or $(KEY),$(BLS_PRIVATE_KEY)) cargo run -q -p crypto-4mica --bin print-vk

# ---------------------------------------------------------------------------
# Tests
#
# Dependency map:
#   test-core      needs infra-up  (DB + anvil + contracts; api.rs spawns core in-process)
#   test-sdk-unit  needs nothing   (pure unit tests + self-spawning mock servers)
#   test-sdk       needs dev-up    (withdraw.rs hits localhost:3000 via SDK_LOCAL_E2E=1)
# ---------------------------------------------------------------------------

test-core: ## Run all core integration tests (needs infra-up, not full stack)
	@set -a; . ./.env; set +a; cargo test -p core-service

test-sdk-unit: ## Run SDK unit tests (no running stack needed)
	@cargo test -p sdk-4mica

test-sdk: ## Run SDK e2e tests incl. withdraw flows (needs dev-up / core-service on :3000)
	@set -a; . ./.env; set +a; SDK_LOCAL_E2E=1 cargo test -p sdk-4mica

test: test-core test-sdk ## Run core tests then SDK e2e tests (needs dev-up)
