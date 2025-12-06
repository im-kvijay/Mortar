# ============================================
# Mortar-C Makefile
# ============================================
# Convenient shortcuts for Docker and development tasks

.PHONY: help build run shell test clean dvd audit verify install

# Default image settings
IMAGE_NAME ?= mortar-c
IMAGE_TAG ?= latest
IMAGE := $(IMAGE_NAME):$(IMAGE_TAG)

# Data directory
DATA_DIR ?= $(PWD)/data

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[1;33m
NC := \033[0m

# ============================================
# Help
# ============================================
help:
	@echo "$(BLUE)Mortar-C Makefile$(NC)"
	@echo ""
	@echo "$(GREEN)Docker Commands:$(NC)"
	@echo "  make build              Build Docker image"
	@echo "  make build-nc           Build without cache"
	@echo "  make run                Run Mortar-C (pass ARGS=...)"
	@echo "  make shell              Interactive shell"
	@echo "  make dvd NUM=1          Run DVD challenge"
	@echo "  make audit FILE=...     Audit single contract"
	@echo "  make compose-up         Start with docker-compose"
	@echo "  make compose-down       Stop docker-compose"
	@echo ""
	@echo "$(GREEN)Testing:$(NC)"
	@echo "  make test               Run Docker setup verification"
	@echo "  make test-full          Run full verification (includes build)"
	@echo "  make verify             Verify Docker installation"
	@echo "  make benchmark          Run DVD benchmark suite"
	@echo ""
	@echo "$(GREEN)Development:$(NC)"
	@echo "  make install            Install Python dependencies locally"
	@echo "  make lint               Run linters"
	@echo "  make format             Format code"
	@echo "  make pytest             Run Python tests"
	@echo ""
	@echo "$(GREEN)Maintenance:$(NC)"
	@echo "  make clean              Clean containers and data"
	@echo "  make prune              Prune Docker system"
	@echo "  make logs               View container logs"
	@echo "  make stats              Show resource usage"
	@echo ""
	@echo "$(GREEN)Examples:$(NC)"
	@echo "  make build"
	@echo "  make dvd NUM=1"
	@echo "  make audit FILE=./contracts/MyContract.sol"
	@echo "  make run ARGS='--help'"
	@echo "  make shell"

# ============================================
# Docker Build
# ============================================
build:
	@echo "$(BLUE)Building Docker image: $(IMAGE)$(NC)"
	DOCKER_BUILDKIT=1 docker build -t $(IMAGE) .
	@echo "$(GREEN)Build complete$(NC)"

build-nc:
	@echo "$(BLUE)Building Docker image (no cache): $(IMAGE)$(NC)"
	DOCKER_BUILDKIT=1 docker build --no-cache -t $(IMAGE) .
	@echo "$(GREEN)Build complete$(NC)"

# ============================================
# Docker Run
# ============================================
run:
	@echo "$(BLUE)Running Mortar-C: $(ARGS)$(NC)"
	docker run --rm \
		-v $(DATA_DIR):/app/data \
		--env-file .env \
		$(IMAGE) \
		$(ARGS)

shell:
	@echo "$(BLUE)Starting interactive shell$(NC)"
	docker run --rm -it \
		-v $(DATA_DIR):/app/data \
		--env-file .env \
		--entrypoint /bin/bash \
		$(IMAGE)

dvd:
	@if [ -z "$(NUM)" ]; then \
		echo "$(YELLOW)Usage: make dvd NUM=<challenge_number>$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Running DVD challenge $(NUM)$(NC)"
	docker run --rm \
		-v $(DATA_DIR):/app/data \
		-v $(PWD)/training:/app/training:ro \
		--env-file .env \
		$(IMAGE) \
		--dvd $(NUM)

audit:
	@if [ -z "$(FILE)" ]; then \
		echo "$(YELLOW)Usage: make audit FILE=<path_to_contract>$(NC)"; \
		exit 1; \
	fi
	@if [ ! -f "$(FILE)" ]; then \
		echo "$(YELLOW)File not found: $(FILE)$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Auditing contract: $(FILE)$(NC)"
	docker run --rm \
		-v $(DATA_DIR):/app/data \
		-v $$(dirname $(FILE)):/contracts:ro \
		--env-file .env \
		$(IMAGE) \
		--contract /contracts/$$(basename $(FILE))

project:
	@if [ -z "$(DIR)" ]; then \
		echo "$(YELLOW)Usage: make project DIR=<path_to_project>$(NC)"; \
		exit 1; \
	fi
	@if [ ! -d "$(DIR)" ]; then \
		echo "$(YELLOW)Directory not found: $(DIR)$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Auditing project: $(DIR)$(NC)"
	docker run --rm \
		-v $(DATA_DIR):/app/data \
		-v $(DIR):/project:ro \
		--env-file .env \
		$(IMAGE) \
		--project /project

# ============================================
# Docker Compose
# ============================================
compose-up:
	@echo "$(BLUE)Starting docker-compose$(NC)"
	docker-compose up

compose-up-d:
	@echo "$(BLUE)Starting docker-compose (background)$(NC)"
	docker-compose up -d

compose-down:
	@echo "$(BLUE)Stopping docker-compose$(NC)"
	docker-compose down

compose-logs:
	docker-compose logs -f

compose-run:
	docker-compose run --rm mortar $(ARGS)

# ============================================
# Testing
# ============================================
test:
	@echo "$(BLUE)Running Docker setup verification$(NC)"
	./scripts/test_docker_setup.sh

test-full:
	@echo "$(BLUE)Running full Docker verification$(NC)"
	FULL_TEST=1 ./scripts/test_docker_setup.sh

verify:
	@echo "$(BLUE)Verifying Docker installation$(NC)"
	@command -v docker >/dev/null 2>&1 || { echo "$(YELLOW)Docker not installed$(NC)"; exit 1; }
	@docker info >/dev/null 2>&1 || { echo "$(YELLOW)Docker daemon not running$(NC)"; exit 1; }
	@echo "$(GREEN)Docker is ready$(NC)"

benchmark:
	@echo "$(BLUE)Running DVD benchmark suite$(NC)"
	@for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18; do \
		echo "$(BLUE)Challenge $$i/18$(NC)"; \
		$(MAKE) dvd NUM=$$i || echo "$(YELLOW)Challenge $$i failed$(NC)"; \
	done
	@echo "$(GREEN)Benchmark complete$(NC)"

# ============================================
# Development (Local)
# ============================================
install:
	@echo "$(BLUE)Installing Python dependencies$(NC)"
	pip install -r requirements.txt
	pip install slither-analyzer
	@echo "$(GREEN)Dependencies installed$(NC)"

pytest:
	@echo "$(BLUE)Running Python tests$(NC)"
	pytest tests/ -v

lint:
	@echo "$(BLUE)Running linters$(NC)"
	@command -v ruff >/dev/null 2>&1 && ruff check src/ || echo "$(YELLOW)ruff not installed$(NC)"
	@command -v mypy >/dev/null 2>&1 && mypy src/ || echo "$(YELLOW)mypy not installed$(NC)"

format:
	@echo "$(BLUE)Formatting code$(NC)"
	@command -v ruff >/dev/null 2>&1 && ruff format src/ || echo "$(YELLOW)ruff not installed$(NC)"

# ============================================
# Maintenance
# ============================================
clean:
	@echo "$(YELLOW)This will remove all containers and data. Continue? [y/N]$(NC)"
	@read -r response; \
	if [ "$$response" = "y" ] || [ "$$response" = "Y" ]; then \
		docker-compose down 2>/dev/null || true; \
		rm -rf $(DATA_DIR)/logs/* $(DATA_DIR)/cache/* $(DATA_DIR)/runs/*; \
		echo "$(GREEN)Cleanup complete$(NC)"; \
	else \
		echo "$(BLUE)Cancelled$(NC)"; \
	fi

prune:
	@echo "$(BLUE)Pruning Docker system$(NC)"
	docker system prune -af --volumes

logs:
	@echo "$(BLUE)Container logs:$(NC)"
	docker logs mortar-c 2>/dev/null || echo "$(YELLOW)Container not running$(NC)"

stats:
	@echo "$(BLUE)Docker resource usage:$(NC)"
	docker stats --no-stream mortar-c 2>/dev/null || docker stats --no-stream

health:
	@echo "$(BLUE)Container health:$(NC)"
	@docker inspect --format='{{.State.Health.Status}}' mortar-c 2>/dev/null || echo "$(YELLOW)Container not running$(NC)"

# ============================================
# Advanced
# ============================================
push:
	@if [ -z "$(REGISTRY)" ]; then \
		echo "$(YELLOW)Usage: make push REGISTRY=<registry_url>$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Pushing to $(REGISTRY)$(NC)"
	docker tag $(IMAGE) $(REGISTRY)/$(IMAGE)
	docker push $(REGISTRY)/$(IMAGE)

pull:
	@if [ -z "$(REGISTRY)" ]; then \
		echo "$(YELLOW)Usage: make pull REGISTRY=<registry_url>$(NC)"; \
		exit 1; \
	fi
	@echo "$(BLUE)Pulling from $(REGISTRY)$(NC)"
	docker pull $(REGISTRY)/$(IMAGE)
	docker tag $(REGISTRY)/$(IMAGE) $(IMAGE)

# ============================================
# Information
# ============================================
info:
	@echo "$(BLUE)Mortar-C Configuration$(NC)"
	@echo "  Image: $(IMAGE)"
	@echo "  Data: $(DATA_DIR)"
	@echo "  PWD: $(PWD)"
	@echo ""
	@docker images $(IMAGE_NAME) 2>/dev/null || echo "$(YELLOW)  Image not built yet$(NC)"

size:
	@echo "$(BLUE)Docker image size:$(NC)"
	@docker images $(IMAGE) --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}"

# ============================================
# Shortcuts
# ============================================
up: compose-up
down: compose-down
ps:
	docker-compose ps
exec:
	docker-compose exec mortar /bin/bash
