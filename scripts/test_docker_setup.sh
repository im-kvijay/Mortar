#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

PASSED=0
FAILED=0

log_test() { echo -e "${BLUE}[test]${NC} $1"; }
log_pass() { echo -e "${GREEN}[pass]${NC} $1"; ((PASSED++)); }
log_fail() { echo -e "${RED}[fail]${NC} $1"; ((FAILED++)); }
log_warn() { echo -e "${YELLOW}[warn]${NC} $1"; }

test_docker_installed() {
    log_test "checking docker installation"
    if command -v docker &> /dev/null; then
        local version=$(docker --version)
        log_pass "docker installed: ${version}"
    else
        log_fail "docker not installed"
    fi
}

test_docker_running() {
    log_test "checking docker daemon"
    if docker info &> /dev/null 2>&1; then
        log_pass "daemon running"
    else
        log_fail "daemon not running"
    fi
}

test_docker_compose() {
    log_test "checking docker compose"
    if docker compose version &> /dev/null 2>&1; then
        local version=$(docker compose version)
        log_pass "compose v2: ${version}"
    else
        log_warn "compose v2 not found, trying v1"
        if docker-compose --version &> /dev/null 2>&1; then
            local version=$(docker-compose --version)
            log_pass "compose v1: ${version}"
        else
            log_fail "compose not installed"
        fi
    fi
}

test_docker_resources() {
    log_test "checking resources"
    if command -v free &> /dev/null; then
        local mem_gb=$(free -g | awk '/^Mem:/{print $7}')
        if [ "${mem_gb}" -ge 8 ]; then
            log_pass "memory: ${mem_gb}gb"
        else
            log_warn "memory: ${mem_gb}gb (8gb+ recommended)"
        fi
    else
        log_warn "cannot check memory on this system"
    fi
    local cpu_cores=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo "unknown")
    if [ "${cpu_cores}" != "unknown" ]; then
        if [ "${cpu_cores}" -ge 4 ]; then
            log_pass "cpu cores: ${cpu_cores}"
        else
            log_warn "cpu cores: ${cpu_cores} (4+ recommended)"
        fi
    else
        log_warn "cannot determine cpu cores"
    fi
}

test_dockerfile_exists() {
    log_test "checking dockerfile"
    if [ -f "Dockerfile" ]; then
        log_pass "dockerfile found"
    else
        log_fail "dockerfile not found"
    fi
}

test_dockerignore_exists() {
    log_test "checking .dockerignore"
    if [ -f ".dockerignore" ]; then
        log_pass ".dockerignore found"
    else
        log_warn ".dockerignore not found (optional)"
    fi
}

test_docker_compose_file() {
    log_test "checking docker-compose.yml"
    if [ -f "docker-compose.yml" ]; then
        log_pass "docker-compose.yml found"
        if docker compose config &> /dev/null 2>&1 || docker-compose config &> /dev/null 2>&1; then
            log_pass "syntax valid"
        else
            log_fail "syntax errors"
        fi
    else
        log_fail "docker-compose.yml not found"
    fi
}

test_env_file() {
    log_test "checking .env file"
    if [ -f ".env" ]; then
        log_pass ".env found"
        if grep -q "XAI_API_KEY=your_api_key_here" .env; then
            log_warn ".env contains default key, update it"
        elif grep -q "XAI_API_KEY=" .env && ! grep -q "XAI_API_KEY=$" .env; then
            log_pass "xai_api_key configured"
        else
            log_warn "xai_api_key not found"
        fi
    else
        log_warn ".env not found, will use defaults"
    fi
}

test_data_directory() {
    log_test "checking data directory"
    if [ -d "data" ]; then
        log_pass "data exists"
        if [ -w "data" ]; then
            log_pass "data writable"
        else
            log_fail "data not writable, fix: chmod -R u+w data"
        fi
    else
        log_warn "data not found, will be created on first run"
    fi
}

test_docker_build() {
    log_test "testing docker build (may take a few minutes)"
    if [ "${SKIP_BUILD_TEST:-0}" = "1" ]; then
        log_warn "build test skipped (set SKIP_BUILD_TEST=0 to enable)"
        return
    fi
    if timeout 600 docker build -t mortar-c:test . &> /tmp/docker_build.log; then
        log_pass "image builds successfully"
        local size=$(docker images mortar-c:test --format "{{.Size}}")
        log_pass "image size: ${size}"
        docker rmi mortar-c:test &> /dev/null || true
    else
        log_fail "build failed, check /tmp/docker_build.log"
        tail -20 /tmp/docker_build.log
    fi
}

test_docker_run() {
    log_test "testing docker run"
    if [ "${SKIP_RUN_TEST:-0}" = "1" ]; then
        log_warn "run test skipped (set SKIP_RUN_TEST=0 to enable)"
        return
    fi
    if ! docker images | grep -q "mortar-c"; then
        log_warn "mortar-c not built, skipping run test"
        return
    fi
    if docker run --rm mortar-c:latest --help &> /dev/null; then
        log_pass "container runs"
    else
        log_fail "container failed to run"
    fi
}

main() {
    echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   mortar-c docker setup verification      ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
    echo ""

    test_docker_installed
    test_docker_running
    test_docker_compose
    test_docker_resources
    test_dockerfile_exists
    test_dockerignore_exists
    test_docker_compose_file
    test_env_file
    test_data_directory

    if [ "${FULL_TEST:-0}" = "1" ]; then
        test_docker_build
        test_docker_run
    else
        echo ""
        log_warn "skipping build/run tests (set FULL_TEST=1 to enable)"
    fi

    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║   test results                             ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════╝${NC}"
    echo -e "${GREEN}passed:${NC} ${PASSED}"
    echo -e "${RED}failed:${NC} ${FAILED}"
    echo ""

    if [ ${FAILED} -eq 0 ]; then
        echo -e "${GREEN}✓ all tests passed${NC}"
        echo ""
        echo "next steps:"
        echo "  1. build:     docker build -t mortar-c:latest ."
        echo "  2. test:      docker run --rm mortar-c:latest --help"
        echo "  3. dvd:       ./scripts/docker_helper.sh dvd 1"
        echo ""
        exit 0
    else
        echo -e "${RED}✗ some tests failed${NC}"
        echo ""
        echo "common fixes:"
        echo "  • docker not running:   start docker or 'sudo systemctl start docker'"
        echo "  • missing files:        run from project root"
        echo "  • permissions:          'chmod -R u+w data'"
        echo ""
        exit 1
    fi
}

case "${1:-}" in
    --full) FULL_TEST=1; main ;;
    --help|-h)
        echo "usage: $0 [--full]"
        echo ""
        echo "options:"
        echo "  --full    run full test suite including build/run (slower)"
        echo ""
        echo "environment:"
        echo "  FULL_TEST=1         enable full suite"
        echo "  SKIP_BUILD_TEST=1   skip build test"
        echo "  SKIP_RUN_TEST=1     skip run test"
        exit 0
        ;;
    *) main ;;
esac
