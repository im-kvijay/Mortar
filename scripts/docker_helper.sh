#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

IMAGE_NAME="${IMAGE_NAME:-mortar-c}"
IMAGE_TAG="${IMAGE_TAG:-latest}"
CONTAINER_NAME="${CONTAINER_NAME:-mortar-c}"
DATA_DIR="${DATA_DIR:-$(pwd)/data}"

log_info() { echo -e "${BLUE}[info]${NC} $1"; }
log_success() { echo -e "${GREEN}[ok]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[warn]${NC} $1"; }
log_error() { echo -e "${RED}[error]${NC} $1"; }

check_requirements() {
    if ! command -v docker &> /dev/null; then
        log_error "docker not installed"
        exit 1
    fi
    if ! docker info &> /dev/null; then
        log_error "docker daemon not running"
        exit 1
    fi
}

check_env_file() {
    if [ ! -f .env ]; then
        log_warn ".env not found, creating template"
        cat > .env << EOF
XAI_API_KEY=your_api_key_here
BACKEND=openrouter
MODEL=x-ai/grok-4.1-fast
FORCE_GROK_FAST=1
CONTRACT_TIMEOUT_SECONDS=7200
AGENT_MAX_SECONDS=1800
VERIFICATION_WORKERS=1
EOF
        log_info "edit .env and add api key"
        exit 0
    fi
}

cmd_build() {
    log_info "building ${IMAGE_NAME}:${IMAGE_TAG}"
    local build_args=""
    if [ "${1:-}" = "--no-cache" ]; then
        build_args="--no-cache"
    fi
    DOCKER_BUILDKIT=1 docker build ${build_args} -t "${IMAGE_NAME}:${IMAGE_TAG}" .
    log_success "image built"
    docker images "${IMAGE_NAME}:${IMAGE_TAG}"
}

cmd_run() {
    check_env_file
    log_info "running: $@"
    docker run --rm -v "${DATA_DIR}:/app/data" --env-file .env "${IMAGE_NAME}:${IMAGE_TAG}" $@
}

cmd_shell() {
    log_info "starting shell"
    docker run --rm -it -v "${DATA_DIR}:/app/data" --env-file .env --entrypoint /bin/bash "${IMAGE_NAME}:${IMAGE_TAG}"
}

cmd_dvd() {
    local challenge="${1:-1}"
    log_info "running dvd ${challenge}"
    check_env_file
    docker run --rm -v "${DATA_DIR}:/app/data" -v "$(pwd)/training:/app/training:ro" --env-file .env "${IMAGE_NAME}:${IMAGE_TAG}" --dvd "${challenge}"
}

cmd_audit() {
    local contract_path="$1"
    if [ ! -f "${contract_path}" ]; then
        log_error "contract not found: ${contract_path}"
        exit 1
    fi
    log_info "auditing ${contract_path}"
    check_env_file
    local contract_dir=$(dirname "${contract_path}")
    local contract_file=$(basename "${contract_path}")
    docker run --rm -v "${DATA_DIR}:/app/data" -v "${contract_dir}:/contracts:ro" --env-file .env "${IMAGE_NAME}:${IMAGE_TAG}" --contract "/contracts/${contract_file}"
}

cmd_project() {
    local project_path="$1"
    if [ ! -d "${project_path}" ]; then
        log_error "project not found: ${project_path}"
        exit 1
    fi
    log_info "auditing project ${project_path}"
    check_env_file
    docker run --rm -v "${DATA_DIR}:/app/data" -v "${project_path}:/project:ro" --env-file .env "${IMAGE_NAME}:${IMAGE_TAG}" --project "/project"
}

cmd_clean() {
    log_warn "remove all containers and data? [y/N]"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        log_info "cancelled"
        exit 0
    fi
    log_info "stopping containers"
    docker-compose down 2>/dev/null || true
    log_info "removing data"
    rm -rf "${DATA_DIR}/logs/"* "${DATA_DIR}/cache/"* "${DATA_DIR}/runs/"*
    log_success "cleanup complete"
}

cmd_logs() {
    local lines="${1:-100}"
    log_info "showing last ${lines} lines"
    if docker-compose ps | grep -q mortar; then
        docker-compose logs --tail="${lines}" -f
    else
        log_error "no running containers"
        exit 1
    fi
}

cmd_stats() {
    log_info "docker resource usage:"
    docker stats --no-stream "${CONTAINER_NAME}" 2>/dev/null || {
        log_warn "container not running, showing all:"
        docker stats --no-stream
    }
}

cmd_health() {
    log_info "checking container health"
    if docker ps | grep -q "${CONTAINER_NAME}"; then
        local health=$(docker inspect --format='{{.State.Health.Status}}' "${CONTAINER_NAME}" 2>/dev/null || echo "unknown")
        case "${health}" in
            healthy) log_success "container healthy" ;;
            unhealthy)
                log_error "container unhealthy"
                docker inspect --format='{{json .State.Health}}' "${CONTAINER_NAME}" | jq
                ;;
            *) log_warn "health status: ${health}" ;;
        esac
    else
        log_error "container not running"
        exit 1
    fi
}

cmd_update() {
    log_info "updating image"
    cmd_build --no-cache
    log_info "testing updated image"
    docker run --rm "${IMAGE_NAME}:${IMAGE_TAG}" --help
    log_success "update complete"
}

cmd_benchmark() {
    log_info "running dvd benchmark suite"
    check_env_file
    for challenge in {1..18}; do
        log_info "challenge ${challenge}/18"
        docker run --rm -v "${DATA_DIR}:/app/data" -v "$(pwd)/training:/app/training:ro" --env-file .env "${IMAGE_NAME}:${IMAGE_TAG}" --dvd "${challenge}" || log_warn "challenge ${challenge} failed"
    done
    log_success "benchmark complete, check ${DATA_DIR}/reports/"
}

cmd_compose() {
    local action="${1:-up}"
    shift || true
    log_info "running docker-compose ${action}"
    docker-compose "${action}" "$@"
}

usage() {
    cat << EOF
${BLUE}mortar-c docker helper${NC}

${GREEN}usage:${NC} $0 <command> [options]

${GREEN}commands:${NC}
    ${YELLOW}build${NC} [--no-cache]     build docker image
    ${YELLOW}run${NC} <args>             run with custom args
    ${YELLOW}shell${NC}                  interactive shell
    ${YELLOW}dvd${NC} <challenge>        run dvd challenge (1-18)
    ${YELLOW}audit${NC} <contract>       audit single contract
    ${YELLOW}project${NC} <path>         audit entire project
    ${YELLOW}compose${NC} <action>       run docker-compose
    ${YELLOW}logs${NC} [lines]           view logs (default: 100)
    ${YELLOW}stats${NC}                  show resource usage
    ${YELLOW}health${NC}                 check container health
    ${YELLOW}clean${NC}                  remove containers and data
    ${YELLOW}update${NC}                 rebuild with latest changes
    ${YELLOW}benchmark${NC}              run full dvd suite

${GREEN}examples:${NC}
    $0 build
    $0 dvd 1
    $0 audit ./contracts/MyContract.sol
    $0 shell
    $0 benchmark

${GREEN}environment:${NC}
    IMAGE_NAME      image name (default: mortar-c)
    IMAGE_TAG       image tag (default: latest)
    CONTAINER_NAME  container name (default: mortar-c)
    DATA_DIR        data directory (default: ./data)
EOF
}

main() {
    check_requirements
    if [ $# -eq 0 ]; then
        usage
        exit 0
    fi
    local command="$1"
    shift
    case "${command}" in
        build) cmd_build "$@" ;;
        run) cmd_run "$@" ;;
        shell) cmd_shell ;;
        dvd) cmd_dvd "$@" ;;
        audit)
            if [ $# -eq 0 ]; then
                log_error "usage: $0 audit <contract_path>"
                exit 1
            fi
            cmd_audit "$@"
            ;;
        project)
            if [ $# -eq 0 ]; then
                log_error "usage: $0 project <project_path>"
                exit 1
            fi
            cmd_project "$@"
            ;;
        compose) cmd_compose "$@" ;;
        logs) cmd_logs "$@" ;;
        stats) cmd_stats ;;
        health) cmd_health ;;
        clean) cmd_clean ;;
        update) cmd_update ;;
        benchmark) cmd_benchmark ;;
        help|--help|-h) usage ;;
        *)
            log_error "unknown command: ${command}"
            usage
            exit 1
            ;;
    esac
}

main "$@"
