#!/usr/bin/env bash
set -euo pipefail

COLOR_RESET="\033[0m"
COLOR_BLUE="\033[1;34m"
COLOR_GREEN="\033[1;32m"
COLOR_RED="\033[1;31m"
COLOR_YELLOW="\033[1;33m"

info() { printf "%b[INFO]%b %s\n" "$COLOR_BLUE" "$COLOR_RESET" "$*"; }
warn() { printf "%b[WARN]%b %s\n" "$COLOR_YELLOW" "$COLOR_RESET" "$*"; }
error() { printf "%b[ERR ]%b %s\n" "$COLOR_RED" "$COLOR_RESET" "$*" >&2; }
success() { printf "%b[ OK ]%b %s\n" "$COLOR_GREEN" "$COLOR_RESET" "$*"; }

prompt() {
  local var_name="$1"
  local label="$2"
  local default_value="${3:-}"
  local current_value="${!var_name:-}"
  local answer

  if [[ -n "$current_value" ]]; then
    return
  fi

  if [[ -n "$default_value" ]]; then
    read -r -p "$label [$default_value]: " answer
    answer="${answer:-$default_value}"
  else
    read -r -p "$label: " answer
  fi
  printf -v "$var_name" "%s" "$answer"
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    error "Команда '$1' не найдена"
    exit 1
  fi
}

choose_existing_action() {
  local answer
  printf "Обнаружена существующая установка панели в %s\n" "$INSTALL_DIR"
  printf "Выберите действие: [u] обновить, [d] удалить, [c] отмена\n"
  read -r -p "Действие [u]: " answer
  answer="${answer:-u}"
  case "$answer" in
    u|U|update|обновить) EXISTING_ACTION="update" ;;
    d|D|delete|remove|удалить) EXISTING_ACTION="delete" ;;
    c|C|cancel|отмена) EXISTING_ACTION="cancel" ;;
    *)
      error "Неизвестное действие: $answer"
      exit 1
      ;;
  esac
}

ensure_repo() {
  if [[ -d "$REPO_DIR/.git" ]]; then
    info "Обновляю репозиторий в $REPO_DIR"
    git -C "$REPO_DIR" fetch --all --tags
    git -C "$REPO_DIR" checkout "$REPO_REF"
    git -C "$REPO_DIR" pull --ff-only origin "$REPO_REF"
    return
  fi

  rm -rf "$REPO_DIR"
  info "Клонирую репозиторий $REPO_URL"
  git clone --depth 1 --branch "$REPO_REF" "$REPO_URL" "$REPO_DIR"
}

has_existing_install() {
  [[ -f "$ENV_FILE" || -d "$PANEL_STATE_DIR" || -d "$REPO_DIR" ]]
}

delete_install() {
  if [[ -f "$ENV_FILE" && -f "$COMPOSE_FILE" ]]; then
    info "Останавливаю текущую панель"
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" down --remove-orphans || true
  fi
  rm -rf "$INSTALL_DIR"
  success "Панель удалена"
}

write_env() {
  cat >"$ENV_FILE" <<EOF
PANEL_PORT=$PANEL_PORT
PANEL_BASE_URL=$PANEL_BASE_URL
PANEL_STATE_DIR=$PANEL_STATE_DIR
ENABLE_LOCAL_NODE=$ENABLE_LOCAL_NODE
LOCAL_NODE_TOKEN=$LOCAL_NODE_TOKEN
SINGBOX_IMAGE=$SINGBOX_IMAGE
SINGBOX_BINARY_PATH=$SINGBOX_BINARY_PATH
EOF
}

usage() {
  cat <<'EOF'
Использование:
  curl -fsSL https://your-panel.example.com/install/panel.sh | bash -s -- [опции]

Опции:
  --repo-url URL
  --repo-ref REF
  --install-dir PATH
  --panel-base-url URL
  --panel-port PORT
  --enable-local-node true|false
  --local-node-token TOKEN
  --singbox-image IMAGE
  --help
EOF
}

REPO_URL="${REPO_URL:-https://github.com/Beykus-Y/mgb-panel}"
REPO_REF="${REPO_REF:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/mgb-panel}"
PANEL_BASE_URL="${PANEL_BASE_URL:-}"
PANEL_PORT="${PANEL_PORT:-8443}"
ENABLE_LOCAL_NODE="${ENABLE_LOCAL_NODE:-false}"
LOCAL_NODE_TOKEN="${LOCAL_NODE_TOKEN:-}"
SINGBOX_IMAGE="${SINGBOX_IMAGE:-ghcr.io/sagernet/sing-box:v1.13.11}"
SINGBOX_BINARY_PATH="${SINGBOX_BINARY_PATH:-/usr/local/bin/sing-box}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --repo-ref) REPO_REF="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --panel-base-url) PANEL_BASE_URL="$2"; shift 2 ;;
    --panel-port) PANEL_PORT="$2"; shift 2 ;;
    --enable-local-node) ENABLE_LOCAL_NODE="$2"; shift 2 ;;
    --local-node-token) LOCAL_NODE_TOKEN="$2"; shift 2 ;;
    --singbox-image) SINGBOX_IMAGE="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *)
      error "Неизвестный аргумент: $1"
      usage
      exit 1
      ;;
  esac
done

prompt REPO_URL "URL git репозитория с mgb-panel" "https://github.com/Beykus-Y/mgb-panel"
prompt PANEL_BASE_URL "Публичный URL панели" "https://panel.example.com:$PANEL_PORT"

REPO_DIR="$INSTALL_DIR/repo"
PANEL_STATE_DIR="$INSTALL_DIR/state"
ENV_FILE="$INSTALL_DIR/panel.env"
COMPOSE_FILE="$REPO_DIR/deploy/panel/docker-compose.yml"
EXISTING_ACTION=""

require_cmd git
require_cmd docker

if ! docker compose version >/dev/null 2>&1; then
  error "Требуется docker compose"
  exit 1
fi

mkdir -p "$INSTALL_DIR" "$PANEL_STATE_DIR"

if has_existing_install; then
  choose_existing_action
  case "$EXISTING_ACTION" in
    delete)
      delete_install
      exit 0
      ;;
    cancel)
      warn "Операция отменена"
      exit 0
      ;;
  esac
fi

ensure_repo
write_env

if [[ "$EXISTING_ACTION" == "update" ]]; then
  info "Обновляю панель через Docker Compose"
else
  info "Запускаю панель через Docker Compose"
fi
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --build

success "Панель установлена"
printf "\n"
printf "Каталог установки: %s\n" "$INSTALL_DIR"
printf "Файл окружения:    %s\n" "$ENV_FILE"
printf "Открыть панель:    %s\n" "$PANEL_BASE_URL"
