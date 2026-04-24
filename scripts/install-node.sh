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
  printf "Обнаружена существующая установка ноды в %s\n" "$INSTALL_DIR"
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
  if [[ -n "${LOCAL_REPO_DIR:-}" ]]; then
    REPO_DIR="$LOCAL_REPO_DIR"
    info "Использую локальный репозиторий $REPO_DIR"
    return
  fi

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
  [[ -f "$ENV_FILE" || -d "$NODE_STATE_DIR" || -d "$BOOTSTRAP_DIR" || ( -z "${LOCAL_REPO_DIR:-}" && -d "$REPO_DIR" ) ]]
}

delete_install() {
  if [[ -f "$ENV_FILE" && -f "$COMPOSE_FILE" ]]; then
    info "Останавливаю текущую ноду"
    docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" down --remove-orphans || true
  fi

  if [[ -n "${LOCAL_REPO_DIR:-}" ]]; then
    rm -rf "$NODE_STATE_DIR" "$BOOTSTRAP_DIR" "$ENV_FILE"
    rmdir "$INSTALL_DIR" 2>/dev/null || true
  else
    rm -rf "$INSTALL_DIR"
  fi

  success "Нода удалена"
}

download_ca() {
  info "Скачиваю CA сертификат панели"
  curl -fsSLk "$PANEL_CA_URL" -o "$PANEL_CA_FILE"

  local actual_fp expected_fp
  actual_fp="$(openssl x509 -in "$PANEL_CA_FILE" -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
  expected_fp="$(printf '%s' "$PANEL_FINGERPRINT" | tr '[:upper:]' '[:lower:]')"

  if [[ -z "$actual_fp" ]]; then
    error "Не удалось вычислить fingerprint CA сертификата"
    exit 1
  fi
  if [[ "$actual_fp" != "$expected_fp" ]]; then
    error "Fingerprint CA не совпадает"
    error "Ожидался: $expected_fp"
    error "Получен:   $actual_fp"
    exit 1
  fi

  success "CA сертификат проверен"
}

write_env() {
  cat >"$ENV_FILE" <<EOF
NODE_STATE_DIR=$NODE_STATE_DIR
PANEL_URL=$PANEL_URL
PANEL_CA_FILE=$PANEL_CA_FILE
BOOTSTRAP_TOKEN=$BOOTSTRAP_TOKEN
PANEL_FINGERPRINT=$PANEL_FINGERPRINT
POLL_INTERVAL=$POLL_INTERVAL
SINGBOX_IMAGE=$SINGBOX_IMAGE
SINGBOX_BINARY_PATH=$SINGBOX_BINARY_PATH
EOF
}

usage() {
  cat <<'EOF'
Использование:
  ./scripts/install-node.sh [опции]

Опции:
  --repo-url URL
  --repo-ref REF
  --install-dir PATH
  --panel-url URL
  --panel-ca-url URL
  --panel-fingerprint SHA256
  --bootstrap-token TOKEN
  --poll-interval DURATION
  --singbox-image IMAGE
  --help
EOF
}

REPO_URL="${REPO_URL:-https://github.com/Beykus-Y/mgb-panel}"
REPO_REF="${REPO_REF:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/mgb-node}"
PANEL_URL="${PANEL_URL:-}"
PANEL_CA_URL="${PANEL_CA_URL:-}"
PANEL_FINGERPRINT="${PANEL_FINGERPRINT:-}"
BOOTSTRAP_TOKEN="${BOOTSTRAP_TOKEN:-}"
POLL_INTERVAL="${POLL_INTERVAL:-20s}"
SINGBOX_IMAGE="${SINGBOX_IMAGE:-ghcr.io/sagernet/sing-box:v1.13.11}"
SINGBOX_BINARY_PATH="${SINGBOX_BINARY_PATH:-/usr/local/bin/sing-box}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/../go.mod" && -f "$SCRIPT_DIR/../deploy/node/docker-compose.yml" ]]; then
  LOCAL_REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --repo-ref) REPO_REF="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --panel-url) PANEL_URL="$2"; shift 2 ;;
    --panel-ca-url) PANEL_CA_URL="$2"; shift 2 ;;
    --panel-fingerprint) PANEL_FINGERPRINT="$2"; shift 2 ;;
    --bootstrap-token) BOOTSTRAP_TOKEN="$2"; shift 2 ;;
    --poll-interval) POLL_INTERVAL="$2"; shift 2 ;;
    --singbox-image) SINGBOX_IMAGE="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *)
      error "Неизвестный аргумент: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${LOCAL_REPO_DIR:-}" ]]; then
  prompt REPO_URL "URL git репозитория с mgb-panel" "https://github.com/Beykus-Y/mgb-panel"
fi
prompt PANEL_URL "URL панели" "https://panel.example.com:8443"
prompt BOOTSTRAP_TOKEN "Bootstrap token ноды"
prompt PANEL_FINGERPRINT "SHA-256 fingerprint CA панели"

if [[ -z "$PANEL_CA_URL" ]]; then
  PANEL_CA_URL="${PANEL_URL%/}/api/pki/ca"
fi

REPO_DIR="$INSTALL_DIR/repo"
if [[ -n "${LOCAL_REPO_DIR:-}" ]]; then
  REPO_DIR="$LOCAL_REPO_DIR"
fi
NODE_STATE_DIR="$INSTALL_DIR/state"
BOOTSTRAP_DIR="$INSTALL_DIR/bootstrap"
PANEL_CA_FILE="$BOOTSTRAP_DIR/panel-ca.pem"
ENV_FILE="$INSTALL_DIR/node.env"
COMPOSE_FILE="$REPO_DIR/deploy/node/docker-compose.yml"
EXISTING_ACTION=""

require_cmd git
require_cmd curl
require_cmd openssl
require_cmd sha256sum
require_cmd docker

if ! docker compose version >/dev/null 2>&1; then
  error "Требуется docker compose"
  exit 1
fi

mkdir -p "$INSTALL_DIR" "$NODE_STATE_DIR" "$BOOTSTRAP_DIR"

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
download_ca
write_env

if [[ "$EXISTING_ACTION" == "update" ]]; then
  info "Обновляю node-agent через Docker Compose"
else
  info "Запускаю node-agent через Docker Compose"
fi
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --build

success "Нода установлена"
printf "\n"
printf "Каталог установки: %s\n" "$INSTALL_DIR"
printf "Файл окружения:    %s\n" "$ENV_FILE"
printf "Сертификат CA:     %s\n" "$PANEL_CA_FILE"
printf "Состояние:         docker compose --env-file %s -f %s ps\n" "$ENV_FILE" "$COMPOSE_FILE"
