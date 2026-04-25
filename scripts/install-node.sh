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

has_cmd() {
  command -v "$1" >/dev/null 2>&1
}

run_privileged() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
    return
  fi
  if has_cmd sudo; then
    sudo "$@"
    return
  fi
  error "Нужны root-права или sudo для выполнения: $*"
  exit 1
}

require_https_url() {
  local value="$1"
  case "$value" in
    https://*/*) ;;
    https://*) ;;
    *)
      error "URL панели должен быть абсолютным HTTPS URL, например https://1.2.3.4:8443"
      exit 1
      ;;
  esac
}

prompt() {
  local var_name="$1"
  local label="$2"
  local default_value="${3:-}"
  local current_value="${!var_name:-}"
  local answer

  if [[ -n "$current_value" ]]; then
    return
  fi

  if [[ ! -r /dev/tty ]]; then
    if [[ -n "$default_value" ]]; then
      printf -v "$var_name" "%s" "$default_value"
      return
    fi
    error "Невозможно спросить '$label': нет интерактивного TTY. Передайте значение через аргумент или переменную окружения."
    exit 1
  fi

  if [[ -n "$default_value" ]]; then
    printf "%s [%s]: " "$label" "$default_value" >/dev/tty
    read -r answer </dev/tty || answer=""
    answer="${answer:-$default_value}"
  else
    printf "%s: " "$label" >/dev/tty
    read -r answer </dev/tty || answer=""
  fi
  printf -v "$var_name" "%s" "$answer"
}

prompt_required() {
  local var_name="$1"
  local label="$2"
  local default_value="${3:-}"
  local value
  while true; do
    prompt "$var_name" "$label" "$default_value"
    value="${!var_name:-}"
    if [[ -n "$value" ]]; then
      return
    fi
    error "$label не может быть пустым"
    unset "$var_name"
  done
}

is_sha256_hex() {
  [[ "$1" =~ ^[A-Fa-f0-9]{64}$ ]]
}

is_safe_dir() {
  local dir="$1"
  case "$dir" in
    /|/usr|/usr/local|/etc|/bin|/sbin|/var|/opt|/home|/root) return 1 ;;
    *) return 0 ;;
  esac
}

choose_existing_action() {
  local answer
  printf "Обнаружена существующая установка ноды в %s\n" "$INSTALL_DIR"
  printf "Выберите действие: [u] обновить, [d] удалить, [c] отмена\n"
  printf "Действие [u]: " >/dev/tty
  read -r answer </dev/tty || answer=""
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

detect_local_repo() {
  local script_source="${BASH_SOURCE[0]:-}"
  local script_dir
  if [[ -z "$script_source" ]]; then
    return
  fi
  script_dir="$(cd "$(dirname "$script_source")" && pwd)"
  if [[ -f "$script_dir/../go.mod" && -f "$script_dir/../deploy/node/docker-compose.yml" ]]; then
    LOCAL_REPO_DIR="$(cd "$script_dir/.." && pwd)"
  fi
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
    compose_run --env-file "$ENV_FILE" -f "$COMPOSE_FILE" down --remove-orphans || true
  fi

  if [[ -n "${LOCAL_REPO_DIR:-}" ]]; then
    rm -rf "$NODE_STATE_DIR" "$BOOTSTRAP_DIR" "$ENV_FILE"
    rmdir "$INSTALL_DIR" 2>/dev/null || true
  else
    if is_safe_dir "$INSTALL_DIR"; then
      rm -rf "$INSTALL_DIR"
    else
      error "Сработала защита: каталог $INSTALL_DIR системный и не может быть удален автоматически"
      exit 1
    fi
  fi

  success "Нода удалена"
}

write_env() {
  cat >"$ENV_FILE" <<EOF
NODE_STATE_DIR="${NODE_STATE_DIR}"
PANEL_URL="${PANEL_URL}"
PANEL_CA_FILE="${PANEL_CA_FILE}"
BOOTSTRAP_TOKEN="${BOOTSTRAP_TOKEN}"
PANEL_FINGERPRINT="${PANEL_FINGERPRINT}"
POLL_INTERVAL="${POLL_INTERVAL}"
NODE_IMAGE="${NODE_IMAGE}"
EOF
}

load_existing_env() {
  if [[ ! -f "$ENV_FILE" ]]; then
    return
  fi
  local key value
  while IFS='=' read -r key value; do
    value="${value%\"}"
    value="${value#\"}"
    case "$key" in
      PANEL_URL) if [[ -z "$PANEL_URL" ]]; then PANEL_URL="$value"; fi ;;
      BOOTSTRAP_TOKEN) if [[ -z "$BOOTSTRAP_TOKEN" ]]; then BOOTSTRAP_TOKEN="$value"; fi ;;
      PANEL_FINGERPRINT) if [[ -z "$PANEL_FINGERPRINT" ]]; then PANEL_FINGERPRINT="$value"; fi ;;
      POLL_INTERVAL) if [[ -z "$POLL_INTERVAL" ]]; then POLL_INTERVAL="$value"; fi ;;
      NODE_IMAGE) if [[ -z "$NODE_IMAGE" ]]; then NODE_IMAGE="$value"; fi ;;
    esac
  done <"$ENV_FILE"
}

install_docker_if_missing() {
  if has_cmd docker && (docker compose version >/dev/null 2>&1 || has_cmd docker-compose); then
    return
  fi

  local answer
  printf "Docker Engine или Compose не найдены.\n"
  printf "Установить Docker автоматически через официальный get.docker.com? [Y/n]: " >/dev/tty
  read -r answer </dev/tty || answer=""
  answer="${answer:-Y}"
  case "$answer" in
    n|N|no|нет)
      error "Docker не установлен"
      exit 1
      ;;
  esac

  if ! has_cmd curl; then
    error "Для автоустановки Docker нужен curl"
    exit 1
  fi

  local tmp_script
  tmp_script="$(mktemp)"
  trap 'rm -f "$tmp_script"' EXIT
  info "Скачиваю официальный installer Docker"
  curl -fsSL https://get.docker.com -o "$tmp_script"
  run_privileged sh "$tmp_script"
  rm -f "$tmp_script"
  trap - EXIT

  if has_cmd systemctl; then
    run_privileged systemctl enable --now docker || true
  elif has_cmd service; then
    run_privileged service docker start || true
  fi
}

ensure_docker_running() {
  DOCKER_PREFIX=()
  if docker info >/dev/null 2>&1; then
    return
  fi

  if has_cmd systemctl; then
    run_privileged systemctl start docker || true
  elif has_cmd service; then
    run_privileged service docker start || true
  fi

  if docker info >/dev/null 2>&1; then
    return
  fi

  if has_cmd sudo && sudo docker info >/dev/null 2>&1; then
    DOCKER_PREFIX=("sudo")
    return
  fi

  error "Docker установлен, но недоступен текущему пользователю. Запусти скрипт через sudo или добавь пользователя в группу docker"
  exit 1
}

set_compose_cmd() {
  if "${DOCKER_PREFIX[@]}" docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=("${DOCKER_PREFIX[@]}" "docker" "compose")
    return
  fi
  if has_cmd docker-compose; then
    COMPOSE_CMD=("${DOCKER_PREFIX[@]}" "docker-compose")
    return
  fi
  error "Не найден ни docker compose, ни docker-compose"
  exit 1
}

compose_run() {
  "${COMPOSE_CMD[@]}" "$@"
}

download_ca() {
  if [[ "$CA_MODE" == "manual" ]]; then
    if [[ -z "$PANEL_CA_INLINE" ]]; then
      error "Для ручного режима нужен --panel-ca-inline"
      exit 1
    fi
    printf "%b\n" "$PANEL_CA_INLINE" >"$PANEL_CA_FILE"
    success "CA сертификат сохранён из ручного ввода"
    return
  fi

  info "Скачиваю CA сертификат панели"
  curl -fsSLk -H "X-Panel-CA-Fingerprint: $PANEL_FINGERPRINT" "$PANEL_CA_URL" -o "$PANEL_CA_FILE"

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
  --panel-ca-inline PEM
  --ca-mode auto|manual
  --panel-fingerprint SHA256
  --bootstrap-token TOKEN
  --poll-interval DURATION
  --node-image IMAGE
  --help
EOF
}

REPO_URL="${REPO_URL:-https://github.com/Beykus-Y/mgb-panel}"
REPO_REF="${REPO_REF:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/mgb-node}"
PANEL_URL="${PANEL_URL:-}"
PANEL_CA_URL="${PANEL_CA_URL:-}"
PANEL_CA_INLINE="${PANEL_CA_INLINE:-}"
PANEL_FINGERPRINT="${PANEL_FINGERPRINT:-}"
BOOTSTRAP_TOKEN="${BOOTSTRAP_TOKEN:-}"
POLL_INTERVAL="${POLL_INTERVAL:-}"
NODE_IMAGE="${NODE_IMAGE:-}"
CA_MODE="${CA_MODE:-auto}"
EXISTING_ACTION=""
COMPOSE_CMD=()
DOCKER_PREFIX=()

detect_local_repo

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --repo-ref) REPO_REF="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --panel-url) PANEL_URL="$2"; shift 2 ;;
    --panel-ca-url) PANEL_CA_URL="$2"; shift 2 ;;
    --panel-ca-inline) PANEL_CA_INLINE="$2"; shift 2 ;;
    --ca-mode) CA_MODE="$2"; shift 2 ;;
    --panel-fingerprint) PANEL_FINGERPRINT="$2"; shift 2 ;;
    --bootstrap-token) BOOTSTRAP_TOKEN="$2"; shift 2 ;;
    --poll-interval) POLL_INTERVAL="$2"; shift 2 ;;
    --node-image) NODE_IMAGE="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *)
      error "Неизвестный аргумент: $1"
      usage
      exit 1
      ;;
  esac
done

REPO_DIR="$INSTALL_DIR/repo"
if [[ -n "${LOCAL_REPO_DIR:-}" ]]; then
  REPO_DIR="$LOCAL_REPO_DIR"
fi
NODE_STATE_DIR="$INSTALL_DIR/state"
BOOTSTRAP_DIR="$INSTALL_DIR/bootstrap"
PANEL_CA_FILE="$BOOTSTRAP_DIR/panel-ca.pem"
ENV_FILE="$INSTALL_DIR/node.env"
COMPOSE_FILE="$REPO_DIR/deploy/node/docker-compose.yml"
load_existing_env

if [[ -z "${LOCAL_REPO_DIR:-}" ]]; then
  prompt_required REPO_URL "URL git репозитория с mgb-panel" "https://github.com/Beykus-Y/mgb-panel"
fi
case "$CA_MODE" in
  auto|manual) ;;
  *) error "--ca-mode должен быть auto или manual"; exit 1 ;;
esac
prompt_required PANEL_URL "URL панели" "https://panel.example.com:8443"
require_https_url "$PANEL_URL"
prompt_required BOOTSTRAP_TOKEN "Bootstrap token ноды"

if [[ "$CA_MODE" == "manual" ]]; then
  prompt_required PANEL_CA_INLINE "Вставь PEM сертификат панели. Поддерживаются реальные переводы строк и последовательности \\n"
else
  prompt_required PANEL_FINGERPRINT "SHA-256 fingerprint CA панели"
  if ! is_sha256_hex "$PANEL_FINGERPRINT"; then
    error "Fingerprint CA должен быть SHA-256 hex строкой из 64 символов"
    exit 1
  fi
fi

if [[ -z "$PANEL_CA_URL" ]]; then
  PANEL_CA_URL="${PANEL_URL%/}/api/pki/ca"
fi
if [[ -z "$POLL_INTERVAL" ]]; then
  POLL_INTERVAL="20s"
fi
if [[ -z "$NODE_IMAGE" ]]; then
  NODE_IMAGE="ghcr.io/beykus-y/mgb-panel:node-latest"
fi

if ! has_cmd git; then
  error "Команда 'git' не найдена"
  exit 1
fi
if ! has_cmd curl; then
  error "Команда 'curl' не найдена"
  exit 1
fi
if ! has_cmd openssl; then
  error "Команда 'openssl' не найдена"
  exit 1
fi
if ! has_cmd sha256sum; then
  error "Команда 'sha256sum' не найдена"
  exit 1
fi

install_docker_if_missing
ensure_docker_running
set_compose_cmd

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
compose_run --env-file "$ENV_FILE" -f "$COMPOSE_FILE" pull
compose_run --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d

success "Нода установлена"
printf "\n"
printf "Каталог установки: %s\n" "$INSTALL_DIR"
printf "Файл окружения:    %s\n" "$ENV_FILE"
printf "Сертификат CA:     %s\n" "$PANEL_CA_FILE"
printf "Состояние:         "
printf "%q " "${COMPOSE_CMD[@]}"
printf -- "--env-file %s -f %s ps\n" "$ENV_FILE" "$COMPOSE_FILE"
