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
  [[ -f "$ENV_FILE" || -d "$NODE_STATE_DIR" || -d "$BOOTSTRAP_DIR" || -d "$REPO_DIR" ]]
}

delete_install() {
  if [[ -f "$ENV_FILE" && -f "$COMPOSE_FILE" ]]; then
    info "Останавливаю текущую ноду"
    compose_run --env-file "$ENV_FILE" -f "$COMPOSE_FILE" down --remove-orphans || true
  fi
  rm -rf "$INSTALL_DIR"
  success "Нода удалена"
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

install_docker_if_missing() {
  if has_cmd docker && (docker compose version >/dev/null 2>&1 || has_cmd docker-compose); then
    return
  fi

  local answer
  printf "Docker Engine или Compose не найдены.\n"
  read -r -p "Установить Docker автоматически через официальный get.docker.com? [Y/n]: " answer
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
  if docker info >/dev/null 2>&1; then
    return
  fi

  if has_cmd systemctl; then
    run_privileged systemctl start docker || true
  elif has_cmd service; then
    run_privileged service docker start || true
  fi

  if ! docker info >/dev/null 2>&1; then
    error "Docker установлен, но демон недоступен. Проверь service docker status"
    exit 1
  fi
}

set_compose_cmd() {
  if docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=("docker" "compose")
    return
  fi
  if has_cmd docker-compose; then
    COMPOSE_CMD=("docker-compose")
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
    printf "%s\n" "$PANEL_CA_INLINE" >"$PANEL_CA_FILE"
    success "CA сертификат сохранён из ручного ввода"
    return
  fi

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

usage() {
  cat <<'EOF'
Использование:
  curl -fsSL https://your-panel.example.com/install/node.sh | bash -s -- [опции]

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
  --singbox-image IMAGE
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
POLL_INTERVAL="${POLL_INTERVAL:-20s}"
SINGBOX_IMAGE="${SINGBOX_IMAGE:-ghcr.io/sagernet/sing-box:v1.13.11}"
SINGBOX_BINARY_PATH="${SINGBOX_BINARY_PATH:-/usr/local/bin/sing-box}"
CA_MODE="${CA_MODE:-auto}"
EXISTING_ACTION=""
COMPOSE_CMD=()

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
prompt PANEL_URL "URL панели" "https://panel.example.com:8443"
prompt BOOTSTRAP_TOKEN "Bootstrap token ноды"

if [[ "$CA_MODE" == "manual" ]]; then
  prompt PANEL_CA_INLINE "Вставь PEM сертификат панели одной строкой с \\n или через переменную PANEL_CA_INLINE"
else
  prompt PANEL_FINGERPRINT "SHA-256 fingerprint CA панели"
fi

if [[ -z "$PANEL_CA_URL" ]]; then
  PANEL_CA_URL="${PANEL_URL%/}/api/pki/ca"
fi

REPO_DIR="$INSTALL_DIR/repo"
NODE_STATE_DIR="$INSTALL_DIR/state"
BOOTSTRAP_DIR="$INSTALL_DIR/bootstrap"
PANEL_CA_FILE="$BOOTSTRAP_DIR/panel-ca.pem"
ENV_FILE="$INSTALL_DIR/node.env"
COMPOSE_FILE="$REPO_DIR/deploy/node/docker-compose.yml"

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
compose_run --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --build

success "Нода установлена"
printf "\n"
printf "Каталог установки: %s\n" "$INSTALL_DIR"
printf "Файл окружения:    %s\n" "$ENV_FILE"
printf "Сертификат CA:     %s\n" "$PANEL_CA_FILE"
printf "Состояние:         "
printf "%q " "${COMPOSE_CMD[@]}"
printf -- "--env-file %s -f %s ps\n" "$ENV_FILE" "$COMPOSE_FILE"
