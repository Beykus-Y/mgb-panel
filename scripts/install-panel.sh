#!/usr/bin/env bash
set -euo pipefail

# === ОПРЕДЕЛЕНИЕ ЦВЕТОВ (отключаются при записи в файл) ===
if [ -t 1 ]; then
  COLOR_RESET="\033[0m"
  COLOR_BLUE="\033[1;34m"
  COLOR_GREEN="\033[1;32m"
  COLOR_RED="\033[1;31m"
  COLOR_YELLOW="\033[1;33m"
else
  COLOR_RESET="" COLOR_BLUE="" COLOR_GREEN="" COLOR_RED="" COLOR_YELLOW=""
fi

# === ФУНКЦИИ ЛОГИРОВАНИЯ ===
info()    { printf "%b[INFO]%b %s\n" "$COLOR_BLUE" "$COLOR_RESET" "$*"; }
warn()    { printf "%b[WARN]%b %s\n" "$COLOR_YELLOW" "$COLOR_RESET" "$*"; }
error()   { printf "%b[ERR ]%b %s\n" "$COLOR_RED" "$COLOR_RESET" "$*" >&2; }
success() { printf "%b[ OK ]%b %s\n" "$COLOR_GREEN" "$COLOR_RESET" "$*"; }

# === УТИЛИТЫ ===
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

generate_token() {
  if has_cmd openssl; then
    openssl rand -hex 24
    return
  fi
  od -An -N24 -tx1 /dev/urandom | tr -d ' \n'
}

require_https_url() {
  local value="$1"
  case "$value" in
    https://*/*) ;;
    https://*) ;;
    *)
      error "Публичный URL панели должен быть абсолютным HTTPS URL, например https://1.2.3.4:8443"
      exit 1
      ;;
  esac
}

# Защита от случайного удаления системных директорий
is_safe_dir() {
  local dir="$1"
  case "$dir" in
    /|/usr|/usr/local|/etc|/bin|/sbin|/var|/opt|/home|/root) return 1 ;;
    *) return 0 ;;
  esac
}

# === ВВОД ДАННЫХ ===
# Исправлено: чтение из /dev/tty позволяет вводить данные, даже если скрипт запущен через "curl | bash"
prompt() {
  local var_name="$1"
  local label="$2"
  local default_value="${3:-}"
  local current_value="${!var_name:-}"
  local answer

  if [[ -n "$current_value" ]] || [[ "$NON_INTERACTIVE" == "true" ]]; then
    if [[ -z "$current_value" && -n "$default_value" ]]; then
      printf -v "$var_name" "%s" "$default_value"
    fi
    return
  fi

  if [[ -n "$default_value" ]]; then
    if read -r -p "$label [$default_value]: " answer </dev/tty 2>/dev/null; then
      answer="${answer:-$default_value}"
    else
      answer="$default_value"
    fi
  else
    if read -r -p "$label: " answer </dev/tty 2>/dev/null; then
      :
    else
      answer=""
    fi
  fi
  printf -v "$var_name" "%s" "$answer"
}

choose_existing_action() {
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    EXISTING_ACTION="update"
    return
  fi

  local answer
  printf "Обнаружена существующая установка панели в %s\n" "$INSTALL_DIR"
  printf "Выберите действие: [u] обновить, [d] удалить, [c] отмена\n"
  if read -r -p "Действие [u]: " answer </dev/tty 2>/dev/null; then
    answer="${answer:-u}"
  else
    answer="u"
  fi

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
  # Исправлено: поддержка симлинков
  local script_source
  if has_cmd realpath; then
    script_source="$(realpath "${BASH_SOURCE[0]:-}")"
  else
    script_source="${BASH_SOURCE[0]:-}"
  fi

  local script_dir
  if [[ -n "$script_source" ]]; then
    script_dir="$(cd "$(dirname "$script_source")" && pwd)"
    if [[ -f "$script_dir/../go.mod" && -f "$script_dir/../deploy/panel/docker-compose.yml" ]]; then
      LOCAL_REPO_DIR="$(cd "$script_dir/.." && pwd)"
    fi
  fi
}

# === GIT & РЕПОЗИТОРИЙ ===
ensure_repo() {
  if [[ -n "${LOCAL_REPO_DIR:-}" ]]; then
    REPO_DIR="$LOCAL_REPO_DIR"
    info "Использую локальный репозиторий $REPO_DIR"
    return
  fi

  if [[ -d "$REPO_DIR/.git" ]]; then
    info "Синхронизирую репозиторий в $REPO_DIR"
    # Исправлено: reset --hard предотвращает ошибки при случайном изменении файлов локально
    git -C "$REPO_DIR" fetch --all --tags
    if git -C "$REPO_DIR" rev-parse "origin/$REPO_REF" >/dev/null 2>&1; then
      git -C "$REPO_DIR" reset --hard "origin/$REPO_REF"
    else
      git -C "$REPO_DIR" reset --hard "$REPO_REF"
    fi
    return
  fi

  # Создаем родительскую директорию, если её нет
  mkdir -p "$(dirname "$REPO_DIR")"
  info "Клонирую репозиторий $REPO_URL (ветка $REPO_REF)"
  git clone -b "$REPO_REF" "$REPO_URL" "$REPO_DIR" || {
    warn "Не удалось склонировать ветку, делаю полный клон и чекаут..."
    git clone "$REPO_URL" "$REPO_DIR"
    git -C "$REPO_DIR" checkout "$REPO_REF"
  }
}

# === УПРАВЛЕНИЕ УСТАНОВКОЙ ===
has_existing_install() {
  [[ -f "$ENV_FILE" || -d "$PANEL_STATE_DIR" || ( -z "${LOCAL_REPO_DIR:-}" && -d "$REPO_DIR/.git" ) ]]
}

delete_install() {
  if [[ -f "$ENV_FILE" && -f "$COMPOSE_FILE" ]]; then
    info "Останавливаю текущую панель и удаляю контейнеры..."
    # Исправлено: добавлен флаг -v для очистки volume'ов базы данных (по желанию)
    compose_run --env-file "$ENV_FILE" -f "$COMPOSE_FILE" down -v --remove-orphans || true
  fi

  if [[ -n "${LOCAL_REPO_DIR:-}" ]]; then
    rm -rf "$PANEL_STATE_DIR" "$ENV_FILE"
    rmdir "$INSTALL_DIR" 2>/dev/null || true
  else
    # Исправлено: защита от rm -rf /
    if is_safe_dir "$INSTALL_DIR"; then
      rm -rf "$INSTALL_DIR"
    else
      error "Сработала защита: каталог $INSTALL_DIR системный и не может быть удален автоматически!"
      exit 1
    fi
  fi

  success "Панель удалена"
}

write_env() {
  # Исправлено: переменные взяты в кавычки во избежание инъекций и ошибок парсинга
  cat >"$ENV_FILE" <<EOF
PANEL_PORT="${PANEL_PORT}"
PANEL_BASE_URL="${PANEL_BASE_URL}"
PANEL_STATE_DIR="${PANEL_STATE_DIR}"
ENABLE_LOCAL_NODE="${ENABLE_LOCAL_NODE}"
LOCAL_NODE_TOKEN="${LOCAL_NODE_TOKEN}"
LOCAL_NODE_STATE_DIR="${LOCAL_NODE_STATE_DIR}"
LOCAL_NODE_POLL_INTERVAL="${LOCAL_NODE_POLL_INTERVAL}"
SINGBOX_IMAGE="${SINGBOX_IMAGE}"
SINGBOX_BINARY_PATH="${SINGBOX_BINARY_PATH}"
EOF
}

# === DOCKER ===
install_docker_if_missing() {
  if has_cmd docker && (docker compose version >/dev/null 2>&1 || has_cmd docker-compose); then
    return
  fi

  local answer
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    answer="y"
  else
    printf "Docker Engine или Compose не найдены.\n"
    if read -r -p "Установить Docker автоматически через официальный get.docker.com?[Y/n]: " answer </dev/tty 2>/dev/null; then
      answer="${answer:-Y}"
    else
      answer="Y"
    fi
  fi

  case "$answer" in
    n|N|no|нет)
      error "Docker не установлен. Установка прервана."
      exit 1
      ;;
  esac

  if ! has_cmd curl; then
    error "Для автоустановки Docker нужен curl"
    exit 1
  fi

  local tmp_script
  tmp_script="$(mktemp)"
  info "Скачиваю официальный installer Docker..."
  
  # Исправлено: безопасное скачивание скрипта
  if ! curl -fsSL https://get.docker.com -o "$tmp_script"; then
    error "Не удалось скачать установочный скрипт Docker."
    rm -f "$tmp_script"
    exit 1
  fi

  info "Запускаю установку Docker..."
  run_privileged sh "$tmp_script"
  rm -f "$tmp_script"

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

  info "Запуск службы Docker..."
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

  error "Docker установлен, но недоступен текущему пользователю. Запусти скрипт через sudo или добавь пользователя в группу docker."
  exit 1
}

set_compose_cmd() {
  # Исправлено: приоритет Docker Compose V2, который корректно читает сложные конструкции .env
  if "${DOCKER_PREFIX[@]}" docker compose version >/dev/null 2>&1; then
    COMPOSE_CMD=("${DOCKER_PREFIX[@]}" "docker" "compose")
    return
  fi
  if has_cmd docker-compose; then
    warn "Используется устаревшая версия docker-compose (V1)."
    warn "Из-за этого возможна ошибка 'Invalid interpolation format' при чтении docker-compose.yml."
    warn "Рекомендуется обновить Docker Engine."
    COMPOSE_CMD=("${DOCKER_PREFIX[@]}" "docker-compose")
    return
  fi
  error "Не найден ни docker compose, ни docker-compose. Установите Docker Compose."
  exit 1
}

compose_run() {
  "${COMPOSE_CMD[@]}" "$@"
}

# === АРГУМЕНТЫ И MAIN ===
usage() {
  cat <<'EOF'
Использование:
  ./install-panel.sh [опции]

Опции:
  -y, --non-interactive        Не задавать вопросы, использовать дефолтные значения
  --repo-url URL               URL git репозитория
  --repo-ref REF               Ветка или тег репозитория
  --install-dir PATH           Папка установки (по умолч. /opt/mgb-panel)
  --panel-base-url URL         Публичный URL панели
  --panel-port PORT            Порт панели (по умолч. 8443)
  --enable-local-node true/false
  --local-node-token TOKEN
  --local-node-state-dir PATH
  --local-node-poll-interval DURATION
  --singbox-image IMAGE
  --help, -h                   Показать эту справку
EOF
}

REPO_URL="${REPO_URL:-https://github.com/Beykus-Y/mgb-panel}"
REPO_REF="${REPO_REF:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/mgb-panel}"
PANEL_BASE_URL="${PANEL_BASE_URL:-}"
PANEL_PORT="${PANEL_PORT:-8443}"
ENABLE_LOCAL_NODE="${ENABLE_LOCAL_NODE:-false}"
LOCAL_NODE_TOKEN="${LOCAL_NODE_TOKEN:-}"
LOCAL_NODE_STATE_DIR="${LOCAL_NODE_STATE_DIR:-}"
LOCAL_NODE_POLL_INTERVAL="${LOCAL_NODE_POLL_INTERVAL:-20s}"
SINGBOX_IMAGE="${SINGBOX_IMAGE:-ghcr.io/sagernet/sing-box:v1.13.11}"
SINGBOX_BINARY_PATH="${SINGBOX_BINARY_PATH:-/usr/local/bin/sing-box}"
NON_INTERACTIVE="false"
EXISTING_ACTION=""
COMPOSE_CMD=()
DOCKER_PREFIX=()

detect_local_repo

while [[ $# -gt 0 ]]; do
  case "$1" in
    -y|--non-interactive) NON_INTERACTIVE="true"; shift 1 ;;
    --repo-url) REPO_URL="$2"; shift 2 ;;
    --repo-ref) REPO_REF="$2"; shift 2 ;;
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --panel-base-url) PANEL_BASE_URL="$2"; shift 2 ;;
    --panel-port) PANEL_PORT="$2"; shift 2 ;;
    --enable-local-node) ENABLE_LOCAL_NODE="$2"; shift 2 ;;
    --local-node-token) LOCAL_NODE_TOKEN="$2"; shift 2 ;;
    --local-node-state-dir) LOCAL_NODE_STATE_DIR="$2"; shift 2 ;;
    --local-node-poll-interval) LOCAL_NODE_POLL_INTERVAL="$2"; shift 2 ;;
    --singbox-image) SINGBOX_IMAGE="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) error "Неизвестный аргумент: $1"; usage; exit 1 ;;
  esac
done

if [[ -z "${LOCAL_REPO_DIR:-}" ]]; then
  prompt REPO_URL "URL git репозитория с mgb-panel" "https://github.com/Beykus-Y/mgb-panel"
fi
prompt PANEL_BASE_URL "Публичный URL панели" "https://panel.example.com:$PANEL_PORT"
require_https_url "$PANEL_BASE_URL"

REPO_DIR="$INSTALL_DIR/repo"
if [[ -n "${LOCAL_REPO_DIR:-}" ]]; then
  REPO_DIR="$LOCAL_REPO_DIR"
fi
PANEL_STATE_DIR="$INSTALL_DIR/state"
if [[ -z "$LOCAL_NODE_STATE_DIR" ]]; then
  LOCAL_NODE_STATE_DIR="$INSTALL_DIR/local-node-state"
fi
ENV_FILE="$INSTALL_DIR/panel.env"
COMPOSE_FILE="$REPO_DIR/deploy/panel/docker-compose.yml"

if ! has_cmd git; then
  error "Команда 'git' не найдена. Установите git: sudo apt install git"
  exit 1
fi

install_docker_if_missing
ensure_docker_running
set_compose_cmd

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

mkdir -p "$INSTALL_DIR" "$PANEL_STATE_DIR"
chmod 755 "$PANEL_STATE_DIR"

if [[ "$ENABLE_LOCAL_NODE" == "true" && -z "$LOCAL_NODE_TOKEN" ]]; then
  LOCAL_NODE_TOKEN="$(generate_token)"
  info "Сгенерирован bootstrap token для локального node-agent контейнера"
fi

ensure_repo
write_env

if [[ "$EXISTING_ACTION" == "update" ]]; then
  info "Обновляю панель через Docker Compose"
else
  info "Запускаю панель через Docker Compose"
fi

# Поднимаем контейнеры. local-node стартует отдельно от панели и ждёт включения из UI.
compose_run --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --build

success "Панель успешно установлена и запущена!"
printf "\n"
printf "Каталог установки: %s\n" "$INSTALL_DIR"
printf "Файл окружения:    %s\n" "$ENV_FILE"
printf "Открыть панель:    %s\n" "$PANEL_BASE_URL"
