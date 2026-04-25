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

prompt_choice() {
  local var_name="$1"
  local label="$2"
  local default_value="$3"
  shift 3
  local value allowed
  while true; do
    prompt "$var_name" "$label" "$default_value"
    value="${!var_name:-}"
    for allowed in "$@"; do
      if [[ "$value" == "$allowed" ]]; then
        return
      fi
    done
    error "Некорректное значение '$value'. Допустимо: $*"
    if [[ "$NON_INTERACTIVE" == "true" ]]; then
      exit 1
    fi
    unset "$var_name"
  done
}

url_host() {
  local value="${1#https://}"
  value="${value%%/*}"
  value="${value%%:*}"
  printf "%s" "$value"
}

is_ip_address() {
  [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ || "$1" =~ ^\[.*\]$ || "$1" == *:* ]]
}

is_local_host() {
  [[ "$1" == "localhost" || "$1" == "127.0.0.1" || "$1" == "::1" ]]
}

is_valid_port() {
  [[ "$1" =~ ^[0-9]+$ ]] && (( "$1" >= 1 && "$1" <= 65535 ))
}

validate_panel_base_url() {
  require_https_url "$PANEL_BASE_URL"
  local host
  host="$(url_host "$PANEL_BASE_URL")"
  if [[ -z "$host" ]]; then
    error "Не удалось определить host из PANEL_BASE_URL=$PANEL_BASE_URL"
    exit 1
  fi
}

default_tls_mode() {
  local host
  host="$(url_host "$PANEL_BASE_URL")"
  if [[ -n "$host" ]] && ! is_ip_address "$host" && ! is_local_host "$host"; then
    printf "letsencrypt"
  else
    printf "internal"
  fi
}

choose_existing_action() {
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    EXISTING_ACTION="update"
    return
  fi

  local answer
  printf "Обнаружена существующая установка панели в %s\n" "$INSTALL_DIR"
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
ADMIN_USER="${ADMIN_USER}"
ADMIN_PASSWORD="${ADMIN_PASSWORD}"
TLS_MODE="${TLS_MODE}"
TLS_CERT_FILE="${TLS_CERT_FILE}"
TLS_KEY_FILE="${TLS_KEY_FILE}"
LETSENCRYPT_DIR="${LETSENCRYPT_DIR}"
TLS_EMAIL="${TLS_EMAIL}"
ENABLE_LOCAL_NODE="${ENABLE_LOCAL_NODE}"
LOCAL_NODE_TOKEN="${LOCAL_NODE_TOKEN}"
LOCAL_NODE_STATE_DIR="${LOCAL_NODE_STATE_DIR}"
LOCAL_NODE_POLL_INTERVAL="${LOCAL_NODE_POLL_INTERVAL}"
PANEL_IMAGE="${PANEL_IMAGE}"
NODE_IMAGE="${NODE_IMAGE}"
EOF
}

load_existing_admin_credentials() {
  if [[ ! -f "$ENV_FILE" ]]; then
    return
  fi
  local key value
  while IFS='=' read -r key value; do
    value="${value%\"}"
    value="${value#\"}"
    case "$key" in
      ADMIN_USER)
        if [[ -z "$ADMIN_USER" ]]; then ADMIN_USER="$value"; fi
        ;;
      ADMIN_PASSWORD)
        if [[ -z "$ADMIN_PASSWORD" ]]; then ADMIN_PASSWORD="$value"; fi
        ;;
    esac
  done <"$ENV_FILE"
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
      ADMIN_USER) if [[ -z "$ADMIN_USER" ]]; then ADMIN_USER="$value"; fi ;;
      ADMIN_PASSWORD) if [[ -z "$ADMIN_PASSWORD" ]]; then ADMIN_PASSWORD="$value"; fi ;;
      PANEL_BASE_URL) if [[ -z "$PANEL_BASE_URL" ]]; then PANEL_BASE_URL="$value"; fi ;;
      PANEL_PORT) if [[ -z "$PANEL_PORT" ]]; then PANEL_PORT="$value"; fi ;;
      TLS_MODE) if [[ -z "$TLS_MODE" ]]; then TLS_MODE="$value"; fi ;;
      TLS_CERT_FILE) if [[ -z "$TLS_CERT_FILE" ]]; then TLS_CERT_FILE="$value"; fi ;;
      TLS_KEY_FILE) if [[ -z "$TLS_KEY_FILE" ]]; then TLS_KEY_FILE="$value"; fi ;;
      LETSENCRYPT_DIR) if [[ -z "$LETSENCRYPT_DIR" ]]; then LETSENCRYPT_DIR="$value"; fi ;;
      TLS_EMAIL) if [[ -z "$TLS_EMAIL" ]]; then TLS_EMAIL="$value"; fi ;;
      ENABLE_LOCAL_NODE) if [[ -z "$ENABLE_LOCAL_NODE" ]]; then ENABLE_LOCAL_NODE="$value"; fi ;;
      LOCAL_NODE_TOKEN) if [[ -z "$LOCAL_NODE_TOKEN" ]]; then LOCAL_NODE_TOKEN="$value"; fi ;;
      LOCAL_NODE_STATE_DIR) if [[ -z "$LOCAL_NODE_STATE_DIR" ]]; then LOCAL_NODE_STATE_DIR="$value"; fi ;;
      LOCAL_NODE_POLL_INTERVAL) if [[ -z "$LOCAL_NODE_POLL_INTERVAL" ]]; then LOCAL_NODE_POLL_INTERVAL="$value"; fi ;;
      PANEL_IMAGE) if [[ -z "$PANEL_IMAGE" ]]; then PANEL_IMAGE="$value"; fi ;;
      NODE_IMAGE) if [[ -z "$NODE_IMAGE" ]]; then NODE_IMAGE="$value"; fi ;;
    esac
  done <"$ENV_FILE"
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
    printf "Установить Docker автоматически через официальный get.docker.com? [Y/n]: " >/dev/tty
    read -r answer </dev/tty || answer=""
    answer="${answer:-Y}"
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

install_certbot_if_missing() {
  if has_cmd certbot; then
    return
  fi
  if ! has_cmd apt-get; then
    error "Для автоматического Let's Encrypt нужен certbot. Установите certbot вручную или выберите TLS_MODE=internal."
    exit 1
  fi
  info "Устанавливаю certbot"
  run_privileged apt-get update
  run_privileged apt-get install -y certbot
}

ensure_letsencrypt_certificate() {
  if [[ "$TLS_MODE" != "letsencrypt" ]]; then
    TLS_CERT_FILE=""
    TLS_KEY_FILE=""
    return
  fi

  local host host_cert_file host_key_file
  local -a email_args
  host="$(url_host "$PANEL_BASE_URL")"
  if [[ -z "$host" || "$host" == *"/"* || "$host" == *"_"* || "$host" != *"."* ]] || is_ip_address "$host" || is_local_host "$host"; then
    error "Let's Encrypt работает только с публичным доменом. Сейчас host: $host"
    error "Используйте домен вида panel.example.com или выберите TLS_MODE=internal."
    exit 1
  fi

  if [[ "$PANEL_BASE_URL" == *":8443"* ]]; then
    warn "Сертификат будет доверенным, но браузер все равно откроет панель с портом :8443. Для обычного URL используйте --panel-port 443 и PANEL_BASE_URL без :8443."
  fi

  install_certbot_if_missing
  LETSENCRYPT_DIR="${LETSENCRYPT_DIR:-/etc/letsencrypt}"
  host_cert_file="$LETSENCRYPT_DIR/live/$host/fullchain.pem"
  host_key_file="$LETSENCRYPT_DIR/live/$host/privkey.pem"
  TLS_CERT_FILE="/etc/letsencrypt/live/$host/fullchain.pem"
  TLS_KEY_FILE="/etc/letsencrypt/live/$host/privkey.pem"

  if [[ -f "$host_cert_file" && -f "$host_key_file" ]]; then
    info "Использую существующий Let's Encrypt сертификат для $host"
  else
    warn "Для выпуска Let's Encrypt сертификата домен $host должен указывать на этот VPS, а порт 80 должен быть открыт и свободен."
    if [[ -n "$TLS_EMAIL" ]]; then
      email_args=(--email "$TLS_EMAIL")
    else
      email_args=(--register-unsafely-without-email)
    fi
    mkdir -p "$INSTALL_DIR/certbot-work" "$INSTALL_DIR/certbot-logs"
    run_privileged certbot certonly --standalone --non-interactive --agree-tos --config-dir "$LETSENCRYPT_DIR" --work-dir "$INSTALL_DIR/certbot-work" --logs-dir "$INSTALL_DIR/certbot-logs" "${email_args[@]}" -d "$host"
  fi

  if [[ ! -f "$host_cert_file" || ! -f "$host_key_file" ]]; then
    error "Сертификат Let's Encrypt не найден после выпуска: $host_cert_file"
    exit 1
  fi
  install_renew_hook
}

install_renew_hook() {
  local hook_dir hook_file
  hook_dir="${LETSENCRYPT_DIR:-/etc/letsencrypt}/renewal-hooks/deploy"
  hook_file="$hook_dir/mgb-panel-restart.sh"
  run_privileged mkdir -p "$hook_dir"
  run_privileged tee "$hook_file" >/dev/null <<EOF
#!/usr/bin/env bash
set -euo pipefail
if command -v docker >/dev/null 2>&1; then
  docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" restart panel >/dev/null 2>&1 || true
fi
EOF
  run_privileged chmod 0755 "$hook_file"
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
  --admin-user USER            Логин администратора (по умолч. admin)
  --admin-password PASSWORD    Пароль администратора
  --tls-mode internal|letsencrypt
  --tls-email EMAIL            Email для Let's Encrypt (необязательно)
  --letsencrypt-dir PATH       Каталог Let's Encrypt на хосте
  --enable-local-node true/false
  --local-node-token TOKEN
  --local-node-state-dir PATH
  --local-node-poll-interval DURATION
  --panel-image IMAGE
  --node-image IMAGE
  --help, -h                   Показать эту справку
EOF
}

REPO_URL="${REPO_URL:-https://github.com/Beykus-Y/mgb-panel}"
REPO_REF="${REPO_REF:-main}"
INSTALL_DIR="${INSTALL_DIR:-/opt/mgb-panel}"
PANEL_BASE_URL="${PANEL_BASE_URL:-}"
PANEL_PORT="${PANEL_PORT:-}"
ADMIN_USER="${ADMIN_USER:-}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"
ADMIN_PASSWORD_WAS_GENERATED="false"
TLS_MODE="${TLS_MODE:-}"
TLS_EMAIL="${TLS_EMAIL:-}"
TLS_CERT_FILE="${TLS_CERT_FILE:-}"
TLS_KEY_FILE="${TLS_KEY_FILE:-}"
LETSENCRYPT_DIR="${LETSENCRYPT_DIR:-}"
ENABLE_LOCAL_NODE="${ENABLE_LOCAL_NODE:-}"
LOCAL_NODE_TOKEN="${LOCAL_NODE_TOKEN:-}"
LOCAL_NODE_STATE_DIR="${LOCAL_NODE_STATE_DIR:-}"
LOCAL_NODE_POLL_INTERVAL="${LOCAL_NODE_POLL_INTERVAL:-}"
PANEL_IMAGE="${PANEL_IMAGE:-}"
NODE_IMAGE="${NODE_IMAGE:-}"
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
    --admin-user) ADMIN_USER="$2"; shift 2 ;;
    --admin-password) ADMIN_PASSWORD="$2"; shift 2 ;;
    --tls-mode) TLS_MODE="$2"; shift 2 ;;
    --tls-email) TLS_EMAIL="$2"; shift 2 ;;
    --letsencrypt-dir) LETSENCRYPT_DIR="$2"; shift 2 ;;
    --enable-local-node) ENABLE_LOCAL_NODE="$2"; shift 2 ;;
    --local-node-token) LOCAL_NODE_TOKEN="$2"; shift 2 ;;
    --local-node-state-dir) LOCAL_NODE_STATE_DIR="$2"; shift 2 ;;
    --local-node-poll-interval) LOCAL_NODE_POLL_INTERVAL="$2"; shift 2 ;;
    --panel-image) PANEL_IMAGE="$2"; shift 2 ;;
    --node-image) NODE_IMAGE="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) error "Неизвестный аргумент: $1"; usage; exit 1 ;;
  esac
done

REPO_DIR="$INSTALL_DIR/repo"
if [[ -n "${LOCAL_REPO_DIR:-}" ]]; then
  REPO_DIR="$LOCAL_REPO_DIR"
fi
PANEL_STATE_DIR="$INSTALL_DIR/state"
ENV_FILE="$INSTALL_DIR/panel.env"
COMPOSE_FILE="$REPO_DIR/deploy/panel/docker-compose.yml"
load_existing_env

if [[ -z "${LOCAL_REPO_DIR:-}" ]]; then
  prompt_required REPO_URL "URL git репозитория с mgb-panel" "https://github.com/Beykus-Y/mgb-panel"
fi
prompt_required PANEL_PORT "Порт панели на VPS" "8443"
if ! is_valid_port "$PANEL_PORT"; then
  error "Некорректный порт панели: $PANEL_PORT"
  exit 1
fi
if [[ "$NON_INTERACTIVE" == "true" && -z "$PANEL_BASE_URL" ]]; then
  error "В non-interactive режиме обязательно передайте --panel-base-url"
  exit 1
fi
prompt_required PANEL_BASE_URL "Публичный HTTPS URL панели" "https://panel.example.com:$PANEL_PORT"
validate_panel_base_url
if [[ -z "$LOCAL_NODE_STATE_DIR" ]]; then
  LOCAL_NODE_STATE_DIR="$INSTALL_DIR/local-node-state"
fi
if [[ -z "$LETSENCRYPT_DIR" ]]; then
  LETSENCRYPT_DIR="/etc/letsencrypt"
fi
if [[ -z "$ENABLE_LOCAL_NODE" ]]; then
  ENABLE_LOCAL_NODE="false"
fi
if [[ -z "$LOCAL_NODE_POLL_INTERVAL" ]]; then
  LOCAL_NODE_POLL_INTERVAL="20s"
fi
if [[ -z "$PANEL_IMAGE" ]]; then
  PANEL_IMAGE="ghcr.io/beykus-y/mgb-panel:panel-latest"
fi
if [[ -z "$NODE_IMAGE" ]]; then
  NODE_IMAGE="ghcr.io/beykus-y/mgb-panel:node-latest"
fi
if [[ -z "$TLS_MODE" ]]; then
  TLS_MODE="$(default_tls_mode)"
fi
prompt_choice TLS_MODE "TLS сертификат панели: internal = встроенный CA, letsencrypt = доверенный браузером" "$TLS_MODE" internal letsencrypt
if [[ "$TLS_MODE" == "letsencrypt" ]]; then
  prompt TLS_EMAIL "Email для Let's Encrypt (можно оставить пустым)" "$TLS_EMAIL"
fi
prompt_required ADMIN_USER "Логин администратора" "admin"
if [[ -z "$ADMIN_PASSWORD" ]]; then
  GENERATED_ADMIN_PASSWORD="$(generate_token)"
  if [[ "$NON_INTERACTIVE" == "true" ]]; then
    ADMIN_PASSWORD="$GENERATED_ADMIN_PASSWORD"
    ADMIN_PASSWORD_WAS_GENERATED="true"
  else
    prompt ADMIN_PASSWORD "Пароль администратора" "$GENERATED_ADMIN_PASSWORD"
    if [[ "$ADMIN_PASSWORD" == "$GENERATED_ADMIN_PASSWORD" ]]; then
      ADMIN_PASSWORD_WAS_GENERATED="true"
    fi
  fi
fi

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

ensure_letsencrypt_certificate
ensure_repo
write_env

if [[ "$EXISTING_ACTION" == "update" ]]; then
  info "Обновляю панель через Docker Compose"
else
  info "Запускаю панель через Docker Compose"
fi

# Поднимаем контейнеры. local-node стартует отдельно от панели и ждёт включения из UI.
compose_run --env-file "$ENV_FILE" -f "$COMPOSE_FILE" pull
compose_run --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d

success "Панель успешно установлена и запущена!"
printf "\n"
printf "Каталог установки: %s\n" "$INSTALL_DIR"
printf "Файл окружения:    %s\n" "$ENV_FILE"
printf "Логин админки:     %s\n" "$ADMIN_USER"
printf "TLS режим:         %s\n" "$TLS_MODE"
if [[ "$TLS_MODE" == "letsencrypt" ]]; then
  printf "TLS сертификат:    %s\n" "$TLS_CERT_FILE"
fi
if [[ "$ADMIN_PASSWORD_WAS_GENERATED" == "true" ]]; then
  printf "Пароль админки:    %s\n" "$ADMIN_PASSWORD"
fi
printf "Открыть панель:    %s\n" "$PANEL_BASE_URL"
