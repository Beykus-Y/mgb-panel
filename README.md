# mgb-panel

`mgb-panel` - панель управления `sing-box` нодами и подписками. Проект состоит из двух ролей:

- `panel` - HTTPS админ-панель, JSON API, пользовательский портал, PKI/CA и компилятор конфигов `sing-box`.
- `node-agent` - агент на VPS-ноде, который регистрируется в панели, получает конфиг по mTLS, проверяет его через `sing-box check` и применяет с откатом на последний рабочий конфиг.

## Статус готовности

Проект можно разворачивать на VPS для тестового стенда, пилота или закрытого использования. Для публичного production-деплоя все равно нужна стандартная внешняя защита: firewall, бэкапы и контроль доступа к VPS.

Админская панель, формы `/admin/*` и `/api/admin/*` защищены Basic Auth. Node API защищен отдельно: enroll требует bootstrap token, а heartbeat/config/ack работают через mTLS клиентский сертификат ноды. `/api/pki/ca` отдает CA только при admin Basic Auth или при передаче ожидаемого CA fingerprint.

Минимальный безопасный вариант перед публичным использованием:

- закрыть порт панели firewall'ом и разрешить доступ только со своего IP/VPN;
- либо поставить панель за reverse proxy, OAuth2 Proxy, Authelia, Tailscale, WireGuard или другим внешним доступом;
- регулярно бэкапить каталог состояния панели, потому что там SQLite-база и CA-ключи;
- перед выдачей пользователям проверить, что сгенерированные `sing-box` конфиги проходят `sing-box check` на реальной ноде.

## Что уже реализовано

- SQLite-хранилище для нод, пользователей, подписок, inbound-профилей, bindings, topology links, config revisions и audit events.
- Самостоятельная PKI: панель генерирует CA и TLS-сертификат сервера.
- Basic Auth для админки, `/admin/*` и `/api/admin/*`.
- Регистрация нод через bootstrap token, CSR и выпуск клиентского сертификата.
- Дальнейшая связь ноды с панелью через mTLS.
- Серверная админка на русском языке.
- Пользовательский портал и plain-text subscription feed по токену подписки.
- Компилятор конфигов `sing-box` для `vless`, `trojan`, `hysteria2`, `shadowsocks` и WireGuard-oriented topology.
- `node-agent` с heartbeat, загрузкой конфига, `sing-box check`, staged apply и rollback.
- Docker Compose профили для панели и отдельной ноды.

## Структура репозитория

```text
cmd/panel                 точка входа панели
cmd/node-agent            точка входа агента ноды
internal/controlplane     HTTP UI/API панели
internal/database         SQLite store и миграции
internal/nodeagent        логика node-agent
internal/pki              CA, TLS и mTLS
internal/singbox          запуск, проверка и откат sing-box
internal/subscriptions    рендер подписок
internal/topology         WireGuard/topology compiler
deploy/panel              Docker Compose для панели
deploy/node               Docker Compose для ноды
scripts                   install scripts для VPS
```

## Требования

Для VPS-деплоя:

- Linux VPS, лучше Ubuntu/Debian.
- Root-доступ или пользователь с `sudo`.
- Открытые нужные порты в firewall/security group.
- `git`, `curl`, `openssl`, `sha256sum`.
- Docker Engine и Docker Compose V2. Скрипты могут предложить установить Docker автоматически через `get.docker.com`.

Для локальной разработки:

- Go 1.22+.
- `sing-box` в `PATH`, если нужно запускать `node-agent` без Docker.

## Быстрый деплой панели на VPS

На VPS, где будет работать панель:

```bash
curl -fsSL https://raw.githubusercontent.com/Beykus-Y/mgb-panel/main/scripts/install-panel.sh -o install-panel.sh
chmod +x install-panel.sh
sudo ./install-panel.sh
```

Скрипт спросит:

- URL git-репозитория, если скрипт запущен не из локального checkout'а.
- Публичный HTTPS URL панели, например `https://panel.example.com:8443` или `https://1.2.3.4:8443`.
- Порт панели, по умолчанию `8443`.
- Логин и пароль администратора. Если пароль не указан, установщик сгенерирует его и сохранит в `/opt/mgb-panel/panel.env`.
- Нужно ли включать локальную ноду в том же compose-профиле.

После установки:

```bash
cd /opt/mgb-panel/repo/deploy/panel
sudo docker compose --env-file /opt/mgb-panel/panel.env -f docker-compose.yml ps
sudo docker compose --env-file /opt/mgb-panel/panel.env -f docker-compose.yml logs -f panel
```

Откройте панель по URL, который указали в `PANEL_BASE_URL`.

Важно: панель использует собственный CA и self-signed TLS-сертификат. Браузер может показывать предупреждение о сертификате. Для нод это нормально: они проверяют CA по fingerprint или CA-файлу.

## Настройка firewall для панели

Если панель открывается напрямую, минимум откройте порт панели:

```bash
sudo ufw allow 8443/tcp
sudo ufw enable
sudo ufw status
```

Для реального использования лучше ограничить доступ к панели только вашим IP:

```bash
sudo ufw allow from YOUR_IP to any port 8443 proto tcp
```

Если используется reverse proxy, наружу можно открыть только `80/443`, а порт `8443` оставить доступным локально или только из proxy-сети.

## Деплой ноды на отдельной VPS

1. В админке панели создайте ноду.
2. Скопируйте `enroll_token` / `bootstrap token` ноды.
3. Скопируйте SHA-256 fingerprint CA панели. Он отображается в админке и также возвращается при enroll.
4. На VPS-ноды запустите установщик:

```bash
curl -fsSL https://raw.githubusercontent.com/Beykus-Y/mgb-panel/main/scripts/install-node.sh -o install-node.sh
chmod +x install-node.sh
sudo ./install-node.sh
```

Скрипт спросит:

- URL git-репозитория.
- URL панели, например `https://panel.example.com:8443`.
- Bootstrap token ноды.
- SHA-256 fingerprint CA панели.

После установки проверьте контейнер и логи:

```bash
cd /opt/mgb-node/repo/deploy/node
sudo docker compose --env-file /opt/mgb-node/node.env -f docker-compose.yml ps
sudo docker compose --env-file /opt/mgb-node/node.env -f docker-compose.yml logs -f node
```

`node-agent` использует `network_mode: host` и capability `NET_ADMIN`, потому что `sing-box` на ноде обычно должен напрямую управлять сетевыми интерфейсами и слушать публичные порты.

## Установка ноды через скрипт из панели

Когда панель уже запущена, она отдает install script сама:

```bash
curl -fsSLk https://your-panel.example.com:8443/install/node.sh -o install-node.sh
chmod +x install-node.sh
sudo ./install-node.sh
```

`-k` нужен только потому, что панель использует собственный CA, которому обычный `curl` не доверяет.

## Non-interactive установка панели

Пример для автоматизации:

```bash
sudo ./scripts/install-panel.sh \
  --non-interactive \
  --repo-url https://github.com/Beykus-Y/mgb-panel \
  --repo-ref main \
  --install-dir /opt/mgb-panel \
  --panel-base-url https://panel.example.com:8443 \
  --panel-port 8443 \
  --admin-user admin \
  --admin-password CHANGE_ME_STRONG_PASSWORD
```

Для локальной ноды в compose панели:

```bash
sudo ./scripts/install-panel.sh \
  --non-interactive \
  --panel-base-url https://panel.example.com:8443 \
  --enable-local-node true \
  --local-node-token CHANGE_ME_RANDOM_TOKEN
```

## Ручной запуск через Docker Compose

Панель:

```bash
cd deploy/panel
cp .env.example .env
```

Отредактируйте `.env`:

```env
PANEL_PORT=8443
PANEL_BASE_URL=https://panel.example.com:8443
PANEL_STATE_DIR=./state/panel
ADMIN_USER=admin
ADMIN_PASSWORD=change-me-strong-password
ENABLE_LOCAL_NODE=false
LOCAL_NODE_TOKEN=
LOCAL_NODE_STATE_DIR=./state/local-node
LOCAL_NODE_POLL_INTERVAL=20s
SINGBOX_IMAGE=ghcr.io/sagernet/sing-box:v1.13.11
SINGBOX_BINARY_PATH=/usr/local/bin/sing-box
```

Запуск:

```bash
docker compose --env-file .env up -d --build
docker compose --env-file .env logs -f panel
```

Нода:

```bash
cd deploy/node
cp .env.example .env
```

Отредактируйте `.env`:

```env
NODE_STATE_DIR=./state/node
PANEL_URL=https://panel.example.com:8443
PANEL_CA_FILE=./bootstrap/panel-ca.pem
BOOTSTRAP_TOKEN=PASTE_NODE_BOOTSTRAP_TOKEN
PANEL_FINGERPRINT=PASTE_PANEL_CA_SHA256
POLL_INTERVAL=20s
SINGBOX_IMAGE=ghcr.io/sagernet/sing-box:v1.13.11
SINGBOX_BINARY_PATH=/usr/local/bin/sing-box
```

CA-файл можно скачать с панели и проверить fingerprint:

```bash
mkdir -p ./bootstrap
curl -fsSLk -H "X-Panel-CA-Fingerprint: PASTE_PANEL_CA_SHA256" https://panel.example.com:8443/api/pki/ca -o ./bootstrap/panel-ca.pem
openssl x509 -in ./bootstrap/panel-ca.pem -outform DER | sha256sum
```

Запуск:

```bash
docker compose --env-file .env up -d --build
docker compose --env-file .env logs -f node
```

## Рабочий процесс после деплоя

1. Запустить панель.
2. Создать ноду в разделе `Ноды`.
3. Указать адрес/IP ноды.
4. Скопировать bootstrap token и fingerprint CA.
5. Запустить `node-agent` на VPS-ноды.
6. Создать inbound profile.
7. Привязать inbound profile к ноде.
8. Создать пользователя и подписку.
9. Проверить, что нода получила конфиг и перешла в healthy state.
10. Открыть пользователю ссылку портала или subscription feed.

## Обновление

Панель:

```bash
sudo /opt/mgb-panel/repo/scripts/install-panel.sh
```

Нода:

```bash
sudo /opt/mgb-node/repo/scripts/install-node.sh
```

Если скрипт обнаружит существующую установку, он предложит обновить, удалить или отменить действие.

## Бэкапы

Для панели критичен каталог состояния, по умолчанию:

```text
/opt/mgb-panel/state
```

В нем находятся:

- `panel.db` - SQLite-база.
- `pki/ca-key.pem` - приватный ключ CA.
- `pki/ca.pem` - CA-сертификат.
- `pki/panel-key.pem` и `pki/panel.pem` - TLS-ключ и сертификат панели.

Пример бэкапа:

```bash
sudo tar -czf mgb-panel-backup-$(date +%F).tar.gz -C /opt/mgb-panel state panel.env
```

Потеря `ca-key.pem` означает, что панель не сможет корректно выпускать новые сертификаты нод от старого CA.

## Локальная разработка

Запуск тестов:

```bash
go test ./...
```

Запуск панели без Docker:

```bash
go run ./cmd/panel \
  -listen :8443 \
  -base-url https://localhost:8443 \
  -data-dir ./var/panel
```

Запуск node-agent без Docker:

```bash
go run ./cmd/node-agent \
  -panel-url https://localhost:8443 \
  -state-dir ./var/node \
  -bootstrap-token ENROLL_TOKEN \
  -panel-ca-file ./var/panel/pki/ca.pem \
  -singbox-binary sing-box
```

## HTTP поверхности

Админка/UI:

- `GET /`
- `GET /overview`
- `GET /nodes`
- `GET /users`
- `GET /subscriptions`
- `GET /inbounds`
- `GET /bindings`
- `GET /topology`
- `GET /revisions`

Admin JSON API:

- `GET|POST /api/admin/nodes`
- `GET|POST /api/admin/users`
- `GET|POST /api/admin/subscriptions`
- `GET|POST /api/admin/inbounds`
- `GET|POST /api/admin/bindings`
- `GET|POST /api/admin/topology`
- `GET /api/admin/revisions`

Все `/api/admin/*` endpoints требуют admin Basic Auth.

Node API:

- `GET /api/pki/ca`
- `POST /api/node/enroll`
- `POST /api/node/heartbeat`
- `GET /api/node/config`
- `POST /api/node/ack`

Авторизация Node API:

- `/api/pki/ca` требует admin Basic Auth или header/query с ожидаемым CA fingerprint.
- `/api/node/enroll` требует bootstrap token ноды.
- `/api/node/heartbeat`, `/api/node/config` и `/api/node/ack` требуют mTLS клиентский сертификат ноды.

Install scripts:

- `GET /install/panel.sh`
- `GET /install/node.sh`

Пользовательские ссылки:

- `GET /portal/{subscription_token}`
- `GET /subscription/{subscription_token}`

## Возможные проблемы при деплое

- Basic Auth защищает админку, но при публичном доступе все равно лучше добавить firewall, VPN или reverse proxy с дополнительной защитой.
- TLS-сертификат панели выдан внутренним CA. Браузер и `curl` не будут доверять ему без явного CA или `-k`.
- Если `PANEL_BASE_URL` указан с неправильным hostname/IP, TLS-сертификат панели может не совпасть с URL, и ноды не смогут подключиться.
- Ноды требуют доступ к панели по `PANEL_URL`; DNS, firewall и security groups должны пропускать исходящий HTTPS с ноды и входящий порт панели.
- Inbound-порты `sing-box` на нодах должны быть открыты в firewall VPS.
- `node-agent` работает с host network и `NET_ADMIN`; это нормально для сетевого агента, но повышает требования к доверию контейнеру.
- SQLite подходит для одного экземпляра панели, но не для горизонтального масштабирования панели.
- Нет встроенной ротации CA и клиентских сертификатов нод.
- Нет встроенного rate limiting для публичных HTTP endpoints.
- Нет биллинга, платежей и полноценной RBAC-модели администраторов.
- Скрипты установки используют Docker build на VPS; на слабых VPS первая сборка может занять время.
- `Dockerfile.panel` собирает `linux/amd64`; для ARM VPS нужно проверить multi-arch сборку или адаптировать build args.

## Текущие ограничения

- Только SQLite.
- Нет полноценной RBAC-модели администраторов, пока есть один Basic Auth логин/пароль.
- Нет PostgreSQL.
- Нет cluster scheduler/background queue.
- Topology model ориентирован на WireGuard и не является универсальным full-mesh оркестратором.
- `sing-box` запускается как внешний бинарник, а не как Go-библиотека.
