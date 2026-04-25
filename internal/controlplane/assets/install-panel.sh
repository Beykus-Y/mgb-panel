#!/usr/bin/env bash
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/Beykus-Y/mgb-panel}"
REPO_REF="${REPO_REF:-main}"
SCRIPT_PATH="scripts/install-panel.sh"

raw_url() {
  local repo="$1"
  repo="${repo%.git}"
  case "$repo" in
    https://github.com/*)
      repo="${repo#https://github.com/}"
      printf "https://raw.githubusercontent.com/%s/%s/%s" "$repo" "$REPO_REF" "$SCRIPT_PATH"
      ;;
    git@github.com:*)
      repo="${repo#git@github.com:}"
      printf "https://raw.githubusercontent.com/%s/%s/%s" "$repo" "$REPO_REF" "$SCRIPT_PATH"
      ;;
    *)
      printf "Неподдерживаемый REPO_URL для bootstrap install script: %s\n" "$REPO_URL" >&2
      exit 1
      ;;
  esac
}

tmp_script="$(mktemp)"
trap 'rm -f "$tmp_script"' EXIT
curl -fsSL "$(raw_url "$REPO_URL")" -o "$tmp_script"
chmod +x "$tmp_script"
exec bash "$tmp_script" "$@"
