#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/oauth-containment-audit.sh [--fix]

Audits OpenClaw-adjacent OAuth/token storage permissions.

Environment:
  OPENCLAW_STATE_DIR        State directory to inspect. Default: ~/.openclaw
  OPENCLAW_WORKSPACE        Repo/workspace root. Default: parent of scripts/
  OAUTH_CONTAINMENT_DIR     Private OAuth containment dir. Default: ~/.local/share/openclaw/oauth
  OAUTH_TOXIC_PATHS         Toxic path manifest. Default: reference/security/oauth-toxic-paths.example.txt

Default mode is read-only and exits non-zero on permission or manifest findings.
Pass --fix to create/chmod expected local directories and files.
EOF
}

fix=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --fix)
      fix=1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "oauth-containment-audit: unknown option: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
  shift
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"

state_dir="${OPENCLAW_STATE_DIR:-$HOME/.openclaw}"
workspace="${OPENCLAW_WORKSPACE:-$repo_root}"
containment_dir="${OAUTH_CONTAINMENT_DIR:-$HOME/.local/share/openclaw/oauth}"
toxic_paths="${OAUTH_TOXIC_PATHS:-$workspace/reference/security/oauth-toxic-paths.example.txt}"

failures=0

report() {
  printf '%s\t%s\t%s\n' "$1" "$2" "$3"
}

mark_fail() {
  failures=$((failures + 1))
  report fail "$1" "$2"
}

dir_mode() {
  stat -c '%a' "$1"
}

file_mode() {
  stat -c '%a' "$1"
}

ensure_dir_700() {
  local path="$1"
  if [ ! -d "$path" ]; then
    if [ "$fix" -eq 1 ]; then
      install -d -m 700 "$path"
      report fixed dir-created-700 "$path"
    else
      mark_fail missing-dir "$path"
      return 0
    fi
  fi

  if [ "$fix" -eq 1 ]; then
    chmod 700 "$path"
  fi

  local mode
  mode="$(dir_mode "$path")"
  if [ "$mode" = "700" ]; then
    report ok dir-700 "$path"
  else
    mark_fail "dir-mode-$mode" "$path"
  fi
}

ensure_file_600() {
  local path="$1"
  [ -f "$path" ] || return 0

  if [ "$fix" -eq 1 ]; then
    chmod 600 "$path"
  fi

  local mode
  mode="$(file_mode "$path")"
  if [ "$mode" = "600" ]; then
    report ok file-600 "$path"
  else
    mark_fail "file-mode-$mode" "$path"
  fi
}

ensure_dir_700 "$containment_dir"
ensure_dir_700 "$HOME/.config/openclaw"
ensure_dir_700 "$HOME/.codex"

if [ -d "$state_dir/agents" ]; then
  ensure_dir_700 "$state_dir/agents"
  while IFS= read -r dir; do
    ensure_dir_700 "$dir"
  done < <(find "$state_dir/agents" -maxdepth 3 -type d -path '*/agent' -print 2>/dev/null | sort)
fi

for file in \
  "$state_dir"/agents/*/agent/auth-profiles.json \
  "$state_dir"/agents/*/agent/auth-state.json \
  "$HOME/.config/openclaw/auth-profile-secret-key" \
  "$HOME/.codex/auth.json"; do
  [ -e "$file" ] || continue
  ensure_file_600 "$file"
done

if [ -f "$toxic_paths" ]; then
  report ok toxic-path-manifest "$toxic_paths"
else
  mark_fail toxic-path-manifest "$toxic_paths"
fi

if ! command -v jq >/dev/null 2>&1; then
  mark_fail missing-tool jq
  exit "$failures"
fi

for file in "$state_dir"/agents/*/agent/auth-profiles.json; do
  [ -f "$file" ] || continue
  jq -r --arg file "$file" '
    (.profiles // {}) | to_entries[]
    | select(.value.type == "oauth")
    | [
        "ok",
        "oauth-profile",
        ($file + "#" + .key + " provider=" + (.value.provider // "unknown"))
      ] | @tsv
  ' "$file"
done

exit "$failures"
