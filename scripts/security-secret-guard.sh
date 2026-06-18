#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/security-secret-guard.sh [--deep] [--remediate]

Runs a local secret-boundary guard for OpenClaw-adjacent state.

Environment:
  OPENCLAW_STATE_DIR                 State directory to inspect. Default: ~/.openclaw
  OPENCLAW_WORKSPACE                 Repo/workspace root. Default: parent of scripts/
  SECURITY_SECRET_GUARD_REPORT_DIR   Report directory. Default: runs/security-secret-guard
  SECURITY_SECRET_GUARD_TOXIC_PATHS  Toxic path manifest. Default: reference/security/oauth-toxic-paths.example.txt
  SECURITY_SECRET_GUARD_DEEP         Set to 1 to run optional trufflehog scan.
  TRUFFLEHOG_BIN                     trufflehog binary path. Default: first trufflehog in PATH

Default mode does not modify auth/config state. It writes a local report under
the report directory. Pass --remediate to delete or strip known unsupported
plaintext auth stores; review the summary before using remediation on real state.
EOF
}

deep="${SECURITY_SECRET_GUARD_DEEP:-0}"
remediate=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --deep)
      deep=1
      ;;
    --remediate)
      remediate=1
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "security-secret-guard: unknown option: $1" >&2
      usage >&2
      exit 64
      ;;
  esac
  shift
done

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
repo_root="$(cd -- "$script_dir/.." && pwd -P)"

workspace="${OPENCLAW_WORKSPACE:-$repo_root}"
state_dir="${OPENCLAW_STATE_DIR:-$HOME/.openclaw}"
scan_root="${SECURITY_SECRET_GUARD_REPORT_DIR:-$workspace/runs/security-secret-guard}"
toxic_paths_manifest="${SECURITY_SECRET_GUARD_TOXIC_PATHS:-$workspace/reference/security/oauth-toxic-paths.example.txt}"
redactor="${SECURITY_SECRET_GUARD_REDACTOR:-$workspace/scripts/redact-sensitive-output.sh}"
run_id="$(date -u +%Y%m%dT%H%M%SZ)"
run_dir="$scan_root/$run_id"
summary="$run_dir/summary.tsv"
manifest="$run_dir/remediation.tsv"

mkdir -p "$run_dir"
chmod 700 "$scan_root" "$run_dir"
printf 'status\tdetector\tverified\tpath\n' > "$summary"
printf 'changed_at\taction\tpath\n' > "$manifest"
chmod 600 "$summary" "$manifest"

append_finding() {
  printf '%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" >> "$summary"
}

note_remediation() {
  printf '%s\t%s\t%s\n' "$(date -Is)" "$1" "$2" >> "$manifest"
}

is_toxic_path() {
  case "$1" in
    */auth-profiles.json|*/auth-state.json|*/.codex/auth*|*/.config/*/tokens|*/.config/*/tokens.*|*/.openclaw/backups/restart-safety/*)
      return 0
      ;;
  esac
  return 1
}

if ! command -v jq >/dev/null 2>&1; then
  append_finding "missing-tool" "jq" "true" "jq"
  findings=1
  printf 'findings\t%s\n' "$findings" >> "$summary"
  echo "security-secret-guard findings=$findings summary=$summary"
  exit 2
fi

# Known unsupported plaintext stores. In default mode these are findings only.
# Remediation is explicit because deletion/stripping is not a safe public default.
while IFS= read -r -d '' file; do
  if [ "$remediate" -eq 1 ]; then
    rm -f -- "$file"
    note_remediation "deleted_unsupported_plaintext_store" "$file"
  else
    append_finding "remediation-needed" "UnsupportedPlaintextStore" "true" "$file"
  fi
done < <(
  find "$state_dir" \
    \( -path "$state_dir/.env" -o -path "$state_dir/gateway.systemd.env" \) -prune -o \
    \( -path '*/codex-home/auth.json' -o -path '*/codex-home/logs_*.sqlite*' -o -path '*/codex-home/state_*.sqlite*' -o -path '*/shell_snapshots/*' \) \
    -type f -print0 2>/dev/null
)

if [ -f "$HOME/.codex/auth.json" ]; then
  if [ "$remediate" -eq 1 ]; then
    rm -f -- "$HOME/.codex/auth.json"
    note_remediation "deleted_user_codex_auth_store" "$HOME/.codex/auth.json"
  else
    append_finding "remediation-needed" "UserCodexAuthStore" "true" "$HOME/.codex/auth.json"
  fi
fi

if [ -f "$HOME/.config/gh/hosts.yml" ] && grep -q 'oauth_token:' "$HOME/.config/gh/hosts.yml"; then
  if [ "$remediate" -eq 1 ]; then
    perl -0pi -e 's/^\s*oauth_token:\s*[^\n]*\n//mg' "$HOME/.config/gh/hosts.yml"
    note_remediation "stripped_github_cli_oauth_token" "$HOME/.config/gh/hosts.yml"
  else
    append_finding "remediation-needed" "GitHubCliOauthToken" "true" "$HOME/.config/gh/hosts.yml"
  fi
fi

for file in "$state_dir"/agents/*/agent/auth-profiles.json; do
  [ -f "$file" ] || continue
  jq -e '
    [
      .profiles // {} | to_entries[] | . as $entry
      | select(
          (.value.type == "api_key" and (.value.key? | type == "string" and length > 0))
          or (.value.type == "token" and (.value.token? | type == "string" and length > 0))
        )
      | $entry.key
    ] | length == 0
  ' "$file" >/dev/null || append_finding "plaintext-auth-profile" "OpenClawAuthProfile" "true" "$file"
done

for file in "$state_dir"/agents/*/agent/models.json; do
  [ -f "$file" ] || continue
  jq -r '
    def ok_marker:
      . == null
      or . == "ollama-local"
      or . == "custom-local"
      or . == "codex-app-server"
      or . == "secretref-managed"
      or (. | type == "string" and test("^(oauth:|[A-Z][A-Z0-9_]*$|secretref-env:)"));
    .providers // {} | to_entries[]
    | select((.value.apiKey | ok_marker) | not)
    | .key
  ' "$file" | while IFS= read -r provider; do
    [ -n "$provider" ] || continue
    append_finding "plaintext-models-json" "OpenClawModelsJson" "true" "$file#providers.$provider.apiKey"
  done
done

config_file="$state_dir/openclaw.json"
if [ -f "$config_file" ]; then
  jq -r '
    def secret_ref_or_env_template:
      (type == "object" and .source and .id)
      or (type == "string" and test("^[$][{][A-Z][A-Z0-9_]*[}]$"));
    [
      ["gateway.auth.token", .gateway.auth.token],
      ["channels.telegram.accounts.example.botToken", .channels.telegram.accounts.example.botToken]
    ][]
    | select((.[1] | secret_ref_or_env_template) | not)
    | .[0]
  ' "$config_file" | while IFS= read -r path; do
    [ -n "$path" ] || continue
    append_finding "plaintext-openclaw-config" "OpenClawConfig" "true" "$config_file#$path"
  done
fi

targets=()
for path in \
  "$HOME/.config/gh/hosts.yml" \
  "$workspace/tmp/security" \
  "$scan_root"; do
  [ -e "$path" ] && targets+=("$path")
done

if [ -f "$toxic_paths_manifest" ]; then
  note_remediation "oauth_toxic_paths_manifest_present" "$toxic_paths_manifest"
else
  append_finding "missing-oauth-toxic-paths" "OAuthContainment" "true" "$toxic_paths_manifest"
fi

trufflehog_bin="${TRUFFLEHOG_BIN:-}"
if [ -z "$trufflehog_bin" ] && command -v trufflehog >/dev/null 2>&1; then
  trufflehog_bin="$(command -v trufflehog)"
fi

if [ "$deep" = "1" ] && [ "${#targets[@]}" -gt 0 ] && [ -n "$trufflehog_bin" ] && [ -x "$trufflehog_bin" ]; then
  # Stream raw JSON directly through jq. Never persist scanner JSON/JSONL/logs.
  timeout 300s nice -n 19 ionice -c3 "$trufflehog_bin" filesystem \
    "${targets[@]}" --json --no-update 2>"$run_dir/trufflehog.stderr" \
    | jq -r '
        select(type=="object")
        | (.SourceMetadata.Data.Filesystem.file // .SourceMetadata.Data.Git.file // empty) as $file
        | select($file != "")
        | [$file, (.DetectorName // ""), (.Verified|tostring)] | @tsv
      ' \
    | sort -u \
    | while IFS=$'\t' read -r file detector verified; do
        [ -n "$file" ] || continue
        if is_toxic_path "$file"; then
          note_remediation "suppressed_oauth_toxic_path_scan_finding" "$file"
          continue
        fi
        append_finding "scanner" "$detector" "$verified" "$file"
      done || true
  rm -f "$run_dir/trufflehog.stderr"
elif [ "$deep" = "1" ]; then
  append_finding "missing-tool" "trufflehog" "true" "TRUFFLEHOG_BIN"
fi

find "$run_dir" -type f \( -name '*.json' -o -name '*.jsonl' -o -name '*.log' \) -delete 2>/dev/null || true

findings="$(awk -F '\t' 'NR>1 && $1 != "ok" {n++} END {print n+0}' "$summary")"
printf 'findings\t%s\n' "$findings" >> "$summary"

if [ "$findings" -gt 0 ]; then
  echo "security-secret-guard findings=$findings summary=$summary"
  if [ -x "$redactor" ]; then
    awk -F '\t' 'NR>1 && $1 != "ok" {print $0}' "$summary" | head -40 | "$redactor"
  else
    awk -F '\t' 'NR>1 && $1 != "ok" {print $0}' "$summary" | head -40
  fi
  exit 2
fi

echo "security-secret-guard clean summary=$summary"
