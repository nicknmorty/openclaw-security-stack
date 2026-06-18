#!/usr/bin/env bash
set -euo pipefail

# Redact common OAuth/API credential fields from captured shell/tool output.
# This is intentionally stdin/stdout so guard scripts can pipe diagnostics
# through it without writing raw scanner output to disk.
perl -CSDA -pe '
  s/(Authorization:\s*Bearer\s+)[A-Za-z0-9._~+\/=-]+/${1}[REDACTED]/ig;
  s/(Bearer\s+)[A-Za-z0-9._~+\/=-]{20,}/${1}[REDACTED]/ig;
  s#("?(?:access_token|refresh_token|id_token|client_secret|api_key|token)"?\s*[:=]\s*)("[^"]*"|'\''[^'\'']*'\''|[^\s,}]+)#$1"[REDACTED]"#ig;
  s#((?:"(?:authorization|bearer)"\s*:|(?:authorization|bearer)\s*=)\s*)("[^"]*"|'\''[^'\'']*'\''|[^\s,}]+)#$1"[REDACTED]"#ig;
'
