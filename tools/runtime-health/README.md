# Runtime-Health Scanner (v1 lane)

Read-only host posture checks emitted as `security-stack.findings.v1` so they
flow through the report core and the orchestrator.

## Checks (all best-effort, skipped gracefully if unavailable)

| Check | Finding | Severity |
| --- | --- | --- |
| Listening sockets (`ss`) | service bound to a non-loopback address | MEDIUM |
| SSH config (`/etc/ssh/sshd_config*`) | `PermitRootLogin yes` | HIGH |
| SSH config | `PasswordAuthentication yes` | MEDIUM |
| SSH key perms (`~/.ssh`) | private key group/other-accessible | HIGH |
| Sensitive files (opt-in) | configured file group/other-accessible | MEDIUM |
| Firewall (`ufw` / `iptables`) | no active firewall detected | LOW |

## Portability

Generic and host-agnostic: no hardcoded paths, usernames, or identity. Designed
to be usable by other operators. Any check whose tool/file is missing or not
readable is recorded under `checks_skipped` instead of failing the run. Core
check logic is implemented as pure functions (testable without a live host).

## Safety

- Read-only. Detection before remediation. It never changes services, SSH,
  firewall, file permissions, or config.
- Output is local-only under `runs/runtime-health/<label>/` and is redacted by
  the report core before sharing.

## Usage

```bash
node scripts/security-runtime-health.mjs --label my-host
# optionally permission-check specific sensitive files:
node scripts/security-runtime-health.mjs --label my-host --sensitive /path/to/.env
# turn it into a redacted report:
node scripts/security-report.mjs --findings runs/runtime-health/my-host/RUNTIME-HEALTH-FINDINGS.json
```

It also runs as a lane inside `scripts/security-scan.mjs`. Note: runtime-health
is host-level, so in a multi-target scan it reports the same host posture under
each target label.

## Note on noise

Many hosts legitimately bind services to all interfaces, so `listening-non-loopback`
can be chatty on a first run. The report core marks repeat findings `persistent`,
so reviewers can focus on `new` exposures. An explicit acknowledge/ignore
workflow is tracked in the backlog.

## Tests

```bash
node scripts/test-security-runtime-health.mjs
```
