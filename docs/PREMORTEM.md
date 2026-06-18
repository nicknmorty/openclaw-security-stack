# Premortem

Assume it is six months later and this project failed badly.

## Likely Failure
It became a noisy checklist runner that produced too many vague findings and nobody trusted the alerts.

Mitigation: classify findings by confidence, track `new/persistent/resolved`, and require evidence that points to an action.

## Dangerous Failure
The tool leaked sensitive local paths, chat IDs, secrets, package names, or security posture details into a shared report.

Mitigation: make redaction a core report-layer requirement before any group/chat summaries.

## Hidden Assumption
That supply-chain exposure, runtime health, and agent safety can share one scanner model immediately.

Mitigation: keep scanners modular and normalize only the finding/report contract.

## Warning Signs
- Raw logs copied into reports.
- Findings without owner/action.
- Auto-remediation pressure before read-only scans are trusted.
- Scans that overload the Pi.
- Security policy changes bundled into convenience scripts.

## Revised Starting Plan
Build V0 as a read-only inventory and reporting skeleton first. Add one scanner lane at a time after the report contract is boring and safe.
