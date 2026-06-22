# Third-Party Notices

OpenClaw Security Stack is licensed under the MIT License for original project
code and documentation. Vendored upstream material and adapted workflow content
retain their original license notices.

This file is a convenience index. The authoritative license text remains in
the referenced upstream license files.

## Anthropic Defending Code Reference Harness

- Source: `anthropics/defending-code-reference-harness`
- URL: https://github.com/anthropics/defending-code-reference-harness
- Imported commit: `9e0f6c6cd54fc3b8ce79708e8208d862634a2624`
- Local path: `tools/anthropic-security/upstream/defending-code/`
- License: Apache License 2.0
- Local license file:
  `tools/anthropic-security/upstream/defending-code/LICENSE`
- Copyright notice in upstream license:
  `Copyright 2026 Anthropic PBC`

OpenClaw-facing wrappers under `tools/anthropic-security/openclaw-skills/`
adapt workflow concepts, schemas, and safety rules from this upstream project.
Those adaptations are distributed with this notice and the upstream Apache-2.0
license preserved in the vendored source tree.

## Anthropic Claude Code Security Review

- Source: `anthropics/claude-code-security-review`
- URL: https://github.com/anthropics/claude-code-security-review
- Imported commit: `0c6a49f1fa56a1d472575da86a94dbc1edb78eda`
- Local path:
  `tools/anthropic-security/upstream/claude-code-security-review/`
- License: MIT License
- Local license file:
  `tools/anthropic-security/upstream/claude-code-security-review/LICENSE`
- Copyright notice in upstream license:
  `Copyright (c) 2025 Anthropic`

The OpenClaw diff-review wrapper is adapted from the upstream security-review
command and keeps this provenance visible through the adapter manifest and
vendored upstream license.

## Notes For Redistributors

- Keep the root `LICENSE` file with copies or substantial portions of the
  original OpenClaw Security Stack code.
- Keep the upstream license files listed above when distributing vendored or
  adapted Anthropic material.
- The root MIT license does not remove, replace, or narrow the upstream MIT or
  Apache-2.0 notices for third-party material.
