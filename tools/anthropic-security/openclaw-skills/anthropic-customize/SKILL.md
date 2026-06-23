---
name: anthropic-customize
description: Plan and adapt the Anthropic defending-code harness for a target.
---

# Anthropic Customize - OpenClaw Skill Wrapper

This skill adapts Anthropic's defending-code `customize` workflow for OpenClaw.
It is self-contained for runtime use.

## When To Use

Use when porting the reference harness to a new target stack, detector, or
vulnerability class.

## Safety

- Treat customization as a plan-and-review workflow.
- Do not install packages, run Docker, execute target code, or change system
  services on a production host without explicit approval for that separate action.
- Dynamic execution must use approved off-Pi/container isolation.
- Never mount OpenClaw secrets, memory, auth stores, SSH keys, or home
  directories into the harness.

## Workflow

1. Identify the target stack, vulnerability classes, and execution oracle.
2. Decide whether static skills are enough or whether dynamic harness work is
   justified.
3. Define target config: build/setup, run command, proof signal, verifier, and
   patch-validation ladder.
4. Define sandbox requirements: network, mounts, secrets, scratch space,
   egress, and isolation level.
5. Propose changes in a PR. Keep target execution out of the Pi path.
6. Validate only with approved lightweight checks unless an off-Pi/container
   execution lane is explicitly authorized.

## Output

Produce a concrete porting plan and reviewed harness/config changes for one
target at a time.
