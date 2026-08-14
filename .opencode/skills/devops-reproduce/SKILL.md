---
name: devops-reproduce
description: CI/CD injection, container escape, workflow injection, build poisoning. After HUNT confirms exploitable — confirmation, PoC creation, exploit adaptation. Use when testing DEVOPS vulnerabilities.
---

# SKILL-DEVOPS-REPRODUCE — CI/CD Pipeline & Container Security Reproduce — REPRODUCE
# Phase Coverage: 46
# Vuln Classes: CI/CD Pipeline Injection, Container Escape, Workflow Injection,
#               Runner Hardening Bypass, Dependency Confusion, Build Poisoning
# Purpose: Confirmation, PoC creation, mitigations, and tool integration for CI/CD findings

---

## SUB-PHASE 46.3: REPRODUCE

```
CONFIRM: actual host access, credential exfiltration, or code execution beyond container boundary
PoC: save to scripts/{SLUG}/devops_{attack}.sh
Save finding: findings/{SLUG}/{severity}/ci-cd/{title}/

CHAIN OUTPUT:
  - Container escape -> host RCE = CRITICAL
  - Container escape + shared runner = cross-repo secret access (CRITICAL)
  - Workflow injection + repo secrets = cloud credential theft (CRITICAL)
  - Dependency confusion + CI install = code exec in build pipeline (HIGH)
  - Artifact poisoning + downstream pipeline = supply chain compromise (HIGH)
```

---

## Mitigations

**For Container Options:**
  - Treat workflow-authored container.options as untrusted input
  - Reject host namespace flags when privileged mode is disabled
  - Strip: --pid=host, --ipc=host, --uts=host, --network=host, --cgroupns=host
  - Strip: --cap-add (especially ALL, SYS_ADMIN), --security-opt with override values
  - Strip: --device, --volumes-from, --runtime, --cgroup-parent
  - Use allowlist of safe Docker options only

**General CI/CD:**
  - Never interpolate untrusted input directly into shell scripts
  - Use environment variables or actions for passing PR metadata
  - Run untrusted workflows on isolated, single-tenant runners
  - Configure scoped credentials (OIDC) instead of long-lived secrets
  - Pin package versions and verify checksums in CI

---

## MCP Integration

```
BROWSER (Firefox):
  - Navigate to Gitea/GitHub repo, inspect Actions tab
  - Review workflow runs, logs, and runner details
  - Check container logs for option injection evidence

KALI:
  - Build test container images for escape verification
  - Run act_runner locally for reproduction
  - Execute nsenter, capsh, and other container escape tools

BURP:
  - Monitor CI webhook deliveries for secrets
  - Intercept workflow dispatch API calls
  - Test webhook payload injection
```

---

## Playwright MCP Integration

CI/CD testing involves web UIs (Gitea, GitHub, GitLab) — Playwright navigates these better than curl.

| DevOps Task | Playwright Tool | Playbook |
|-------------|----------------|----------|
| **Workflow file discovery** | `browser_navigate` to `/.gitea/workflows/`, `browser_snapshot` | Check exposed workflow directories via browser |
| **Runner log inspection** | `browser_navigate` to Actions tab, `browser_snapshot` | Observe runner execution logs for injection evidence |
| **Webhook payload testing** | `browser_network_requests` | Monitor CI webhook deliveries in real-time |
| **GitHub Actions review** | `browser_navigate` to PR workflows, `browser_snapshot` | Inspect workflow runs for script injection from PR titles/branches |
| **Container escape verification** | `browser_evaluate` → monitor job output | Check if host namespace flags produce detectable output |

### CI/CD UI Testing
```
1. browser_navigate(url="https://gitea.target.com/org/repo/actions")
2. browser_snapshot → inspect workflow runs, job logs
3. browser_click → drill into specific job output
4. browser_evaluate → extract runner metadata, container options, secrets references
```

---

*SKILL-DEVOPS-REPRODUCE — Part of the acy Agentic Security Research System v3.0*
