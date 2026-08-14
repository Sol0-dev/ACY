---
name: devops-discovery
description: CI/CD injection, container escape, workflow injection, build poisoning. Phase start — surface detection, parameter identification, initial probes. Use when testing DEVOPS vulnerabilities.
---

# SKILL-DEVOPS-DISCOVERY — CI/CD Pipeline & Container Security Discovery — DISCOVERY
# Phase Coverage: 46
# Vuln Classes: CI/CD Pipeline Injection, Container Escape, Workflow Injection,
#               Runner Hardening Bypass, Dependency Confusion, Build Poisoning
# Purpose: CI/CD pipeline, container, and DevOps infrastructure security testing — discovery phase

---

## Phase 46: CI/CD Pipeline Attacks — CIA: C:H I:H A:H

```
TRIGGER: Target uses GitHub Actions, GitLab CI, Gitea Actions, Jenkins, or similar CI/CD.
         Recon discovers .github/workflows/, .gitlab-ci.yml, Jenkinsfile, or act_runner.
SURFACE TYPES: workflow files, runner configurations, container build steps,
               artifact uploads, deployment pipelines, self-hosted runners.
```

### SUB-PHASE 46.1: DISCOVERY

**Passive Discovery:**
  - Check repository for workflow files (.github/workflows/*.yml, .gitea/workflows/*.yml)
  - Examine runner configuration (act_runner config, GitHub Actions runner settings)
  - Check if self-hosted runners are used (shared with untrusted repos?)
  - Review container.options, services, and job environment variables
  - Check for image references: docker://, registry access, image pull policy

**Active Discovery:**
  - Push a branch with a test workflow to trigger CI
  - Observe runner behavior: container isolation, network access, volume mounts
  - Check what Docker options are passed to job containers
  - Test if privileged mode is truly disabled or can be bypassed

---

*SKILL-DEVOPS-DISCOVERY — Part of the acy Agentic Security Research System v3.0*
