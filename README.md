# skwatch

[![CI](https://github.com/domehahn/skwatch/actions/workflows/ci.yml/badge.svg)](https://github.com/domehahn/skwatch/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/domehahn/skwatch.svg)](https://pkg.go.dev/github.com/domehahn/skwatch)
[![Go Version](https://img.shields.io/github/go-mod/go-version/domehahn/skwatch)](https://github.com/domehahn/skwatch/blob/main/go.mod)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/domehahn/skwatch/blob/main/LICENSE)

`skwatch` (**Continuous Threat & Drift Monitor**) continuously inspects deployed AI agent skills, detects content drift against cryptographic digests, and surfaces post-deployment security risks.

## Features

- **Continuous Drift Detection**: Verifies directory contents against expected `sha256:...` digests.
- **Vulnerability & Prompt Heuristics**: Detects unconstrained shell downloads, hardcoded tokens, and prompt injection markers.
- **Alert Dispatcher**: Sends notifications to webhooks and SIEM backends upon policy violations.

## Installation

```bash
go install github.com/domehahn/skwatch/cmd/skwatch@latest
```

## Quick Start

```bash
# Scan a skill directory for threats
skwatch scan --path ./my-skill

# Verify skill integrity against an expected digest
skwatch drift --path ./my-skill --expected sha256:abcd...
```
