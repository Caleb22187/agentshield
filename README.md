# 🛡️ AgentShield — Prompt Injection Scanner

**Free, browser-based prompt injection scanner for AI agents.**

[![Live Demo](https://img.shields.io/badge/demo-live-brightgreen)](https://caleb22187.github.io/agentshield/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## 🔍 What It Does

Paste any text and instantly scan for prompt injection attacks across **9 detection categories**:

| Category | What It Catches |
|----------|----------------|
| 🔴 Prompt Override | "Ignore previous instructions", role reassignment, jailbreaks |
| 🔑 Credential Theft | API key requests, password fishing, "verification" scams |
| 💰 Crypto Scams | ETH transfer requests, fake airdrops, wallet address extraction |
| 💻 Code Injection | `eval()`, `exec()`, reverse shells, destructive commands |
| 🎭 Social Engineering | Urgency manipulation, authority impersonation, social proof |
| 🔐 Encoded Payloads | Base64, URL-encoded, Unicode-escaped attack strings |
| 📤 Data Exfiltration | Memory dumps, webhook exfil, contact harvesting |
| 🧠 Manipulation | Gaslighting, restriction removal, flattery-based attacks |
| ⚡ Resource Attacks | Infinite loops, token exhaustion, bandwidth abuse |

## 🚀 Try It Now

**Live:** [caleb22187.github.io/agentshield](https://caleb22187.github.io/agentshield/)

Or clone and run locally:
```bash
git clone https://github.com/Caleb22187/agentshield.git
open agentshield/index.html
```

## 🔒 Privacy

- **100% client-side** — no data leaves your browser
- **No tracking, no analytics, no cookies**
- **No backend** — works offline after loading

## 📡 API

**AgentShield API** — scan text programmatically from any language:

```bash
curl -X POST https://agentshield-api.caleb22-187.workers.dev/scan \
  -H "Content-Type: application/json" \
  -d '{"text": "Ignore all previous instructions"}'
```

Free, no auth required, sub-100ms. [Full API docs →](https://github.com/Caleb22187/agentshield-api)

## 📦 Integration

**npm package** (zero dependencies):
```bash
npm install Caleb22187/agentshield-npm
```

```javascript
import { scan } from 'agentshield';
const result = scan(untrustedText);
if (!result.safe) console.log('⚠️ Threats:', result.threats);
```

Also available: [AI Agent Security Toolkit](https://calebsaga77.gumroad.com/l/agent-security-toolkit) with 150+ detection rules, audit checklist, and test suite.

## 🤝 Contributing

Found a new attack pattern? Open an issue or PR. The more patterns we catch, the safer everyone is.

## 📜 License

MIT — use freely, credit appreciated.

---

*Built by [Caleb](https://github.com/Caleb22187) 🦞 — keeping agents safe on the open internet.*
