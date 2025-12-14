# AI Guard v2.0: The Security Operating System for LLMs

![Build Status](https://img.shields.io/github/actions/workflow/status/ShyamSathish005/ai-guard/ci.yml?branch=main&style=flat-square&label=Tests)
![Bundle Size](https://img.shields.io/bundlephobia/minzip/react-ai-guard?style=flat-square&label=Size)
![License](https://img.shields.io/npm/l/react-ai-guard?style=flat-square)
![NPM Version](https://img.shields.io/npm/v/react-ai-guard?style=flat-square)

> **"The Firewall for GenAI."**  
> Validates streams, prevents injections, and redacts secrets in real-time—entirely client-side.

---

### 🎥 Streaming De-Identification (Demo)
> *[Insert your recorded demo.gif here showing the "My secret is sk-ant..." text being redacted in real-time]*

---

## ⚡ v2.0 Architecture
We have transitioned from a utility library to a **Privacy-First OS**.

| Package | Role | Version |
| :--- | :--- | :--- |
| **[`@ai-guard/core`](./packages/core)** | **The Kernel.** Universal TypeScript logic. Runs in Node, Edge, or Browser (Worker). Contains the **Entropy Engine** and **Injection Heuristics**. | [![npm](https://img.shields.io/npm/v/@ai-guard/core)](https://www.npmjs.com/package/@ai-guard/core) |
| **[`@ai-guard/react`](./packages/react)** | **The UI Layer.** React hooks (`useAiGuard`) that communicate with the Core Worker via the new **Delta-Protocol**. | [![npm](https://img.shields.io/npm/v/@ai-guard/react)](https://www.npmjs.com/package/@ai-guard/react) |
| **[`@ai-guard/playground`](./packages/playground)** | **Test Lab.** Local environment to fuzz-test the security engines. | - |

## 🛡️ New Security Engines

### 1. Entropy Scanner (`src/security/EntropyScanner.ts`)
Detects API keys, private tokens, and high-entropy secrets using Shannon Entropy analysis. It catches secrets regular Regex misses (e.g. `sk-ant-12345AaBb...`).

### 2. Injection Heuristics (`src/security/InjectionScanner.ts`)
A scoring engine that detects Jailbreak attempts like "Ignore previous instructions", "DAN Mode", and "System Override".

### 3. Smart PII Context
Context-aware Regex engines that reduce false positives by checking surrounding words (e.g. `123-45` vs `SSN: 123-45`).

## Installation

```bash
npm install @ai-guard/react
```

## Quick Start (Streaming)

```tsx
import { useAiGuard } from '@ai-guard/react';

// Pipe your LLM stream directly through the Guard
const { scanStream } = useAiGuard({
  pii: { redact: true },
  blockOnInjection: true
});

// onChunkReceived:
await scanStream(newChunk); 
// Returns: { safe: true, text: "[REDACTED]" }
```

## Contributing
See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License
MIT © [ShyamSathish005](https://github.com/ShyamSathish005)
