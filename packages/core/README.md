# @ai-guard/core

The core kernel for AI Guard. This package contains the framework-agnostic logic for:

- **Web Worker Management**: Handling heavy validation tasks off the main thread.
- **Schema Engine**: Deterministic JSON repair and variable extraction.
- **Security Scanning**: PII detection and content safety checks.

## Installation

```bash
npm install @ai-guard/core
```

## Usage

This package is primarily intended to be consumed by `@ai-guard/react` or other framework wrappers. However, it can be used directly in vanilla JS or Node.js environments.

```javascript
import { repairJSON, scanText } from '@ai-guard/core';

// Repair broken JSON
const result = repairJSON('{"name": "Al');
console.log(result.data); // { name: "Al" }

// Scan for PII
const safety = await scanText("My secret is 1234-5678-9012-3456");
console.log(safety.safe); // false
```
