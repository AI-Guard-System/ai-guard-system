# React AI Guard

> Protect your AI applications from PII leakage and repair malformed JSON from LLM responses.

[![npm version](https://img.shields.io/npm/v/react-ai-guard.svg)](https://www.npmjs.com/package/react-ai-guard)
[![license](https://img.shields.io/npm/l/react-ai-guard.svg)](https://github.com/yourusername/react-ai-guard/blob/main/LICENSE)

---

## The Problem

Building AI-powered applications comes with two painful realities:

1. **PII Leakage**: Users accidentally (or intentionally) paste sensitive data—emails, SSNs, credit cards, API keys—into your AI chat. That data gets sent to third-party LLMs, logged in your backend, and suddenly you're explaining a data breach to your legal team.

2. **Broken JSON**: LLMs love to respond with JSON... wrapped in markdown, with trailing commas, unquoted keys, or truncated mid-stream. Your `JSON.parse()` fails, your app crashes, users complain.

**React AI Guard solves both.**

---

## Features

✅ **PII Scanner** — Detect 15+ types of sensitive data (emails, phones, SSNs, credit cards, API keys, JWTs, and more)  
✅ **Auto-Sanitization** — Replace PII with safe placeholders before sending to LLMs  
✅ **JSON Repair** — Fix malformed LLM responses (trailing commas, comments, markdown blocks, truncated streams)  
✅ **Web Worker Support** — Offload processing to a worker thread for zero UI lag  
✅ **React Hooks** — `useAIGuard()` hook for seamless integration  
✅ **Zero Dependencies** — Pure JavaScript core, works anywhere  
✅ **TypeScript Ready** — Full type definitions included  

---

## Installation

```bash
npm install react-ai-guard
# or
yarn add react-ai-guard
# or
pnpm add react-ai-guard
```

---

## Quick Start

### PII Scanning

```jsx
import { useAIGuard } from 'react-ai-guard';

function ChatInput() {
  const { scanText, sanitizeText, detectPII } = useAIGuard();

  const handleSubmit = async (message) => {
    // Quick check
    if (await detectPII(message)) {
      alert('Your message contains sensitive information!');
      return;
    }

    // Or scan for details
    const result = await scanText(message);
    if (result.hasPII) {
      console.log('Found PII:', result.matches);
      // Use sanitized version
      sendToLLM(result.sanitized);
    }
  };

  return <textarea onSubmit={handleSubmit} />;
}
```

### JSON Repair

```jsx
import { useAIGuard } from 'react-ai-guard';

function AIResponse() {
  const { repairJSON, parseJSON } = useAIGuard();

  const handleLLMResponse = async (rawResponse) => {
    // Safe parse with automatic repair
    const data = await parseJSON(rawResponse, { fallback: {} });
    
    // Or get detailed repair info
    const result = await repairJSON(rawResponse);
    if (result.success) {
      console.log('Fixes applied:', result.fixes);
      console.log('Parsed data:', result.data);
    }
  };
}
```

### Streaming JSON with Schema Validation (v1.1.0+)

Use `useStreamingJson` with Zod schemas for real-time validation of LLM streams:

```jsx
import { useStreamingJson } from 'react-ai-guard';
import { z } from 'zod';

// Define your schema
const UserSchema = z.object({
  name: z.string(),
  email: z.string().email(),
  age: z.number().min(0)
});

function StreamingForm({ rawStream }) {
  const { data, isValid, schemaErrors } = useStreamingJson(rawStream, {
    schema: UserSchema.deepPartial(), // ⚠️ IMPORTANT: Use deepPartial()
    fallback: { name: '', email: '', age: 0 }
  });

  return (
    <div>
      <pre>{JSON.stringify(data, null, 2)}</pre>
      {schemaErrors.map(err => (
        <p key={err.path} className="error">{err.path}: {err.message}</p>
      ))}
    </div>
  );
}
```

> ⚠️ **Critical: Use `schema.deepPartial()` for streaming**
>
> During streaming, your JSON is incomplete. A schema like `z.object({ name: z.string() })` 
> will fail validation on partial chunks like `{"user": {}}` because `name` is missing.
>
> Always use `.deepPartial()` to make all nested fields optional during streaming,
> or handle missing fields gracefully in your UI.

**TypeScript Support:**

```tsx
import { useTypedStream } from 'react-ai-guard';
import { z } from 'zod';

const ProductSchema = z.object({
  id: z.string(),
  price: z.number(),
  inStock: z.boolean()
});

type Product = z.infer<typeof ProductSchema>;

function ProductStream({ stream }: { stream: string }) {
  // Fully typed - data is Product
  const { data, isValid } = useTypedStream<Product>(
    stream, 
    ProductSchema.deepPartial()
  );
  
  return <div>{data.id}: ${data.price}</div>;
}
```

### Without React (Pure JavaScript)

```javascript
import { scan, sanitize, repair, safeParse } from 'react-ai-guard';

// Scan for PII
const result = scan('Contact john@example.com or call 555-123-4567');
console.log(result.sanitized); // "Contact [EMAIL] or call [PHONE]"

// Repair broken JSON
const fixed = repair('{"name": "John",}');
console.log(fixed.data); // { name: "John" }
```

---

## API Reference

### React Hooks

#### `useAIGuard(options?)`

Main hook providing all functionality.

```typescript
const {
  // Scanner
  scanText,        // (text: string) => Promise<ScanResult>
  sanitizeText,    // (text: string) => Promise<string>
  detectPII,       // (text: string) => Promise<boolean>
  scanBatch,       // (texts: string[]) => Promise<ScanResult[]>
  
  // Repair
  repairJSON,      // (input: string, options?) => Promise<RepairResult>
  parseJSON,       // (input: string, fallback?) => Promise<any>
  repairStreamingJSON, // (partial: string) => Promise<RepairResult>
  
  // State
  lastScanResult,  // ScanResult | null
  lastRepairResult,// RepairResult | null
  isProcessing,    // boolean
  error,           // Error | null
  workerReady,     // boolean
} = useAIGuard({
  useWorker: false,     // Use Web Worker for processing
  rules: {},            // Custom rules to merge with presets
  only: null,           // Only use these rule types
  exclude: [],          // Exclude these rule types
  onPIIDetected: null,  // Callback when PII is detected
  onRepairComplete: null, // Callback when repair completes
});
```

#### `AIGuardProvider`

Context provider for shared configuration.

```jsx
import { AIGuardProvider, useAIGuardContext } from 'react-ai-guard';

function App() {
  return (
    <AIGuardProvider
      initialConfig={{ exclude: ['ipv4'] }}
      enabled={true}
    >
      <YourApp />
    </AIGuardProvider>
  );
}

function Component() {
  const { scanner, rules, addRule, removeRule } = useAIGuardContext();
}
```

### Core Functions

#### Scanner

```javascript
import { scan, sanitize, detect, createScanner } from 'react-ai-guard';

// Scan text for PII
const result = scan('Email: test@example.com');
// {
//   original: 'Email: test@example.com',
//   sanitized: 'Email: [EMAIL]',
//   matches: [{ type: 'email', value: 'test@example.com', ... }],
//   hasPII: true,
//   summary: { email: 1 }
// }

// Just sanitize
const clean = sanitize('SSN: 123-45-6789');
// 'SSN: [SSN]'

// Fast detection
const hasPII = detect('Hello world'); // false

// Custom scanner
const scanner = createScanner({
  only: ['email', 'phone'],
  exclude: ['ssn'],
  rules: {
    customId: {
      pattern: /ID-\d{6}/g,
      name: 'Custom ID',
      replacement: '[CUSTOM_ID]',
    },
  },
});
```

#### Repair

```javascript
import { repair, safeParse, validate, extractJSON } from 'react-ai-guard';

// Full repair with details
const result = repair('{"name": "John",}');
// {
//   success: true,
//   data: { name: 'John' },
//   repaired: '{"name": "John"}',
//   original: '{"name": "John",}',
//   fixes: ['Removed trailing commas'],
//   error: null
// }

// Simple safe parse
const data = safeParse('{broken: "json"}', { default: true });
// { broken: 'json' } or { default: true } on failure

// Validate JSON
const { valid, error } = validate('{"test": 1}');

// Extract JSON from text
const json = extractJSON('Here is the data: ```json\n{"key": "value"}\n```');
// '{"key": "value"}'
```

---

## Built-in PII Patterns

| Type | Example | Replacement |
|------|---------|-------------|
| `email` | john@example.com | `[EMAIL]` |
| `phone` | 555-123-4567 | `[PHONE]` |
| `ssn` | 123-45-6789 | `[SSN]` |
| `creditCard` | 4111111111111111 | `[CREDIT_CARD]` |
| `ipv4` | 192.168.1.100 | `[IP_ADDRESS]` |
| `ipv6` | 2001:0db8:85a3:... | `[IP_ADDRESS]` |
| `apiKey` | sk_live_abc123... | `[API_KEY]` |
| `awsKey` | AKIAIOSFODNN7... | `[AWS_KEY]` |
| `jwt` | eyJhbGciOiJIUzI1... | `[JWT]` |
| `address` | 123 Main St | `[ADDRESS]` |
| `dob` | 01/15/1990 | `[DOB]` |
| `passport` | AB1234567 | `[PASSPORT]` |
| `driversLicense` | D1234567 | `[DRIVERS_LICENSE]` |
| `sensitiveUrl` | https://...?token=... | `[SENSITIVE_URL]` |

### Adding Custom Rules

```javascript
import { createRule, createScanner } from 'react-ai-guard';

const scanner = createScanner({
  rules: {
    employeeId: createRule({
      pattern: /EMP-\d{8}/g,
      name: 'Employee ID',
      replacement: '[EMPLOYEE_ID]',
    }),
    internalCode: {
      pattern: /INTERNAL-[A-Z]{3}-\d{4}/g,
      name: 'Internal Code',
      replacement: '[INTERNAL]',
    },
  },
});
```

---

## JSON Repair Capabilities

The repair engine handles common LLM response issues:

| Issue | Before | After |
|-------|--------|-------|
| Trailing commas | `{"a": 1,}` | `{"a": 1}` |
| Unquoted keys | `{name: "John"}` | `{"name": "John"}` |
| Single quotes | `{'key': 'value'}` | `{"key": "value"}` |
| Comments | `{/* comment */ "a": 1}` | `{"a": 1}` |
| Markdown blocks | `` ```json {...} ``` `` | `{...}` |
| Missing brackets | `{"a": 1` | `{"a": 1}` |
| undefined/NaN | `{"a": undefined}` | `{"a": null}` |
| Truncated streams | `{"items": [{"a": 1}, {"b":` | Best-effort parse |

---

## Web Worker Support

For heavy processing, offload work to a Web Worker:

```jsx
const { scanText, workerReady } = useAIGuard({
  useWorker: true,
});

// Wait for worker to initialize
if (workerReady) {
  const result = await scanText(largeText);
}
```

---

## Examples

Run the demo app:

```bash
cd examples/demo-chat
npm install
npm run dev
```

---

## Testing

```bash
# Run tests
npm test

# Run with coverage
npm run test:coverage
```

---

## License

MIT © [Your Name]

---

## Contributing

PRs welcome! Please ensure tests pass and add tests for new features.

```bash
# Install dependencies
npm install

# Run tests in watch mode
npm test

# Build
npm run build
```
