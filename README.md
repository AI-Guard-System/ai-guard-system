# react-ai-guard

Client-side safety layer for Large Language Model (LLM) applications.

A lightweight, zero-dependency React library that ensures application stability and data privacy when integrating with LLMs. It executes entirely within a dedicated Web Worker to maintain 60fps UI performance, regardless of stream volume or validation complexity.

---

## The Problem

Integrating streaming LLM responses into React applications introduces two critical risks:

1. **Application Crashes**: `JSON.parse()` fails when processing partial or malformed JSON chunks typical of streaming responses. This often leads to white screens or extensive try/catch boilerplate.

2. **Data Exfiltration**: Users may inadvertently paste sensitive information (PII, API keys) into prompts, which are then sent to third-party model providers.

---

## The Solution

`react-ai-guard` acts as a middleware between the user/LLM and your application state.

- **Deterministic JSON Repair**: Utilizes a stack-based finite state machine to auto-close brackets, quotes, and structural errors in real-time. It transforms broken streams (e.g., `{"data": {"nam`) into valid JavaScript objects.

- **Client-Side Firewall**: Scans input text for sensitive patterns (Credit Cards, SSNs, API Keys) using a background thread before the network request is initiated.

- **Main Thread Isolation**: All heavy computation (regex scanning, recursive parsing) is offloaded to a Web Worker, ensuring the UI thread remains unblocked.

---

## Installation

```bash
npm install react-ai-guard
```

---

## Usage

### 1. Handling Streaming JSON

Use the `useStreamingJson` hook to consume raw text streams. It guarantees a valid object at every render cycle, eliminating the need for manual parsing logic.

```javascript
import { useStreamingJson } from 'react-ai-guard';

const ChatComponent = ({ rawStream }) => {
  // rawStream: '{"user": {"name": "Ali'
  const { data, isValid } = useStreamingJson(rawStream);

  // data: { user: { name: "Ali" } }
  return (
    <div>
      <p>Name: {data?.user?.name}</p>
      {!isValid && <span>Streaming...</span>}
    </div>
  );
};
```

### 2. Schema Validation (Zod Support)

The library supports "Duck Typing" for schema validation. You can pass a Zod schema (or any object with a `.safeParse` method) to ensure the streamed data matches your expected type definition.

Note: For streaming data, use `.deepPartial()` as the object is built incrementally.

```javascript
import { z } from 'zod';
import { useStreamingJson } from 'react-ai-guard';

const UserSchema = z.object({
  id: z.number(),
  name: z.string(),
  role: z.enum(['admin', 'user'])
}).deepPartial();

const Dashboard = ({ stream }) => {
  const { data, isSchemaValid, schemaErrors } = useStreamingJson(stream, { 
    schema: UserSchema 
  });

  return (
    <div>
      <pre>{JSON.stringify(data, null, 2)}</pre>
      {!isSchemaValid && (
        <div className="error">
          Validation Error: {schemaErrors?.[0]?.message}
        </div>
      )}
    </div>
  );
};
```

### 3. PII and Secret Detection

Use the `useAIGuard` hook to validate user input before sending it to an external API. This runs synchronously from the UI perspective but asynchronously on the worker thread.

```javascript
import { useAIGuard } from 'react-ai-guard';

const InputForm = () => {
  const { scanInput } = useAIGuard({
    redact: true // Replaces detected entities with [REDACTED]
  });

  const handleSubmit = async (text) => {
    // Blocks execution if sensitive data is found
    const result = await scanInput(text);

    if (!result.safe) {
      console.warn("Blocked PII:", result.findings);
      alert("Please remove sensitive information.");
      return;
    }

    // Proceed with sanitized text
    await sendToLLM(result.text); 
  };
};
```

---

## Architecture

This library is designed for high-performance frontend environments.

- **Singleton Worker**: A single Web Worker instance is spawned upon the first hook usage and shared across all components to conserve memory.

- **Message Queue**: Requests are serialized and processed via a promise-based message queue, preventing race conditions during rapid state updates.

- **No External Dependencies**: The core parsing and scanning logic is written in pure JavaScript with zero runtime dependencies.

---

## API Reference

### useStreamingJson(rawString, options)

| Parameter | Type | Description |
|-----------|------|-------------|
| `rawString` | `string` | The raw text chunk received from the LLM stream. |
| `options.fallback` | `object` | Initial state before parsing begins (default: `{}`). |
| `options.schema` | `ZodSchema` | Optional schema to validate the parsed data against. |
| `options.partial` | `boolean` | Allow partial schema matches during streaming (default: `true`). |

**Returns:**

| Property | Type | Description |
|----------|------|-------------|
| `data` | `object` | The repaired, valid JSON object. |
| `isValid` | `boolean` | Indicates if the current chunk is syntactically valid JSON. |
| `isSchemaValid` | `boolean` | Indicates if data passes the provided schema. |
| `schemaErrors` | `array` | Array of error objects returned by the schema validator. |

---

### useAIGuard(config)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `rules` | `string[]` | All | Array of rule IDs to enable (e.g., `['CREDIT_CARD', 'API_KEY']`). |
| `redact` | `boolean` | `false` | If true, returns a redacted string instead of just blocking. |

**Returns:**

| Method | Signature | Description |
|--------|-----------|-------------|
| `scanInput` | `(text: string) => Promise<ScanResult>` | Scans text for PII. Returns `{ safe, findings, text }`. |
| `repairJson` | `(text: string) => Promise<RepairResult>` | Repairs and parses JSON. Returns `{ data, isValid, fixedString }`. |

---

## Supported PII Rules

The following patterns are detected by the default engine:

| Rule ID | Description |
|---------|-------------|
| `CREDIT_CARD` | Major credit card number formats (Visa, Mastercard, Amex). |
| `EMAIL` | Standard email address patterns. |
| `API_KEY` | High-entropy strings resembling API tokens (e.g., `sk-`, `ghp-`). |
| `SSN` | US Social Security Numbers (XXX-XX-XXXX format). |
| `IPV4` | IPv4 addresses. |

---

## Demo
### Feature 1: Auto-Repairing Broken Streams
Standard `JSON.parse` crashes when the stream cuts off. We fix it in real-time.

<video src="https://github.com/user-attachments/assets/80ce21fb-8017-4c48-b803-1813fcc1c369" controls="false" autoplay="true" loop="true" width="100%"></video>






## License

MIT
