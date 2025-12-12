# react-ai-guard

![Build Status](https://img.shields.io/github/actions/workflow/status/ShyamSathish005/ai-guard/ci.yml?branch=main&style=flat-square&label=Tests)
![Bundle Size](https://img.shields.io/bundlephobia/minzip/react-ai-guard?style=flat-square&label=Size)
![License](https://img.shields.io/npm/l/react-ai-guard?style=flat-square)
![NPM Version](https://img.shields.io/npm/v/react-ai-guard?style=flat-square)

Client-side safety layer for Large Language Model (LLM) applications.

A lightweight, zero-dependency React library that ensures application stability and data privacy when integrating with LLMs. It executes entirely within a dedicated Web Worker to maintain 60fps UI performance, regardless of stream volume or validation complexity.

**v1.3.0**: Now with reasoning model support (DeepSeek-R1, o1) and Vercel AI SDK integration.

---

## Support for Reasoning Models (DeepSeek-R1, o1)

Reasoning models often output `<think>` blocks or Markdown before the actual JSON. `react-ai-guard` automatically strips these and extracts the JSON for you.

```javascript
const { data } = useStreamingJson(stream, { 
  extract: true // 👈 Auto-strips <think> and finds the JSON
});
```

The first React hook with native support for DeepSeek-R1 and OpenAI o1 reasoning traces.

## Installation

```bash
npm install react-ai-guard
# or
yarn add react-ai-guard
# or
pnpm add react-ai-guard
```

## The Problem

Integrating streaming LLM responses into React applications introduces three critical risks:

*   **Application Crashes**: `JSON.parse()` fails when processing partial or malformed JSON chunks typical of streaming responses. This often leads to white screens or extensive try/catch boilerplate.
*   **Data Exfiltration**: Users may inadvertently paste sensitive information (PII, API keys) into prompts, which are then sent to third-party model providers.
*   **Reasoning Model Noise**: Models like DeepSeek-R1 and o1 output `<think>` traces or prose before JSON, breaking naive parsers.

## Why not just use `JSON.parse`?

Reasoning models like **DeepSeek-R1** and **OpenAI o1** are non-deterministic. They output:
1.  **Thinking Traces:** `<think>...` blocks that break standard parsers.
2.  **Mixed Modality:** Markdown text interleaved with JSON code blocks.
3.  **Partial Tokens:** Streams often pause mid-syntax (`{"id": 1, "nam`...).

`react-ai-guard` isn't a "band-aid"; it's a **Stream Normalization Layer**. It standardizes the chaotic output of these models into a reliable, typed object stream that your UI can render safely at 60fps.

## The Solution

`react-ai-guard` acts as a middleware between the user/LLM and your application state.

*   **Deterministic JSON Repair**: Utilizes a stack-based finite state machine to auto-close brackets, quotes, and structural errors in real-time. It transforms broken streams (e.g., `{"data": {"nam`) into valid JavaScript objects.
*   **Reasoning Model Extraction**: Strips `<think>` tags, markdown code blocks, and prose to extract clean JSON from verbose model outputs.
*   **Client-Side Firewall**: Scans input text for sensitive patterns (Credit Cards, SSNs, API Keys, JWTs) using a background thread before the network request is initiated.
*   **Main Thread Isolation**: All heavy computation (regex scanning, recursive parsing) is offloaded to a Web Worker, ensuring the UI thread remains unblocked.

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

### 2. Reasoning Model Support (DeepSeek-R1, o1)

For models that output thinking traces before JSON, enable extract mode:

```javascript
import { useStreamingJson } from 'react-ai-guard';

// Model output: "<think>Let me analyze...</think>{"result": "success"}"
const { data, isComplete } = useStreamingJson(rawStream, { 
  extract: true  // Strips <think> tags and extracts JSON
});
// data: { result: "success" }
```

### 3. Vercel AI SDK Integration

Seamlessly integrate with `useChat()`:

```javascript
import { useChat } from 'ai/react';
import { useVercelStream } from 'react-ai-guard';

const Chat = () => {
  const { messages } = useChat();
  const { object, isStreaming } = useVercelStream(messages, {
    schema: ResponseSchema,
    extract: true  // Handle reasoning models
  });

  return <div>{object?.response}</div>;
};
```

### 4. Schema Validation (Zod Support)

The library supports "Duck Typing" for schema validation. You can pass a Zod schema (or any object with a `.safeParse` method) to ensure the streamed data matches your expected type definition.

```javascript
import { z } from 'zod';
import { useStreamingJson } from 'react-ai-guard';

const UserSchema = z.object({
  id: z.number(),
  name: z.string(),
  role: z.enum(['admin', 'user'])
}).deepPartial();

const Dashboard = ({ stream }) => {
  const { data, isSchemaValid, schemaErrors, isComplete } = useStreamingJson(stream, { 
    schema: UserSchema,
    stubFromSchema: true,            // Pre-fill skeleton for optimistic UI
    onComplete: (data) => save(data),
    onValidationFail: (errors) => console.warn(errors)
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

### 5. PII and Secret Detection

Use the `useAIGuard` hook to validate user input before sending it to an external API.

```javascript
import { useAIGuard } from 'react-ai-guard';

const InputForm = () => {
  const { scanInput } = useAIGuard({
    redact: true,
    allow: [/support@company\.com/],  // Whitelist patterns
    customRules: [{ name: 'INTERNAL_ID', pattern: /INT-\d{6}/ }]
  });

  const handleSubmit = async (text) => {
    const result = await scanInput(text);

    if (!result.safe) {
      console.warn("Blocked PII:", result.findings);
      alert("Please remove sensitive information.");
      return;
    }

    await sendToLLM(result.text); 
  };
};
```

## API Reference

### useStreamingJson(rawString, options)

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `rawString` | `string` | The raw text chunk received from the LLM stream. |
| `options.fallback` | `object` | Initial state before parsing begins (default: `{}`). |
| `options.schema` | `ZodSchema` | Optional schema to validate the parsed data against. |
| `options.partial` | `boolean` | Allow partial schema matches during streaming (default: `true`). |
| `options.extract` | `boolean` | Strip `<think>` tags and extract JSON from prose (default: `false`). |
| `options.stubFromSchema` | `boolean` | Pre-fill skeleton from schema for optimistic UI (default: `false`). |
| `options.onComplete` | `function` | Callback when stream is complete and validated. |
| `options.onError` | `function` | Callback on repair error. |
| `options.onValidationFail` | `function` | Callback on schema validation failure. |

**Returns:**

| Property | Type | Description |
| :--- | :--- | :--- |
| `data` | `object` | The repaired, valid JSON object. |
| `isValid` | `boolean` | Indicates if the current chunk is syntactically valid JSON. |
| `isSchemaValid` | `boolean` | Indicates if data passes the provided schema. |
| `schemaErrors` | `array` | Array of error objects returned by the schema validator. |
| `isComplete` | `boolean` | True when stream is finished and validated. |

### useVercelStream(messages, options)

Adapter for Vercel AI SDK's `useChat()` hook.

| Parameter | Type | Description |
| :--- | :--- | :--- |
| `messages` | `array` | Messages array from `useChat()`. |
| `options` | `object` | Same options as `useStreamingJson`. |

**Returns:**

| Property | Type | Description |
| :--- | :--- | :--- |
| `object` | `object` | Alias for data (matches Vercel naming). |
| `isStreaming` | `boolean` | True while stream is in progress. |
| `...rest` | | All properties from `useStreamingJson`. |

### useAIGuard(config)

| Option | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `rules` | `string[]` | All | Array of rule IDs to enable (e.g., `['CREDIT_CARD', 'API_KEY']`). |
| `redact` | `boolean` | `false` | If true, returns a redacted string instead of just blocking. |
| `allow` | `(string\|RegExp)[]` | | Patterns to whitelist (exceptions). |
| `customRules` | `object[][]` | | Custom rules: `[{ name: 'CUSTOM', pattern: /.../ }]` |

**Returns:**

| Method | Signature | Description |
| :--- | :--- | :--- |
| `scanInput` | `(text: string) => Promise<ScanResult>` | Scans text for PII. Returns `{ safe, findings, text }`. |
| `repairJson` | `(text: string, options?) => Promise<RepairResult>` | Repairs JSON. options.extract strips reasoning traces. |
| `extractJson` | `(text: string) => Promise<{extracted: string}>` | Extract JSON from reasoning model output. |

### Direct Utilities

For non-React environments or custom integrations:

```javascript
import { extractJSON, repairJSON, scanText } from 'react-ai-guard';

// Extract from DeepSeek/o1 output
const json = extractJSON('<think>...</think>{"data": 1}');

// Repair broken JSON
const fixed = repairJSON('{"incomplete": true');

// Scan for PII
const result = scanText('Email: test@example.com', ['EMAIL']);
```

### Supported PII Rules

| Rule ID | Description |
| :--- | :--- |
| `CREDIT_CARD` | Major credit card number formats (Visa, Mastercard, Amex). |
| `EMAIL` | Standard email address patterns. |
| `API_KEY` | High-entropy strings resembling API tokens (e.g., `sk-`, `ghp-`). |
| `SSN` | US Social Security Numbers (XXX-XX-XXXX format). |
| `IPV4` | IPv4 addresses. |
| `AWS_KEY` | AWS Access Key IDs (AKIA...). |
| `JWT` | JSON Web Tokens. |

## Demo

**Feature 1: Auto-Repairing Broken Streams**

Standard `JSON.parse` crashes when the stream cuts off. We fix it in real-time.

<video src="https://github.com/user-attachments/assets/80ce21fb-8017-4c48-b803-1813fcc1c369" controls="false" autoplay="true" loop="true" width="100%"></video>

## License

MIT
