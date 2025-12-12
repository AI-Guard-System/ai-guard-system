# react-ai-guard

**Stop letting LLMs crash your UI. Stop leaking secrets. It is not that hard.**

Most "AI" developers today seem to believe that `JSON.parse()` is a valid strategy for handling streaming text from a Large Language Model. It is not. It is optimistic, fragile, and lazy.

When you pipe raw, non-deterministic output from a chatbot directly into your application state, you are asking for a crash. When you let users paste API keys into a text box without checking them, you are asking for a lawsuit.

This library does two things, and it does them correctly:

1. **It repairs broken JSON streams on the fly** (closing missing brackets, fixing quotes) so your UI doesn't white-screen.

2. **It blocks PII** (secrets, credit cards, emails) in the browser, before the data ever touches the network.

It runs in a Web Worker. It keeps your main thread at 60fps. It has zero dependencies on "cloud guardrails."

---

## The Problem

You are building a chat interface. The LLM sends this chunk:

```json
{"user": {"name": "Linus", "role": "admin
```

Your app tries to parse it. Crash. `SyntaxError: Unexpected end of JSON input`.

So you write a try/catch. Great. Now your UI is frozen until the entire stream finishes. You have defeated the purpose of streaming.

---

## The Solution

`react-ai-guard` implements a **Stack-Based Finite State Machine** that tracks depth and context. It knows how to "auto-close" a broken JSON structure at any byte offset. It turns the garbage above into this:

```json
{"user": {"name": "Linus", "role": "admin"}}
```

It is O(N). It is fast. It is deterministic.

---

## Installation

```bash
npm install react-ai-guard
```

(Or yarn, or pnpm. Just get the package.)

---

## Usage

### 1. The JSON Repair Hook (`useStreamingJson`)

Use this when you are streaming structured data from an LLM.

```javascript
import { useStreamingJson } from 'react-ai-guard';

const MyComponent = () => {
  // partialString is the raw, broken text coming from the socket
  // data is the Safe, Validated Object. It never crashes.
  const { data } = useStreamingJson(partialString);

  return <div>Hello, {data?.user?.name || 'Loading...'}</div>;
};
```

### 2. The Firewall Hook (`useAIGuard`)

Use this to prevent users (or employees) from pasting stupid things into your model.

```javascript
import { useAIGuard } from 'react-ai-guard';

const ChatInput = () => {
  const { scanInput } = useAIGuard({
    rules: ['CREDIT_CARD', 'API_KEY', 'EMAIL'],
    redact: true // Turns "sk-12345" into "[REDACTED]"
  });

  const handleSubmit = async (text) => {
    const check = await scanInput(text);
    
    if (!check.safe) {
      alert("Found sensitive data: " + check.reasons.join(", "));
      return; // The network request never happens.
    }
    
    sendMessage(check.sanitized); // Send the [REDACTED] version
  };
};
```

---

## Architecture (For those who care)

I refuse to ship a library that blocks the main thread.

- **The Engine**: All Regex scanning and JSON parsing happens in a dedicated Web Worker.
- **The Scanner**: We use strict Regex patterns. No "AI detecting AI." Determinism is the only way to ensure safety.
- **The Parser**: A custom recursive descent tokenizer. It handles escaped quotes, nested arrays, and trailing commas.

---

## Contributing

1. Do not break the build.
2. Do not add dependencies. I don't want your 50MB "utility" library. Write the code yourself.
3. Test your code. If you send a PR without a test case for the bug you fixed, I will close it.

---

## License

MIT
