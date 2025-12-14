# Security Policy & Defense in Depth

## Client-Side Limitations

**React AI Guard** operates primarily in the client's browser (or Edge runtime). While it provides robust "Defense in Depth" (e.g., preventing accidental PII leaks or checking inputs before they leave the browser), **it is not a replacement for server-side security.**

### 1. Browser Environment
- The API keys and logic reside in the user's browser memory. Sophisticated attackers who control the browser can bypass these checks (e.g., by disabling JavaScript or modifying the Worker).
- **Recommendation:** Always validate sensitive operations (like API calls) on your backend.

### 2. Regex & Heuristics
- Our detection engines (Shannon Entropy, Injection Heuristics, PII Regex) are probabilistic. They may have false positives or false negatives.
- **Recommendation:** Treat the `score` as a signal, not an absolute truth.

### 3. API Key Management
- Never hardcode production API keys in client-side code, even with this guard in place.
- Use a proxy server or Backend-for-Frontend (BFF) to hold keys.
- AI Guard helps detect *accidental* inclusion of keys in user prompts, not malicious key extraction from your source code.

## Reporting a Vulnerability

If you bypass the guard in a novel way that could affect many users, please report it.

Email: security@ai-guard.dev
We allow 48 hours for triage.
