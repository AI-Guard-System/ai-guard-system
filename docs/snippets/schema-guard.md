# Feature: Streaming Schema Guard

Most LLM applications blindly `JSON.parse()` whatever the model outputs. If the model hallucinates a malicious key (e.g., `is_admin: true`), it passes straight to your UI state.

**react-ai-guard** introduces **Schema Enforced Streaming**.

**How it works:** We don't just validate types; we strictly enforce the shape. Any key not present in your Zod schema is strictly **stripped** from the stream before it ever reaches your React components.

### Example:

```javascript
// The model sends: { "role": "user", "admin": true }
// The schema expects: { role: string }
const { data } = useGuard(stream, { schema: UserSchema });

console.log(data); 
// Output: { "role": "user" } 
// "admin" key was incinerated in the kernel.
```
