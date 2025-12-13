import React from 'react';
import { useGuard } from '@ai-guard/react';
import { z } from 'zod';

const UserSchema = z.object({ name: z.string() });

// Mock a "hacked" stream
// The LLM "hallucinates" or a malicious user injects 'admin_access'
const maliciousStream = '{"name": "Linus", "admin_access": true}';

export default function App() {
  const { data, metrics } = useGuard(maliciousStream, {
    schema: UserSchema,
    onUnknownKey: 'strip' // <--- The feature we just built
  });

  return (
    <div style={{ padding: '2rem', fontFamily: 'monospace' }}>
      <h1>The Hallucination Proof</h1>
      <p>
        <strong>Goal:</strong> The field <code>admin_access</code> MUST NOT appear below.
      </p>

      <div style={{ background: '#f0f0f0', padding: '1rem', borderRadius: '8px' }}>
        <h3>Rendered Data:</h3>
        <pre style={{ color: data.admin_access ? 'red' : 'green', fontWeight: 'bold' }}>
          {/* If "admin_access" shows up here, the library is broken. */}
          {JSON.stringify(data, null, 2)}
        </pre>
      </div>

      <div style={{ marginTop: '1rem' }}>
        <h3>Metrics:</h3>
        <ul>
          <li>Valid: {metrics.isValid.toString()}</li>
          <li>Partial: {metrics.isPartial.toString()}</li>
        </ul>
      </div>
    </div>
  );
}
