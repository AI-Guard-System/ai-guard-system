import React, { useState, useEffect } from 'react';
import { useStreamingJson, useAIGuard } from 'react-ai-guard';

const BROKEN_STREAM_CHUNKS = [
  '{"user": {"na',
  'me": "Ali", "ro',
  'le": "admin", ',
  '"bi',
  'o": "He loves AI"}}'
];

function App() {
  const [input, setInput] = useState('');
  const [stream, setStream] = useState('');
  const { data, isValid } = useStreamingJson(stream);
  const { scanInput } = useAIGuard({ redact: true });
  const [piiResult, setPiiResult] = useState(null);

  const handleScan = async () => {
    const result = await scanInput(input);
    setPiiResult(result);
  };

  const runStream = () => {
    setStream('');
    let i = 0;
    const interval = setInterval(() => {
      if (i < BROKEN_STREAM_CHUNKS.length) {
        setStream(prev => prev + BROKEN_STREAM_CHUNKS[i]);
        i++;
      } else {
        clearInterval(interval);
      }
    }, 500);
  };

  return (
    <div style={{ padding: '2rem', fontFamily: 'sans-serif', maxWidth: '800px', margin: '0 auto' }}>
      <h1>react-ai-guard Demo</h1>

      <section style={{ marginBottom: '2rem', border: '1px solid #ccc', padding: '1rem', borderRadius: '8px' }}>
        <h2>1. PII Guard Defense</h2>
        <p>Type sensitive data (e.g. email, or API key like 'sk-...') to see the guard in action.</p>
        <textarea
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Enter text with PII..."
          rows={3}
          style={{ width: '100%', padding: '0.5rem', marginBottom: '0.5rem' }}
        />
        <button onClick={handleScan} style={{ padding: '0.5rem 1rem', cursor: 'pointer' }}>Scan Input</button>
        {piiResult && (
          <div style={{ marginTop: '1rem', background: '#f5f5f5', padding: '1rem', borderRadius: '4px' }}>
            <p><strong>Safe:</strong> {piiResult.safe ? '✅ Yes' : '❌ No'}</p>
            {!piiResult.safe && <p><strong>Findings:</strong> {JSON.stringify(piiResult.findings)}</p>}
            <p><strong>Redacted Output:</strong></p>
            <pre style={{ background: '#eee', padding: '0.5rem' }}>{piiResult.text}</pre>
          </div>
        )}
      </section>

      <section style={{ border: '1px solid #ccc', padding: '1rem', borderRadius: '8px' }}>
        <h2>2. Streaming JSON Repair</h2>
        <p>Simulates a broken JSON stream from an LLM.</p>
        <div style={{ display: 'flex', gap: '1rem', marginBottom: '1rem' }}>
          <button onClick={runStream} style={{ padding: '0.5rem 1rem', cursor: 'pointer' }}>Start Simulation</button>
        </div>

        <div style={{ background: '#333', color: '#fff', padding: '1rem', borderRadius: '4px', marginBottom: '1rem' }}>
          <strong>Raw Stream:</strong><br />
          <code style={{ wordBreak: 'break-all' }}>{stream}</code>
        </div>

        <div style={{ background: '#e0f7fa', padding: '1rem', borderRadius: '4px', border: '1px solid #b2ebf2' }}>
          <strong>Live Parsed Object (useStreamingJson):</strong>
          <pre style={{ margin: '0.5rem 0' }}>{JSON.stringify(data, null, 2)}</pre>
          <small>Valid JSON: {isValid ? 'Yes' : 'No'}</small>
        </div>
      </section>
    </div>
  );
}

export default App;
