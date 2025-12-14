import React, { useState, useEffect } from 'react';
import { useAiGuard } from '@ai-guard/react';

export default function App() {
  const [inputText, setInputText] = useState('');
  const [displayResult, setDisplayResult] = useState({
    text: '',
    safe: true,
    matches: []
  });

  const { scanStream } = useAiGuard({
    pii: {
      redact: true,
      mode: 'block'
    }
  });

  // Handle live typing
  const handleChange = (e) => {
    const newText = e.target.value;
    setInputText(newText);

    // We treat this as a stream for the demo
    scanStream(newText).then(result => {
      // The result will contain the delta findings if we were purely stream-based, 
      // but our simplified hook logic might just return the scan of the chunk.
      // Wait, our useAiGuard.ts logic for scanStream takes the NEW text if it starts with old, 
      // or Resets.
      // But result from scanStream is: { safe, pii, injection, entropy }
      // The PII object has 'redactedText' for the whole input if using scanText, 
      // but for scanStream_CHUNK, does it return redacted chunk?
      // Let's look at the Worker trace:
      // Worker: SCAN_STREAM_CHUNK -> accumulates -> returns scan of TOTAL buffer? 
      // No, worker says: "Scan the accumulated buffer". 
      // So it returns the FULL scan result of the stream so far.
      // Perfect for this UI.

      // We want to show the redacted text.
      // result.pii.redactedText will be the full redacted buffer.

      if (result?.pii?.redactedText !== undefined) {
        setDisplayResult({
          text: result.pii.redactedText,
          safe: result.safe,
          matches: result.pii.findings
        });
      } else {
        // Maybe empty or safe?
        setDisplayResult({
          text: newText,
          safe: result?.safe,
          matches: []
        });
      }
    });
  };

  return (
    <div style={{
      display: 'flex', flexDirection: 'column', alignItems: 'center',
      fontFamily: 'Inter, sans-serif', padding: '2rem', height: '100vh',
      background: '#1a1a1a', color: '#fff'
    }}>
      <h1 style={{
        background: 'linear-gradient(to right, #4facfe 0%, #00f2fe 100%)',
        WebkitBackgroundClip: 'text', WebkitTextFillColor: 'transparent',
        fontSize: '2.5rem', marginBottom: '2rem'
      }}>
        Running Locally · v2.0.0
      </h1>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '2rem', width: '100%', maxWidth: '1000px' }}>

        {/* INPUT */}
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <label style={{ marginBottom: '0.5rem', fontWeight: 'bold', color: '#888' }}>
            INPUT STREAM (Type here)
          </label>
          <textarea
            value={inputText}
            onChange={handleChange}
            placeholder="Type 'My API key is sk-ant-12345678...'"
            style={{
              width: '100%', height: '300px', background: '#252525', border: '1px solid #333',
              borderRadius: '8px', padding: '1rem', color: '#e0e0e0', fontSize: '1rem',
              resize: 'none', outline: 'none'
            }}
          />
        </div>

        {/* OUTPUT */}
        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <label style={{ marginBottom: '0.5rem', fontWeight: 'bold', color: '#888' }}>
            AI GUARD OUTPUT (Real-time Redaction)
          </label>
          <div style={{
            width: '100%', height: '300px', background: '#111', border: displayResult.safe ? '1px solid #333' : '1px solid #ff4444',
            borderRadius: '8px', padding: '1rem', color: displayResult.safe ? '#4ade80' : '#ff4444',
            fontSize: '1rem', overflowY: 'auto'
          }}>
            {displayResult.text || "Waiting for input..."}
          </div>

          {displayResult.matches?.length > 0 && (
            <div style={{ marginTop: '1rem', fontSize: '0.8rem', color: '#ff4444' }}>
              Detected: {displayResult.matches.map(m => m.type).join(', ')}
            </div>
          )}
        </div>

      </div>

      <div style={{ marginTop: '2rem', color: '#666' }}>
        Status: {displayResult.safe ? 'Secure' : 'Threat Detected'}
      </div>
    </div>
  );
}
