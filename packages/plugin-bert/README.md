# @react-ai-guard/plugin-bert

> Contextual PII detection using BERT. Catches "My password is hunter2" that regex misses.

## Why?

Regex-based PII detection is dumb. It catches `4111-1111-1111-1111` but misses:

- "My password is hunter2"
- "Call me at five five five one two three four"
- "I live on 123 Main Street"

This plugin uses a quantized BERT model (~10MB) running entirely in the browser via WebAssembly. No server calls. No data leaves the device.

## Installation

```bash
npm install @react-ai-guard/plugin-bert
```

## Usage

```jsx
import { useBertScanner } from '@react-ai-guard/plugin-bert';

function ChatInput() {
  const { scan, isReady, isLoading } = useBertScanner();
  const [input, setInput] = useState('');
  
  const handleSubmit = async () => {
    const result = await scan(input);
    
    if (!result.safe) {
      alert(`⚠️ Detected: ${result.findings.map(f => f.type).join(', ')}`);
      return;
    }
    
    // Safe to send
    sendToAPI(input);
  };

  return (
    <div>
      <textarea 
        value={input} 
        onChange={e => setInput(e.target.value)}
        disabled={isLoading}
      />
      <button onClick={handleSubmit} disabled={!isReady}>
        {isLoading ? 'Loading AI...' : 'Send'}
      </button>
    </div>
  );
}
```

## Combining with Base Scanner

Use BERT for deep analysis, regex for speed:

```jsx
import { useAIGuard } from 'react-ai-guard';
import { useBertScanner } from '@react-ai-guard/plugin-bert';

function SecureInput() {
  const { scanInput } = useAIGuard(); // Fast regex
  const { scan: deepScan } = useBertScanner(); // Smart BERT
  
  const handleSubmit = async (text) => {
    // Level 1: Fast regex check (< 1ms)
    const quickResult = await scanInput(text);
    if (!quickResult.safe) {
      return { blocked: true, reason: 'regex', findings: quickResult.findings };
    }
    
    // Level 2: Deep BERT check (~50ms)
    const deepResult = await deepScan(text);
    if (!deepResult.safe) {
      return { blocked: true, reason: 'contextual', findings: deepResult.findings };
    }
    
    return { blocked: false };
  };
}
```

## Model Details

- **Architecture**: DistilBERT (66M params, quantized to ~10MB)
- **Training**: Fine-tuned on PII detection datasets
- **Labels**: NAME, EMAIL, PHONE, ADDRESS, SSN, CREDIT_CARD, PASSWORD, API_KEY
- **Inference**: ~50ms on modern hardware via ONNX Runtime Web (WASM)

## Performance

| Device | Load Time | Inference |
|--------|-----------|-----------|
| M1 Mac | 1.2s | 35ms |
| Modern Desktop | 1.5s | 45ms |
| iPhone 14 | 2.1s | 65ms |
| Budget Android | 3.5s | 120ms |

## License

MIT
