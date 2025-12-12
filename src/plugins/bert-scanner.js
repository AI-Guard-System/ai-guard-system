/**
 * @react-ai-guard/plugin-bert
 * 
 * Contextual PII detection using a quantized BERT model via ONNX Runtime Web.
 * 
 * This is a PLUGIN - it extends the base react-ai-guard with ML capabilities.
 * The model runs entirely client-side in the browser using WebAssembly.
 * 
 * Architecture:
 * 1. Load quantized BERT model (~10MB) via ONNX Runtime Web
 * 2. Tokenize input text
 * 3. Run inference to detect contextual PII (e.g., "My password is hunter2")
 * 4. Return enhanced scan results
 * 
 * This file is the SPEC - actual implementation requires:
 * - onnxruntime-web package
 * - Pre-trained/fine-tuned BERT model for PII detection
 * - Tokenizer (bert-tokenizer or similar)
 */

// Plugin interface that extends base scanner
export const BERT_PII_LABELS = [
  'O',           // Outside (not PII)
  'B-NAME',      // Beginning of Name
  'I-NAME',      // Inside Name
  'B-EMAIL',     // Beginning of Email
  'I-EMAIL',     // Inside Email
  'B-PHONE',     // Beginning of Phone
  'I-PHONE',     // Inside Phone
  'B-ADDRESS',   // Beginning of Address
  'I-ADDRESS',   // Inside Address
  'B-SSN',       // Beginning of SSN
  'I-SSN',       // Inside SSN
  'B-CREDIT',    // Beginning of Credit Card
  'I-CREDIT',    // Inside Credit Card
  'B-PASSWORD',  // Beginning of Password (contextual!)
  'I-PASSWORD',  // Inside Password
  'B-API_KEY',   // Beginning of API Key
  'I-API_KEY',   // Inside API Key
];

/**
 * BertScanner class - WASM-based contextual PII detection
 * 
 * Usage:
 * ```js
 * import { BertScanner } from '@react-ai-guard/plugin-bert';
 * 
 * const scanner = new BertScanner();
 * await scanner.load(); // Downloads ~10MB model
 * 
 * const result = await scanner.scan("My password is hunter2");
 * // { findings: [{ type: 'PASSWORD', text: 'hunter2', confidence: 0.94 }] }
 * ```
 */
export class BertScanner {
  constructor(options = {}) {
    this.modelPath = options.modelPath || '/models/pii-bert-quantized.onnx';
    this.vocabPath = options.vocabPath || '/models/vocab.txt';
    this.session = null;
    this.tokenizer = null;
    this.isLoaded = false;
    this.maxLength = options.maxLength || 128;
  }

  /**
   * Load the ONNX model and tokenizer
   * Call this once on app startup or lazily on first scan
   */
  async load() {
    if (this.isLoaded) return;

    // Dynamic import to avoid bundling if not used
    const ort = await import('onnxruntime-web');
    
    // Configure WASM backend
    ort.env.wasm.numThreads = navigator.hardwareConcurrency || 4;
    ort.env.wasm.simd = true;
    
    // Load model
    this.session = await ort.InferenceSession.create(this.modelPath, {
      executionProviders: ['wasm'],
      graphOptimizationLevel: 'all'
    });

    // Load tokenizer vocabulary
    const vocabResponse = await fetch(this.vocabPath);
    const vocabText = await vocabResponse.text();
    this.vocab = vocabText.split('\n');
    this.vocabMap = new Map(this.vocab.map((word, i) => [word, i]));
    
    this.isLoaded = true;
  }

  /**
   * Simple WordPiece tokenizer (BERT-style)
   * For production, use a proper tokenizer library
   */
  tokenize(text) {
    const tokens = ['[CLS]'];
    const words = text.toLowerCase().split(/\s+/);
    
    for (const word of words) {
      // Simple character-level fallback
      if (this.vocabMap.has(word)) {
        tokens.push(word);
      } else {
        // WordPiece: split into subwords
        let remaining = word;
        let isFirst = true;
        while (remaining.length > 0) {
          let found = false;
          for (let end = remaining.length; end > 0; end--) {
            const substr = isFirst ? remaining.slice(0, end) : '##' + remaining.slice(0, end);
            if (this.vocabMap.has(substr)) {
              tokens.push(substr);
              remaining = remaining.slice(end);
              isFirst = false;
              found = true;
              break;
            }
          }
          if (!found) {
            tokens.push('[UNK]');
            break;
          }
        }
      }
    }
    
    tokens.push('[SEP]');
    return tokens.slice(0, this.maxLength);
  }

  /**
   * Convert tokens to input tensors for ONNX
   */
  tokensToTensors(tokens) {
    const inputIds = tokens.map(t => this.vocabMap.get(t) || this.vocabMap.get('[UNK]'));
    const attentionMask = new Array(tokens.length).fill(1);
    const tokenTypeIds = new Array(tokens.length).fill(0);
    
    // Pad to maxLength
    while (inputIds.length < this.maxLength) {
      inputIds.push(0);
      attentionMask.push(0);
      tokenTypeIds.push(0);
    }
    
    return {
      input_ids: new BigInt64Array(inputIds.map(BigInt)),
      attention_mask: new BigInt64Array(attentionMask.map(BigInt)),
      token_type_ids: new BigInt64Array(tokenTypeIds.map(BigInt))
    };
  }

  /**
   * Run inference and extract PII entities
   */
  async scan(text) {
    if (!this.isLoaded) {
      await this.load();
    }

    const tokens = this.tokenize(text);
    const tensors = this.tokensToTensors(tokens);
    
    // Create ONNX tensors
    const ort = await import('onnxruntime-web');
    const feeds = {
      input_ids: new ort.Tensor('int64', tensors.input_ids, [1, this.maxLength]),
      attention_mask: new ort.Tensor('int64', tensors.attention_mask, [1, this.maxLength]),
      token_type_ids: new ort.Tensor('int64', tensors.token_type_ids, [1, this.maxLength])
    };

    // Run model
    const results = await this.session.run(feeds);
    const logits = results.logits.data; // [1, seq_len, num_labels]
    
    // Extract entities from predictions
    const findings = [];
    let currentEntity = null;
    
    for (let i = 1; i < tokens.length - 1; i++) { // Skip [CLS] and [SEP]
      const labelIdx = this.argmax(logits, i);
      const label = BERT_PII_LABELS[labelIdx];
      const confidence = this.softmax(logits, i)[labelIdx];
      
      if (label.startsWith('B-')) {
        // Start new entity
        if (currentEntity) {
          findings.push(currentEntity);
        }
        currentEntity = {
          type: label.slice(2),
          tokens: [tokens[i]],
          confidence,
          startIdx: i
        };
      } else if (label.startsWith('I-') && currentEntity) {
        // Continue entity
        currentEntity.tokens.push(tokens[i]);
        currentEntity.confidence = Math.min(currentEntity.confidence, confidence);
      } else {
        // End entity
        if (currentEntity) {
          findings.push(currentEntity);
          currentEntity = null;
        }
      }
    }
    
    if (currentEntity) {
      findings.push(currentEntity);
    }

    return {
      safe: findings.length === 0,
      findings: findings.map(f => ({
        type: f.type,
        text: f.tokens.join(' ').replace(/##/g, ''),
        confidence: f.confidence
      })),
      modelVersion: '1.0.0'
    };
  }

  argmax(logits, seqIdx) {
    const numLabels = BERT_PII_LABELS.length;
    const start = seqIdx * numLabels;
    let maxIdx = 0;
    let maxVal = logits[start];
    for (let i = 1; i < numLabels; i++) {
      if (logits[start + i] > maxVal) {
        maxVal = logits[start + i];
        maxIdx = i;
      }
    }
    return maxIdx;
  }

  softmax(logits, seqIdx) {
    const numLabels = BERT_PII_LABELS.length;
    const start = seqIdx * numLabels;
    const values = Array.from({ length: numLabels }, (_, i) => logits[start + i]);
    const maxVal = Math.max(...values);
    const exps = values.map(v => Math.exp(v - maxVal));
    const sum = exps.reduce((a, b) => a + b, 0);
    return exps.map(e => e / sum);
  }

  /**
   * Cleanup resources
   */
  dispose() {
    if (this.session) {
      this.session.release();
      this.session = null;
    }
    this.isLoaded = false;
  }
}

/**
 * React Hook for BERT-based PII scanning
 * 
 * Usage:
 * ```jsx
 * const { scan, isLoading, isReady } = useBertScanner();
 * 
 * const handleCheck = async () => {
 *   const result = await scan(userInput);
 *   if (!result.safe) {
 *     alert('PII detected: ' + result.findings.map(f => f.type).join(', '));
 *   }
 * };
 * ```
 */
export function useBertScanner(options = {}) {
  // This would be implemented as a React hook
  // For now, just export the class
  throw new Error(
    'useBertScanner requires @react-ai-guard/plugin-bert package. ' +
    'Install with: npm install @react-ai-guard/plugin-bert'
  );
}
