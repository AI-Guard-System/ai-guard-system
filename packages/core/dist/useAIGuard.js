import { useEffect, useRef, useCallback } from 'react';

// --- GLOBAL SINGLETON SCOPE ---
let sharedWorker = null;
let workerScriptUrl = null;
const pendingRequests = new Map();

/**
 * Worker code inlined as a Blob for universal bundler compatibility.
 * 
 * Why? Because \`new Worker(new URL('./worker.js', import.meta.url))\`
 * breaks when your package is inside node_modules. Every bundler
 * handles it differently. Vite works. Next.js doesn't. Webpack needs config.
 * 
 * The Blob trick works EVERYWHERE. Zero config for the user.
 */
const INLINE_WORKER_CODE = `// ============================================
// INLINED WORKER CODE (auto-generated)
// DO NOT EDIT - regenerate with: npm run build
// ============================================

// --- src/core/scanner.js ---
/**
 * scanner.js
 * The logic for detecting PII and secrets.
 * 
 * Rules:
 * 1. Fail fast.
 * 2. Deterministic matching.
 * 
 * v1.2.0: Added allow-lists and custom rules
 */

const PATTERNS = {
  // Credit Card - groups of 4 digits separated by spaces or dashes
  CREDIT_CARD: /\\b(?:\\d{4}[ -]?){3}\\d{4}\\b/,
  
  // Standard Email
  EMAIL: /\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b/,
  
  // Generic "Secret Key" patterns (sk-, ghp-, etc)
  API_KEY: /\\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36})\\b/,
  
  // US SSN (Area-Group-Serial)
  SSN: /\\b\\d{3}-\\d{2}-\\d{4}\\b/,
  
  // IP Address (IPv4)
  IPV4: /\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b/,
  
  // AWS Access Key ID
  AWS_KEY: /\\b(AKIA[0-9A-Z]{16})\\b/,
  
  // JWT Token
  JWT: /\\beyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*\\b/
};

/**
 * Scans text for specific PII types.
 * @param {string} text - The raw input.
 * @param {string[]} enabledRules - List of keys from PATTERNS to check.
 * @param {boolean} redact - If true, replaces with [REDACTED].
 * @param {(string|RegExp)[]} allowList - Patterns to ignore (exceptions).
 * @param {object[]} customRules - Custom rules: [{ name: 'CUSTOM', pattern: /.../ }]
 */
function scanText(text, enabledRules = [], redact = false, allowList = [], customRules = []) {
  let cleanText = text;
  const findings = [];
  let isSafe = true;

  // Build combined pattern map (built-in + custom)
  const allPatterns = { ...PATTERNS };
  for (const rule of customRules) {
    if (rule.name && rule.pattern) {
      allPatterns[rule.name] = rule.pattern;
    }
  }

  // Default to all rules if none specified
  const rulesToCheck = enabledRules.length > 0 
    ? enabledRules 
    : Object.keys(allPatterns);

  // Pre-compile allow-list patterns
  const allowPatterns = allowList.map(p => 
    typeof p === 'string' ? new RegExp(p) : p
  );

  for (const rule of rulesToCheck) {
    const regex = allPatterns[rule];
    if (!regex) continue;

    // Create global regex for matching
    const globalRegex = new RegExp(regex.source, 'g');
    const matches = text.match(globalRegex);
    
    if (matches && matches.length > 0) {
      // Filter out allowed matches
      const filteredMatches = matches.filter(match => 
        !allowPatterns.some(allow => allow.test(match))
      );
      
      if (filteredMatches.length > 0) {
        isSafe = false;
        findings.push({ type: rule, matches: filteredMatches });
        
        if (redact) {
          for (const match of filteredMatches) {
            cleanText = cleanText.replace(match, \`[\${rule}_REDACTED]\`);
          }
        }
      }
    }
  }

  return {
    safe: isSafe,
    findings,
    text: cleanText
  };
}

// --- src/core/repair.js ---
/**
 * repair.js
 * Stack-Based Finite State Machine for JSON repair.
 * 
 * Takes broken streaming JSON and auto-closes it.
 * O(N). Fast. Deterministic.
 * 
 * v1.2.0: Added extractJSON for reasoning models (DeepSeek, o1)
 */

/**
 * Strips markdown code blocks (\`\`\`json ... \`\`\`) from the string.
 * Handles partial streams where the closing \`\`\` hasn't arrived yet.
 */
function stripMarkdown(text) {
  if (!text) return "";
  let clean = text.trim();
  
  // Handle "\`\`\`javascript", "\`\`\`js", "\`\`\`json", or just "\`\`\`"
  clean = clean.replace(/^\`\`\`[a-zA-Z]*\\s*/, "");

  // Remove closing \`\`\` if at the very end
  clean = clean.replace(/\\s*\`\`\`$/, "");

  return clean;
}

/**
 * Extracts JSON from mixed content (reasoning traces, markdown, prose).
 * 
 * Handles:
 * - <think>...</think> reasoning traces (DeepSeek-R1, o1)
 * - Markdown code blocks \`\`\`json ... \`\`\`
 * - Prose before/after JSON: "Here is your data: {...} Let me know!"
 * - Multiple JSON blocks (returns last complete one, or last partial)
 * 
 * @param {string} text - Raw LLM output with mixed content
 * @param {object} options
 * @param {boolean} options.last - Return last JSON block instead of first (default: true)
 * @returns {string} - Extracted JSON string (may still need repair)
 */
function extractJSON(text, options = {}) {
  if (!text) return "";
  
  const { last = true } = options;
  
  let clean = text;
  
  // Step 1: Remove <think>...</think> reasoning traces (DeepSeek-R1, o1-style)
  // Handle both complete and partial (unclosed) think tags
  clean = clean.replace(/<think>[\\s\\S]*?<\\/think>/gi, '');
  clean = clean.replace(/<think>[\\s\\S]*$/gi, ''); // Partial unclosed tag
  
  // Step 2: Extract from markdown code blocks first (highest priority)
  const codeBlockRegex = /\`\`\`(?:json|json5|javascript|js)?\\s*([\\s\\S]*?)(?:\`\`\`|$)/gi;
  const codeBlocks = [];
  let match;
  
  while ((match = codeBlockRegex.exec(clean)) !== null) {
    const content = match[1].trim();
    if (content && (content.startsWith('{') || content.startsWith('['))) {
      codeBlocks.push(content);
    }
  }
  
  if (codeBlocks.length > 0) {
    return last ? codeBlocks[codeBlocks.length - 1] : codeBlocks[0];
  }
  
  // Step 3: No code blocks - find raw JSON in the text
  // Look for { or [ that starts a JSON structure
  const jsonCandidates = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;
  
  for (let i = 0; i < clean.length; i++) {
    const char = clean[i];
    
    if (escaped) {
      escaped = false;
      continue;
    }
    
    if (char === '\\\\' && inString) {
      escaped = true;
      continue;
    }
    
    if (char === '"' && !escaped) {
      inString = !inString;
      continue;
    }
    
    if (inString) continue;
    
    if (char === '{' || char === '[') {
      if (depth === 0) start = i;
      depth++;
    } else if (char === '}' || char === ']') {
      depth--;
      if (depth === 0 && start !== -1) {
        // Found complete JSON block
        jsonCandidates.push(clean.slice(start, i + 1));
        start = -1;
      }
    }
  }
  
  // Handle incomplete JSON (stream still coming)
  if (start !== -1 && depth > 0) {
    jsonCandidates.push(clean.slice(start));
  }
  
  if (jsonCandidates.length > 0) {
    return last ? jsonCandidates[jsonCandidates.length - 1] : jsonCandidates[0];
  }
  
  // Step 4: Fallback - try to find anything that looks like JSON start
  const firstBrace = clean.indexOf('{');
  const firstBracket = clean.indexOf('[');
  
  if (firstBrace === -1 && firstBracket === -1) {
    return clean.trim(); // No JSON found, return as-is for repair to handle
  }
  
  const jsonStart = firstBrace === -1 ? firstBracket : 
                    firstBracket === -1 ? firstBrace :
                    Math.min(firstBrace, firstBracket);
  
  return clean.slice(jsonStart).trim();
}

/**
 * Repairs a broken JSON string by auto-closing brackets and quotes.
 * @param {string} raw - The broken JSON string from a stream.
 * @param {object} options
 * @param {boolean} options.extract - Run extractJSON first (for reasoning models)
 * @returns {string} - A valid (or best-effort) JSON string.
 */
function repairJSON(raw, options = {}) {
  const { extract = false } = options;
  
  // Pre-process: Extract JSON if requested (for reasoning models)
  let text = extract ? extractJSON(raw) : stripMarkdown(raw);
  
  // If it's empty or just whitespace, return empty object
  if (!text || !text.trim()) return "{}";

  let result = text.trim();
  
  // State machine
  const stack = [];
  let inString = false;
  let escaped = false;

  for (let i = 0; i < result.length; i++) {
    const char = result[i];

    if (escaped) {
      escaped = false;
      continue;
    }

    if (char === '\\\\' && inString) {
      escaped = true;
      continue;
    }

    if (char === '"' && !escaped) {
      inString = !inString;
      if (inString) {
        stack.push('"');
      } else {
        if (stack.length > 0 && stack[stack.length - 1] === '"') {
          stack.pop();
        }
      }
      continue;
    }

    if (inString) continue;

    if (char === '{') {
      stack.push('{');
    } else if (char === '[') {
      stack.push('[');
    } else if (char === '}') {
      if (stack.length > 0 && stack[stack.length - 1] === '{') {
        stack.pop();
      }
    } else if (char === ']') {
      if (stack.length > 0 && stack[stack.length - 1] === '[') {
        stack.pop();
      }
    }
  }

  // Auto-close: First close any open string
  if (inString) {
    result += '"';
    if (stack.length > 0 && stack[stack.length - 1] === '"') {
      stack.pop();
    }
  }

  // Handle trailing comma before closing
  result = result.replace(/,\\s*$/, '');

  // Close remaining brackets in reverse order
  while (stack.length > 0) {
    const open = stack.pop();
    if (open === '{') {
      result += '}';
    } else if (open === '[') {
      result += ']';
    }
  }

  return result;
}

// --- src/worker/index.js ---
// Message Event Listener
self.onmessage = (e) => {
  const { id, type, payload, options } = e.data;

  try {
    let result;

    switch (type) {
      case 'SCAN_TEXT':
        // Handle both shapes: 
        // Old: payload=string, options={rules, redact}
        // New: payload={text, enabledRules, redact, allow, customRules}
        const scanText_input = typeof payload === 'string' ? payload : payload?.text;
        const scanText_rules = options?.rules || payload?.enabledRules || [];
        const scanText_redact = options?.redact ?? payload?.redact ?? false;
        const scanText_allow = options?.allow || payload?.allow || [];
        const scanText_customRules = options?.customRules || payload?.customRules || [];
        result = scanText(scanText_input, scanText_rules, scanText_redact, scanText_allow, scanText_customRules);
        break;

      case 'REPAIR_JSON':
        // Handle both: payload=string or payload={text, extract}
        const repair_input = typeof payload === 'string' ? payload : payload?.text;
        const repair_extract = options?.extract ?? payload?.extract ?? false;
        const fixed = repairJSON(repair_input, { extract: repair_extract });
        
        // isValid = true if repaired JSON parses successfully
        let isValid = false;
        let parsed = null;
        try {
          parsed = JSON.parse(fixed);
          isValid = true;
        } catch {
          isValid = false;
        }

        result = {
          raw: fixed,
          fixedString: fixed,
          data: parsed,
          isValid
        };
        break;

      case 'EXTRACT_JSON':
        // Pure extraction without repair (for inspection)
        const extract_input = typeof payload === 'string' ? payload : payload?.text;
        const extract_last = options?.last ?? payload?.last ?? true;
        const extracted = extractJSON(extract_input, { last: extract_last });
        result = { extracted };
        break;

      default:
        throw new Error(\`Unknown message type: \${type}\`);
    }

    // Send Success Response
    self.postMessage({
      id,
      success: true,
      payload: result
    });

  } catch (error) {
    // Send Error Response
    self.postMessage({
      id,
      success: false,
      error: error.message
    });
  }
};`;

function getWorker() {
  if (sharedWorker) return sharedWorker;

  if (typeof window === 'undefined') return null; // SSR protection

  // Create the Blob URL once
  if (!workerScriptUrl) {
    const blob = new Blob([INLINE_WORKER_CODE], { type: 'application/javascript' });
    workerScriptUrl = URL.createObjectURL(blob);
  }

  sharedWorker = new Worker(workerScriptUrl);

  // Global Message Listener
  sharedWorker.onmessage = (e) => {
    const { id, success, payload, error } = e.data;
    const req = pendingRequests.get(id);
    if (req) {
      clearTimeout(req.timeout);
      if (success) req.resolve(payload);
      else req.reject(new Error(error));
      pendingRequests.delete(id);
    }
  };

  // Handle worker errors (reject all pending requests)
  sharedWorker.onerror = (err) => {
    console.error('[react-ai-guard] Worker error:', err);
    pendingRequests.forEach((req, id) => {
      clearTimeout(req.timeout);
      req.reject(new Error('Worker error: ' + (err.message || 'Unknown')));
      pendingRequests.delete(id);
    });
  };

  return sharedWorker;
}

// --- THE HOOK ---
export function useAIGuard(config = {}) {
  const workerRef = useRef(null);

  useEffect(() => {
    workerRef.current = getWorker();
    // No cleanup - worker lives for app lifetime
  }, []);

  const post = useCallback((type, payload, options) => {
    const worker = getWorker();
    if (!worker) return Promise.reject(new Error("Worker not initialized"));

    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      // Timeout: reject if worker doesn't respond in 30s (prevents memory leak)
      const timeout = setTimeout(() => {
        pendingRequests.delete(id);
        reject(new Error('Worker timeout (30s)'));
      }, 30000);
      
      pendingRequests.set(id, { resolve, reject, timeout });
      worker.postMessage({ id, type, payload, options });
    });
  }, []);

  const scanInput = useCallback((text, options = {}) => {
    return post('SCAN_TEXT', text, { 
      rules: options.rules || config.rules, 
      redact: options.redact || config.redact 
    });
  }, [post, config.rules, config.redact]);

  const repairJson = useCallback((raw) => {
    return post('REPAIR_JSON', raw);
  }, [post]);

  return { scanInput, repairJson };
}
