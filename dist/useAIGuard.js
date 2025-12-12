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
 */

const PATTERNS = {
  // Simple Credit Card (Luhn algorithm is too slow for 100ms budget, strict regex is fine for v1)
  // Matches groups of 4 digits separated by spaces or dashes
  CREDIT_CARD: /\\b(?:\\d{4}[ -]?){3}\\d{4}\\b/,
  
  // Standard Email
  EMAIL: /\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b/,
  
  // Generic "Secret Key" patterns (catch-all for "sk-...", "api_key", etc)
  // Looks for "sk-" followed by 20+ alphanumerics
  API_KEY: /\\b(sk-[a-zA-Z0-9]{20,})\\b/,
  
  // US SSN (Area-Group-Serial)
  SSN: /\\b\\d{3}-\\d{2}-\\d{4}\\b/,
  
  // IP Address (IPv4)
  IPV4: /\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b/
};

/**
 * Scans text for specific PII types.
 * @param {string} text - The raw input.
 * @param {string[]} enabledRules - List of keys from PATTERNS to check.
 * @param {boolean} redact - If true, replaces with [REDACTED].
 */
function scanText(text, enabledRules = [], redact = false) {
  let cleanText = text;
  const findings = [];
  let isSafe = true;

  // Default to all rules if none specified (Safe by default)
  const rulesToCheck = enabledRules.length > 0 
    ? enabledRules 
    : Object.keys(PATTERNS);

  for (const rule of rulesToCheck) {
    const regex = PATTERNS[rule];
    if (!regex) continue; // Skip unknown rules

    // Create global regex for matching
    const globalRegex = new RegExp(regex.source, 'g');
    const matches = text.match(globalRegex);
    
    if (matches && matches.length > 0) {
      isSafe = false;
      findings.push({ type: rule, matches });
      
      if (redact) {
        cleanText = cleanText.replace(globalRegex, \`[\${rule}_REDACTED]\`);
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
 */

/**
 * strips markdown code blocks (\`\`\`json ... \`\`\`) from the string.
 * Handles partial streams where the closing \`\`\` hasn't arrived yet.
 */
function stripMarkdown(text) {
  if (!text) return "";
  let clean = text.trim();
  
  // FIX #6: Handle "\`\`\`javascript", "\`\`\`js", or just "\`\`\`"
  // ^ means start of string.
  // We remove everything from the first \`\`\` up to the newline.
  clean = clean.replace(/^\`\`\`[a-zA-Z]*\\s*/, "");

  // Remove closing \`\`\` if at the very end
  clean = clean.replace(/\\s*\`\`\`$/, "");

  return clean;
}

/**
 * Repairs a broken JSON string by auto-closing brackets and quotes.
 * @param {string} raw - The broken JSON string from a stream.
 * @returns {string} - A valid (or best-effort) JSON string.
 */
function repairJSON(raw) {
  // Pre-process: Remove markdown wrappers
  const text = stripMarkdown(raw);
  
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
        // Pop the string marker
        if (stack.length > 0 && stack[stack.length - 1] === '"') {
          stack.pop();
        }
      }
      continue;
    }

    if (inString) continue; // Ignore everything inside strings

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
    // Pop the string marker if we added it
    if (stack.length > 0 && stack[stack.length - 1] === '"') {
      stack.pop();
    }
  }

  // Handle trailing comma before closing (common LLM mistake)
  // Remove trailing comma if it's the last significant char
  result = result.replace(/,\\s*$/, '');

  // Now close remaining brackets in reverse order
  while (stack.length > 0) {
    const open = stack.pop();
    if (open === '{') {
      result += '}';
    } else if (open === '[') {
      result += ']';
    }
    // Ignore leftover string markers at this point
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
        // New: payload={text, enabledRules, redact}
        const scanText_input = typeof payload === 'string' ? payload : payload?.text;
        const scanText_rules = options?.rules || payload?.enabledRules || [];
        const scanText_redact = options?.redact ?? payload?.redact ?? false;
        result = scanText(scanText_input, scanText_rules, scanText_redact);
        break;

      case 'REPAIR_JSON':
        // Handle both: payload=string or payload={text}
        const repair_input = typeof payload === 'string' ? payload : payload?.text;
        const fixed = repairJSON(repair_input);
        
        // isValid = true if repaired JSON parses successfully
        // This will be true for every chunk (that's the point of repair)
        // Zod runs frequently — this is GOOD for streaming UX
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
