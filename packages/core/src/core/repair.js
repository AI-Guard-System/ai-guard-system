/**
 * repair.js
 * Stack-Based Finite State Machine for JSON repair.
 * 
 * Takes broken streaming JSON and auto-closes it.
 * O(N). Fast. Deterministic.
 * 
 * v1.2.0: Added extractJSON for reasoning models (DeepSeek, o1)
 * v1.3.0: Added Transparent Mode (Patches & IsPartial)
 */

/**
 * Strips markdown code blocks (```json ... ```) from the string.
 * Handles partial streams where the closing ``` hasn't arrived yet.
 */
export function stripMarkdown(text) {
  if (!text) return "";
  let clean = text.trim();

  // Handle "```javascript", "```js", "```json", or just "```"
  clean = clean.replace(/^```[a-zA-Z]*\s*/, "");

  // Remove closing ``` if at the very end
  clean = clean.replace(/\s*```$/, "");

  return clean;
}

/**
 * Extracts JSON from mixed content (reasoning traces, markdown, prose).
 * 
 * Handles:
 * - <think>...</think> reasoning traces (DeepSeek-R1, o1)
 * - Markdown code blocks ```json ... ```
 * - Prose before/after JSON: "Here is your data: {...} Let me know!"
 * - Multiple JSON blocks (returns last complete one, or last partial)
 * 
 * @param {string} text - Raw LLM output with mixed content
 * @param {object} options
 * @param {boolean} options.last - Return last JSON block instead of first (default: true)
 * @returns {string} - Extracted JSON string (may still need repair)
 */
export function extractJSON(text, options = {}) {
  if (!text) return "";

  const { last = true } = options;

  let clean = text;

  // Step 1: Remove <think>...</think> reasoning traces (DeepSeek-R1, o1-style)
  // Handle both complete and partial (unclosed) think tags
  clean = clean.replace(/<think>[\s\S]*?<\/think>/gi, '');
  clean = clean.replace(/<think>[\s\S]*$/gi, ''); // Partial unclosed tag

  // Step 2: Extract from markdown code blocks first (highest priority)
  const codeBlockRegex = /```(?:json|json5|javascript|js)?\s*([\s\S]*?)(?:```|$)/gi;
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

    if (char === '\\' && inString) {
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
 * Now returns a transparent repair report.
 * 
 * @param {string} raw - The broken JSON string from a stream.
 * @param {object} options
 * @param {boolean} options.extract - Run extractJSON first (for reasoning models)
 * @returns {object} - { fixed, data, isPartial, patches }
 */
export function repairJSON(raw, options = {}) {
  const { extract = false } = options;

  // Pre-process: Extract JSON if requested (for reasoning models)
  let text = extract ? extractJSON(raw) : stripMarkdown(raw);

  // Empty check
  if (!text || !text.trim()) {
    return {
      fixed: "{}",
      data: {},
      isPartial: false,
      patches: []
    };
  }

  let result = text.trim();
  const patches = [];
  let isPartial = false;

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

    if (char === '\\' && inString) {
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
    patches.push({ type: 'unclosed_string', index: result.length });
    result += '"';
    isPartial = true;
    if (stack.length > 0 && stack[stack.length - 1] === '"') {
      stack.pop();
    }
  }

  // Handle trailing comma before closing
  if (/,\s*$/.test(result)) {
    const match = result.match(/,\s*$/);
    patches.push({ type: 'trailing_comma', index: match.index });
    result = result.replace(/,\s*$/, '');
    isPartial = true;
  }

  // Close remaining brackets in reverse order
  while (stack.length > 0) {
    const open = stack.pop();
    if (open === '{') {
      patches.push({ type: 'missing_brace', index: result.length });
      result += '}';
      isPartial = true;
    } else if (open === '[') {
      patches.push({ type: 'missing_brace', index: result.length });
      result += ']';
      isPartial = true;
    }
  }

  // Attempt to parse
  let data = null;
  try {
    data = JSON.parse(result);
  } catch (err) {
    // If it still fails, data remains null
  }

  return {
    fixed: result,
    data,
    isPartial,
    patches
  };
}
