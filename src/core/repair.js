/**
 * repair.js
 * Stack-Based Finite State Machine for JSON repair.
 * 
 * Takes broken streaming JSON and auto-closes it.
 * O(N). Fast. Deterministic.
 */

/**
 * strips markdown code blocks (```json ... ```) from the string.
 * Handles partial streams where the closing ``` hasn't arrived yet.
 */
export function stripMarkdown(text) {
  if (!text) return "";
  let clean = text.trim();
  
  // FIX #6: Handle "```javascript", "```js", or just "```"
  // ^ means start of string.
  // We remove everything from the first ``` up to the newline.
  clean = clean.replace(/^```[a-zA-Z]*\s*/, "");

  // Remove closing ``` if at the very end
  clean = clean.replace(/\s*```$/, "");

  return clean;
}

/**
 * Repairs a broken JSON string by auto-closing brackets and quotes.
 * @param {string} raw - The broken JSON string from a stream.
 * @returns {string} - A valid (or best-effort) JSON string.
 */
export function repairJSON(raw) {
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

    if (char === '\\' && inString) {
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

  // Handle trailing commas (common LLM mistake)
  // Remove commas that appear right before a closing bracket/brace
  result = result.replace(/,\s*(?=[}\]])/g, '');
  // Also remove a trailing comma at the very end
  result = result.replace(/,\s*$/, '');

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
