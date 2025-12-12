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
  CREDIT_CARD: /\b(?:\d{4}[ -]?){3}\d{4}\b/,
  
  // Standard Email
  EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  
  // Generic "Secret Key" patterns (catch-all for "sk-...", "api_key", etc)
  // Looks for "sk-" followed by 20+ alphanumerics
  API_KEY: /\b(sk-[a-zA-Z0-9]{20,})\b/,
  
  // US SSN (Area-Group-Serial)
  SSN: /\b\d{3}-\d{2}-\d{4}\b/,
  
  // IP Address (IPv4)
  IPV4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/
};

/**
 * Scans text for specific PII types.
 * @param {string} text - The raw input.
 * @param {string[]} enabledRules - List of keys from PATTERNS to check.
 * @param {boolean} redact - If true, replaces with [REDACTED].
 */
export function scanText(text, enabledRules = [], redact = false) {
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
        cleanText = cleanText.replace(globalRegex, `[${rule}_REDACTED]`);
      }
    }
  }

  return {
    safe: isSafe,
    findings,
    text: cleanText
  };
}
