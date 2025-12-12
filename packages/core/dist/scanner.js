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
  CREDIT_CARD: /\b(?:\d{4}[ -]?){3}\d{4}\b/,
  
  // Standard Email
  EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  
  // Generic "Secret Key" patterns (sk-, ghp-, etc)
  API_KEY: /\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36})\b/,
  
  // US SSN (Area-Group-Serial)
  SSN: /\b\d{3}-\d{2}-\d{4}\b/,
  
  // IP Address (IPv4)
  IPV4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/,
  
  // AWS Access Key ID
  AWS_KEY: /\b(AKIA[0-9A-Z]{16})\b/,
  
  // JWT Token
  JWT: /\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b/
};

/**
 * Scans text for specific PII types.
 * @param {string} text - The raw input.
 * @param {string[]} enabledRules - List of keys from PATTERNS to check.
 * @param {boolean} redact - If true, replaces with [REDACTED].
 * @param {(string|RegExp)[]} allowList - Patterns to ignore (exceptions).
 * @param {object[]} customRules - Custom rules: [{ name: 'CUSTOM', pattern: /.../ }]
 */
export function scanText(text, enabledRules = [], redact = false, allowList = [], customRules = []) {
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
            cleanText = cleanText.replace(match, `[${rule}_REDACTED]`);
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
