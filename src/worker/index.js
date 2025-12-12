import { repairJSON } from '../core/repair.js';
import { scanText } from '../core/scanner.js';

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
        throw new Error(`Unknown message type: ${type}`);
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
};
