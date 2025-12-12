/**
 * react-ai-guard
 * 
 * Stop letting LLMs crash your UI. Stop leaking secrets.
 */

// The Core Hooks
export { useAIGuard } from './react/useAIGuard.js';
export { useStreamingJson } from './react/useStreamingJson.js';

// Utilities (Optional, but "power users" might want them)
// We export the Worker logic via the hook, but maybe someone wants 
// to use the regex patterns directly?
export { scanText } from './core/scanner.js';
