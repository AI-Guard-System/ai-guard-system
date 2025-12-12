/**
 * react-ai-guard
 * 
 * Stop letting LLMs crash your UI. Stop leaking secrets.
 */

// The Core Hooks
export { useAIGuard } from './useAIGuard.js';
export { useStreamingJson, useTypedStream } from './useStreamingJson.js';

// Utilities (for power users who want direct access)
export { scanText } from './scanner.js';
