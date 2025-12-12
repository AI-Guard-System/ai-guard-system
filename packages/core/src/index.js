/**
 * react-ai-guard v1.2.0
 * 
 * Stop letting LLMs crash your UI. Stop leaking secrets.
 * Now with reasoning model support (DeepSeek-R1, o1) and Vercel AI SDK integration.
 */

// The Core Hooks
export { useAIGuard } from './react/useAIGuard.js';
export { useStreamingJson, useTypedStream, useVercelStream } from './react/useStreamingJson.js';

// Core Utilities (for power users and non-React environments)
export { scanText } from './core/scanner.js';
export { repairJSON, extractJSON } from './core/repair.js';
