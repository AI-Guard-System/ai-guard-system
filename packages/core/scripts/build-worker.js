#!/usr/bin/env node
/**
 * build-worker.js
 * 
 * Inlines the worker code into useAIGuard.js as a Blob.
 * This makes the library work with ANY bundler (Vite, Next.js, Webpack)
 * without requiring user configuration.
 * 
 * The ugly truth: new Worker(new URL(...)) breaks in node_modules.
 * The solution: Blob URLs.
 * 
 * CRITICAL: Blob URLs have NO filesystem. We must inline ALL dependencies
 * directly into the worker source. No imports allowed in the final output.
 */

import { readFileSync, writeFileSync, mkdirSync, existsSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT = join(__dirname, '..');

// Read the core modules
const scannerCode = readFileSync(join(ROOT, 'src/core/scanner.js'), 'utf8');
const repairCode = readFileSync(join(ROOT, 'src/core/repair.js'), 'utf8');
const workerCode = readFileSync(join(ROOT, 'src/worker/index.js'), 'utf8');

/**
 * Strip all import statements from a file.
 * Blob URLs have no filesystem - imports WILL crash.
 */
function stripImports(code) {
  return code.replace(/^import\s+.*from\s+['"].*['"];?\s*$/gm, '').trim();
}

/**
 * Convert exports to plain function declarations.
 * "export function foo" -> "function foo"
 * "export const foo" -> "const foo"
 */
function stripExports(code) {
  return code
    .replace(/^export\s+function\s+/gm, 'function ')
    .replace(/^export\s+const\s+/gm, 'const ')
    .replace(/^export\s+\{[^}]*\};?\s*$/gm, '') // Remove "export { foo, bar };"
    .trim();
}

// Process each file: strip imports AND exports
const scannerClean = stripExports(stripImports(scannerCode));
const repairClean = stripExports(stripImports(repairCode));
const workerClean = stripImports(workerCode); // Keep structure, just remove imports

// Build the combined worker source
// Order matters: dependencies first, then the worker entry
const combinedWorkerSource = `
// ============================================
// INLINED WORKER CODE (auto-generated)
// DO NOT EDIT - regenerate with: npm run build
// ============================================

// --- src/core/scanner.js ---
${scannerClean}

// --- src/core/repair.js ---
${repairClean}

// --- src/worker/index.js ---
${workerClean}
`.trim();

// Escape for use in a JS template literal
function escapeForTemplateLiteral(str) {
  return str
    .replace(/\\/g, '\\\\')  // Escape backslashes first
    .replace(/`/g, '\\`')    // Escape backticks
    .replace(/\$\{/g, '\\${'); // Escape template expressions
}

const escapedSource = escapeForTemplateLiteral(combinedWorkerSource);

// Generate the new useAIGuard.js with SINGLETON pattern and inlined worker
const useAIGuardTemplate = `import { useEffect, useRef, useCallback } from 'react';

// --- GLOBAL SINGLETON SCOPE ---
let sharedWorker = null;
let workerScriptUrl = null;
const pendingRequests = new Map();

/**
 * Worker code inlined as a Blob for universal bundler compatibility.
 * 
 * Why? Because \\\`new Worker(new URL('./worker.js', import.meta.url))\\\`
 * breaks when your package is inside node_modules. Every bundler
 * handles it differently. Vite works. Next.js doesn't. Webpack needs config.
 * 
 * The Blob trick works EVERYWHERE. Zero config for the user.
 */
const INLINE_WORKER_CODE = \`${escapedSource}\`;

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
`;

// Ensure dist directory exists
const distDir = join(ROOT, 'dist');
if (!existsSync(distDir)) {
  mkdirSync(distDir, { recursive: true });
}

// Write the bundled useAIGuard
writeFileSync(join(distDir, 'useAIGuard.js'), useAIGuardTemplate);

// Copy useStreamingJson (it imports from local useAIGuard, that's fine)
const useStreamingJson = readFileSync(join(ROOT, 'src/react/useStreamingJson.js'), 'utf8');
writeFileSync(join(distDir, 'useStreamingJson.js'), useStreamingJson);

// Create dist/index.js
const indexContent = `/**
 * react-ai-guard
 * 
 * Stop letting LLMs crash your UI. Stop leaking secrets.
 */

// The Core Hooks
export { useAIGuard } from './useAIGuard.js';
export { useStreamingJson, useTypedStream } from './useStreamingJson.js';

// Utilities (for power users who want direct access)
export { scanText } from './scanner.js';
`;
writeFileSync(join(distDir, 'index.js'), indexContent);

// Copy scanner.js for direct imports (with exports intact)
writeFileSync(join(distDir, 'scanner.js'), scannerCode);

console.log('✓ Worker inlined into dist/useAIGuard.js (SINGLETON pattern)');
console.log('✓ Built dist/useStreamingJson.js');
console.log('✓ Built dist/index.js');
console.log('✓ Copied dist/scanner.js');
console.log('');
console.log('Build complete. Publish from /dist');
