import { useEffect, useRef, useState, useCallback } from 'react';

// --- GLOBAL SINGLETON SCOPE ---
let sharedWorker = null;
let workerScriptUrl = null;
const pendingRequests = new Map();

// The "Blob" injection happens here in the build step.
// For dev, we assume this string is injected or loaded.
// In the final build, this var is populated.
const INLINE_WORKER_CODE = `/* INJECTED_BY_BUILD_SCRIPT */`; 

function getWorker() {
  if (sharedWorker) return sharedWorker;

  if (typeof window === 'undefined') return null; // SSR protection

  // Create the Blob URL once
  if (!workerScriptUrl && INLINE_WORKER_CODE && INLINE_WORKER_CODE !== '/* INJECTED_BY_BUILD_SCRIPT */') {
    const blob = new Blob([INLINE_WORKER_CODE], { type: 'application/javascript' });
    workerScriptUrl = URL.createObjectURL(blob);
  }

  // Fallback for dev environment (loading from file)
  const url = workerScriptUrl || new URL('../worker/index.js', import.meta.url);

  sharedWorker = new Worker(url, { type: 'module' });

  // Global Message Listener
  sharedWorker.onmessage = (e) => {
    const { id, success, payload, error } = e.data;
    const req = pendingRequests.get(id);
    if (req) {
      if (success) req.resolve(payload);
      else req.reject(new Error(error));
      pendingRequests.delete(id);
    }
  };

  return sharedWorker;
}

// --- THE HOOK ---
export function useAIGuard(config = {}) {
  // We use a ref to ensure we don't try to send messages before mount
  const workerRef = useRef(null);

  useEffect(() => {
    workerRef.current = getWorker();
    
    // Cleanup? No. We keep the worker alive for the app's lifetime.
    // It's 5MB of RAM. It's fine.
  }, []);

  const post = useCallback((type, payload, options) => {
    const worker = getWorker(); // Ensure we have it
    if (!worker) return Promise.reject("Worker not initialized");

    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      pendingRequests.set(id, { resolve, reject });
      worker.postMessage({ id, type, payload, options });
    });
  }, []); // Dependencies are empty -> Stable function identity

  // Fix #1: API Mismatch (Standardize naming)
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

