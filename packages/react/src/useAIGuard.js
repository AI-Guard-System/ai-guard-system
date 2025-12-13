import { useEffect, useRef, useState, useCallback } from 'react';
import { scanText, repairJSON, extractJSON, WORKER_CODE_PURE } from '@ai-guard/core';

// --- GLOBAL SINGLETON SCOPE ---
let sharedWorker = null;
let workerScriptUrl = null;
let fallbackMode = false;
const pendingRequests = new Map();
const loadedPluginNames = new Set(); // Track which plugins are loaded globally

// --- FALLBACK MAIN THREAD IMPLEMENTATION ---
async function runMainThread(type, payload, options) {
  if (type === 'SCAN_TEXT') {
    const scanText_input = typeof payload === 'string' ? payload : payload?.text;
    const scanText_rules = options?.rules || payload?.enabledRules || [];
    const scanText_redact = options?.redact ?? payload?.redact ?? false;
    const scanText_allow = options?.allow || payload?.allow || [];
    const scanText_customRules = options?.customRules || payload?.customRules || [];

    // Note: Plugins not supported in fallback for now
    return scanText(scanText_input, scanText_rules, scanText_redact, scanText_allow, scanText_customRules);
  }

  if (type === 'REPAIR_JSON') {
    const repair_input = typeof payload === 'string' ? payload : payload?.text;
    const repair_extract = options?.extract ?? payload?.extract ?? false;

    const repairResult = repairJSON(repair_input, { extract: repair_extract });

    let parsed = repairResult.data;
    let isValid = true;

    if (parsed === null && repairResult.fixed !== 'null') {
      try {
        parsed = JSON.parse(repairResult.fixed);
      } catch {
        isValid = false;
      }
    }

    return {
      fixedString: repairResult.fixed,
      data: parsed,
      isValid,
      isPartial: repairResult.isPartial,
      patches: repairResult.patches,
      mode: 'main-thread-js'
    };
  }

  if (type === 'EXTRACT_JSON') {
    const extract_input = typeof payload === 'string' ? payload : payload?.text;
    const extract_last = options?.last ?? payload?.last ?? true;
    const extracted = extractJSON(extract_input, { last: extract_last });
    return { extracted };
  }

  if (type === 'LOAD_PLUGIN' || type === 'LIST_PLUGINS') {
    return { success: true, warning: 'Plugins not supported in fallback mode' };
  }

  throw new Error(`Unknown message type: ${type}`);
}

function getWorker() {
  if (fallbackMode) return null;
  if (sharedWorker) return sharedWorker;

  if (typeof window === 'undefined') return null; // SSR protection

  // Create the Blob URL once
  if (!workerScriptUrl && WORKER_CODE_PURE) {
    try {
      const blob = new Blob([WORKER_CODE_PURE], { type: 'application/javascript' });
      workerScriptUrl = URL.createObjectURL(blob);
    } catch (e) {
      console.warn("react-ai-guard: Blob creation failed (CSP). Falling back to main thread.");
      fallbackMode = true;
      return null;
    }
  }

  // Fallback for dev environment (loading from file) - REMOVED relative import logic as we rely on package import
  const url = workerScriptUrl;
  if (!url) {
    console.warn("react-ai-guard: Worker code not found. Falling back to main thread.");
    fallbackMode = true;
    return null;
  }

  try {
    sharedWorker = new Worker(url, { type: 'module' });
  } catch (err) {
    console.warn("react-ai-guard: Worker creation blocked by CSP. Falling back to main thread.");
    fallbackMode = true;
    return null;
  }

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
  const [pluginsReady, setPluginsReady] = useState(false);
  const [pluginErrors, setPluginErrors] = useState([]);
  const workerRef = useRef(null);
  const pluginsLoadedRef = useRef(false);

  const post = useCallback((type, payload, options, timeout = 30000) => {
    if (fallbackMode) {
      return runMainThread(type, payload, options);
    }

    const worker = getWorker();

    // Check if getWorker triggered fallbackMode
    if (fallbackMode || !worker) {
      if (fallbackMode) return runMainThread(type, payload, options);
      return Promise.reject(new Error("Worker not initialized"));
    }

    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        pendingRequests.delete(id);
        reject(new Error(`Worker timeout (${timeout / 1000}s)`));
      }, timeout);

      pendingRequests.set(id, { resolve, reject, timeout: timeoutId });
      worker.postMessage({ id, type, payload, options });
    });
  }, []);

  // Load plugins on mount (only once globally)
  useEffect(() => {
    workerRef.current = getWorker();

    const plugins = config.plugins || [];
    if (plugins.length === 0 || pluginsLoadedRef.current) {
      setPluginsReady(true);
      return;
    }

    const loadPlugins = async () => {
      const errors = [];

      for (const plugin of plugins) {
        // Plugin can be: { name, url } or { name, module } or a class with static props
        const pluginConfig = typeof plugin === 'function'
          ? { name: plugin.pluginName, url: plugin.pluginUrl, module: plugin }
          : plugin;

        if (loadedPluginNames.has(pluginConfig.name)) {
          continue; // Already loaded globally
        }

        try {
          // Long timeout for model loading (120s)
          await post('LOAD_PLUGIN', pluginConfig, null, 120000);
          loadedPluginNames.add(pluginConfig.name);
        } catch (err) {
          errors.push({ name: pluginConfig.name, error: err.message });
          console.error(`[react-ai-guard] Failed to load plugin "${pluginConfig.name}":`, err);
        }
      }

      pluginsLoadedRef.current = true;
      setPluginErrors(errors);
      setPluginsReady(true);
    };

    loadPlugins();
  }, [config.plugins, post]);

  // v1.3.0: Enhanced scanInput with plugin support
  const scanInput = useCallback((text, options = {}) => {
    return post('SCAN_TEXT', text, {
      rules: options.rules || config.rules,
      redact: options.redact || config.redact,
      allow: options.allow || config.allow || [],
      customRules: options.customRules || config.customRules || [],
      runPlugins: options.runPlugins ?? config.runPlugins ?? true,
      plugins: options.plugins || null // Specific plugins to run, or null for all
    }, options.timeout || 60000); // Longer timeout when plugins involved
  }, [post, config.rules, config.redact, config.allow, config.customRules, config.runPlugins]);

  // v1.2.0: repairJson now supports extract mode for reasoning models
  const repairJson = useCallback((raw, options = {}) => {
    return post('REPAIR_JSON', raw, { extract: options.extract || false });
  }, [post]);

  // v1.2.0: Direct extraction API for reasoning model output
  const extractJson = useCallback((raw, options = {}) => {
    return post('EXTRACT_JSON', raw, { last: options.last ?? true });
  }, [post]);

  // v1.3.0: Plugin management
  const loadPlugin = useCallback(async (pluginConfig) => {
    const result = await post('LOAD_PLUGIN', pluginConfig, null, 120000);
    if (result.success) {
      loadedPluginNames.add(pluginConfig.name);
    }
    return result;
  }, [post]);

  const unloadPlugin = useCallback(async (name) => {
    const result = await post('UNLOAD_PLUGIN', { name });
    loadedPluginNames.delete(name);
    return result;
  }, [post]);

  const listPlugins = useCallback(() => {
    return post('LIST_PLUGINS', null);
  }, [post]);

  return {
    scanInput,
    repairJson,
    extractJson,
    // Plugin API
    loadPlugin,
    unloadPlugin,
    listPlugins,
    pluginsReady,
    pluginErrors
  };
}

