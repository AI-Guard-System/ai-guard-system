import { useEffect, useRef, useState, useCallback } from 'react';

// --- GLOBAL SINGLETON SCOPE ---
let sharedWorker = null;
let workerScriptUrl = null;
const pendingRequests = new Map();
const loadedPluginNames = new Set(); // Track which plugins are loaded globally

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
    const worker = getWorker();
    if (!worker) return Promise.reject(new Error("Worker not initialized"));

    const id = crypto.randomUUID();
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => {
        pendingRequests.delete(id);
        reject(new Error(`Worker timeout (${timeout/1000}s)`));
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

