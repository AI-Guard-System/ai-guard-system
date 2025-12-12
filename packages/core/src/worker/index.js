import { repairJSON, extractJSON } from '../core/repair.js';
import { scanText } from '../core/scanner.js';

// === PLUGIN SYSTEM ===
// Plugins are loaded dynamically and run after regex (fast-first strategy)
const loadedPlugins = new Map();
let pluginInitPromises = new Map();

/**
 * Load a plugin from URL or inline code
 * Plugins must export: { name, init(), check(text) }
 */
async function loadPlugin(pluginConfig) {
  const { name, url, module } = pluginConfig;
  
  if (loadedPlugins.has(name)) {
    return { success: true, name, cached: true };
  }
  
  // Prevent duplicate loading
  if (pluginInitPromises.has(name)) {
    await pluginInitPromises.get(name);
    return { success: true, name, cached: true };
  }
  
  const initPromise = (async () => {
    try {
      let plugin;
      
      if (module) {
        // Inline module (for testing or bundled plugins)
        plugin = module;
      } else if (url) {
        // Dynamic import from URL
        plugin = await import(/* webpackIgnore: true */ url);
      } else {
        throw new Error('Plugin requires either url or module');
      }
      
      // Initialize plugin (load models, etc.)
      if (typeof plugin.init === 'function') {
        await plugin.init();
      }
      
      loadedPlugins.set(name, plugin);
      return plugin;
    } catch (err) {
      pluginInitPromises.delete(name);
      throw err;
    }
  })();
  
  pluginInitPromises.set(name, initPromise);
  await initPromise;
  
  return { success: true, name };
}

/**
 * Run all loaded plugins against text
 * Returns first failure or combined success
 */
async function runPlugins(text, pluginNames = null) {
  const results = [];
  
  const pluginsToRun = pluginNames 
    ? pluginNames.filter(n => loadedPlugins.has(n))
    : Array.from(loadedPlugins.keys());
  
  for (const name of pluginsToRun) {
    const plugin = loadedPlugins.get(name);
    if (plugin && typeof plugin.check === 'function') {
      try {
        const result = await plugin.check(text);
        results.push({ name, ...result });
        
        // Fast-fail: stop on first block
        if (!result.safe) {
          return {
            safe: false,
            blockedBy: name,
            reason: result.reason || 'Plugin blocked',
            score: result.score,
            results
          };
        }
      } catch (err) {
        results.push({ name, error: err.message });
      }
    }
  }
  
  return { safe: true, results };
}

// === MESSAGE HANDLER ===
self.onmessage = async (e) => {
  const { id, type, payload, options } = e.data;

  try {
    let result;

    switch (type) {
      // === PLUGIN MANAGEMENT ===
      case 'LOAD_PLUGIN':
        result = await loadPlugin(payload);
        break;
        
      case 'UNLOAD_PLUGIN':
        const pluginName = typeof payload === 'string' ? payload : payload.name;
        loadedPlugins.delete(pluginName);
        pluginInitPromises.delete(pluginName);
        result = { success: true, name: pluginName };
        break;
        
      case 'LIST_PLUGINS':
        result = { plugins: Array.from(loadedPlugins.keys()) };
        break;

      // === SCANNING (Regex + Plugins) ===
      case 'SCAN_TEXT':
        // Handle both shapes: 
        // Old: payload=string, options={rules, redact}
        // New: payload={text, enabledRules, redact, allow, customRules}
        const scanText_input = typeof payload === 'string' ? payload : payload?.text;
        const scanText_rules = options?.rules || payload?.enabledRules || [];
        const scanText_redact = options?.redact ?? payload?.redact ?? false;
        const scanText_allow = options?.allow || payload?.allow || [];
        const scanText_customRules = options?.customRules || payload?.customRules || [];
        const runPluginsFlag = options?.runPlugins ?? payload?.runPlugins ?? true;
        const pluginList = options?.plugins || payload?.plugins || null;
        
        // Step 1: Fast regex scan
        result = scanText(scanText_input, scanText_rules, scanText_redact, scanText_allow, scanText_customRules);
        
        // Step 2: If regex passed and plugins enabled, run AI plugins
        if (result.safe && runPluginsFlag && loadedPlugins.size > 0) {
          const pluginResult = await runPlugins(scanText_input, pluginList);
          if (!pluginResult.safe) {
            result = {
              ...result,
              safe: false,
              blockedBy: pluginResult.blockedBy,
              reason: pluginResult.reason,
              score: pluginResult.score,
              pluginResults: pluginResult.results
            };
          } else {
            result.pluginResults = pluginResult.results;
          }
        }
        break;

      // === JSON REPAIR ===
      case 'REPAIR_JSON':
        // Handle both: payload=string or payload={text, extract}
        const repair_input = typeof payload === 'string' ? payload : payload?.text;
        const repair_extract = options?.extract ?? payload?.extract ?? false;
        const fixed = repairJSON(repair_input, { extract: repair_extract });
        
        // isValid = true if repaired JSON parses successfully
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

      case 'EXTRACT_JSON':
        // Pure extraction without repair (for inspection)
        const extract_input = typeof payload === 'string' ? payload : payload?.text;
        const extract_last = options?.last ?? payload?.last ?? true;
        const extracted = extractJSON(extract_input, { last: extract_last });
        result = { extracted };
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
