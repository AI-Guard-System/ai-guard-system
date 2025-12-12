import { scanText } from '../core/scanner.js';
import { stripMarkdown, extractJSON, repairJSON } from '../core/repair.js';

// === WASM KERNEL STATE ===
let wasmInstance = null;
let repair_c = null;

// The bundler (esbuild) will replace process.env.WASM_ENABLED
// allowing dead-code elimination for the Pure JS build.
const WASM_ENABLED = process.env.WASM_ENABLED === 'true';

async function initKernel() {
  if (wasmInstance) return;
  if (!WASM_ENABLED) throw new Error("Wasm Kernel is disabled in this build.");

  try {
    // Dynamic import to allow tree-shaking when WASM_ENABLED is false
    const module = await import('../core/repair_wasm.js');
    const createRepairModule = module.default || module; // Handle Module vs CommonJS export
    wasmInstance = await createRepairModule();
    repair_c = wasmInstance.cwrap('repair_json', 'string', ['string']);
  } catch (e) {
    console.error("Failed to load Wasm kernel:", e);
    throw e;
  }
}

// === PLUGIN SYSTEM ===
const loadedPlugins = new Map();
let pluginInitPromises = new Map();

async function loadPlugin(pluginConfig) {
  const { name, url, module } = pluginConfig;

  if (loadedPlugins.has(name)) {
    return { success: true, name, cached: true };
  }

  if (pluginInitPromises.has(name)) {
    await pluginInitPromises.get(name);
    return { success: true, name, cached: true };
  }

  const initPromise = (async () => {
    try {
      let plugin;

      if (module) {
        plugin = module;
      } else if (url) {
        plugin = await import(/* webpackIgnore: true */ url);
      } else {
        throw new Error('Plugin requires either url or module');
      }

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

      // === SCANNING ===
      case 'SCAN_TEXT':
        const scanText_input = typeof payload === 'string' ? payload : payload?.text;
        const scanText_rules = options?.rules || payload?.enabledRules || [];
        const scanText_redact = options?.redact ?? payload?.redact ?? false;
        const scanText_allow = options?.allow || payload?.allow || [];
        const scanText_customRules = options?.customRules || payload?.customRules || [];
        const runPluginsFlag = options?.runPlugins ?? payload?.runPlugins ?? true;
        const pluginList = options?.plugins || payload?.plugins || null;

        result = scanText(scanText_input, scanText_rules, scanText_redact, scanText_allow, scanText_customRules);

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
        {
          const repair_input = typeof payload === 'string' ? payload : payload?.text;
          const repair_extract = options?.extract ?? payload?.extract ?? false;
          const useWasm = options?.useWasm && WASM_ENABLED; // Opt-in and must be enabled in build

          let repairResult;

          if (useWasm) {
            // == C/WASM Mode ==
            if (!wasmInstance) await initKernel();
            // Pre-process (Strip logic still in JS, or could function in C)
            // For now, mimic the C kernel flow: strip markdown first
            const cleanText = repair_extract ? extractJSON(repair_input) : stripMarkdown(repair_input);
            const fixedStr = repair_c(cleanText);

            // Shim the object for Wasm (Patches not yet supported in C)
            repairResult = {
              fixed: fixedStr,
              data: null, // Will try parse below
              isPartial: false,
              patches: []
            };
          } else {
            // == Pure JS Mode ==
            // repairJSON now returns { fixed, data, isPartial, patches }
            repairResult = repairJSON(repair_input, { extract: repair_extract });
          }

          // Final Validation / Parse Check
          let parsed = repairResult.data;
          let isValid = true;

          // If repairJSON failed to parse (or Wasm didn't try), try now.
          // Note: repairJSON returns null on failure, but null is also valid JSON.
          // valid JSON 'null' -> formatted as 'null'.
          if (parsed === null && repairResult.fixed !== 'null') {
            try {
              parsed = JSON.parse(repairResult.fixed);
            } catch {
              isValid = false;
            }
          }

          result = {
            fixedString: repairResult.fixed,
            data: parsed,
            isValid,
            isPartial: repairResult.isPartial,
            patches: repairResult.patches,
            mode: useWasm ? 'wasm' : 'js'
          };
        }
        break;

      case 'EXTRACT_JSON':
        const extract_input = typeof payload === 'string' ? payload : payload?.text;
        const extract_last = options?.last ?? payload?.last ?? true;
        const extracted = extractJSON(extract_input, { last: extract_last });
        result = { extracted };
        break;

      default:
        throw new Error(`Unknown message type: ${type}`);
    }

    self.postMessage({ id, success: true, payload: result });

  } catch (error) {
    self.postMessage({ id, success: false, error: error.message });
  }
};
