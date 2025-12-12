import { useEffect, useRef, useState, useCallback } from 'react';

// --- GLOBAL SINGLETON SCOPE ---
let sharedWorker = null;
let workerScriptUrl = null;
const pendingRequests = new Map();
const loadedPluginNames = new Set(); // Track which plugins are loaded globally

// The "Blob" injection happens here in the build step.
// For dev, we assume this string is injected or loaded.
// In the final build, this var is populated.
const INLINE_WORKER_CODE = `var Z={CREDIT_CARD:/\\b(?:\\d{4}[ -]?){3}\\d{4}\\b/,EMAIL:/\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b/,API_KEY:/\\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36})\\b/,SSN:/\\b\\d{3}-\\d{2}-\\d{4}\\b/,IPV4:/\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b/,AWS_KEY:/\\b(AKIA[0-9A-Z]{16})\\b/,JWT:/\\beyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*\\b/};function M(r,a={},c=!1,e=[],s=[]){let t={};Array.isArray(a)?t={rules:a,redact:c,allow:e,customRules:s,mode:"block"}:t={rules:[],redact:!1,allow:[],customRules:[],mode:"block",...a};let{rules:l=[],redact:n=!1,allow:f=[],customRules:p=[],mode:d="block"}=t,i=r,o=[],x=!0,b={...Z};for(let u of p)u.name&&u.pattern&&(b[u.name]=u.pattern);let h=l.length>0?l:Object.keys(b),w=f.map(u=>typeof u=="string"?new RegExp(u):u);for(let u of h){let m=b[u];if(!m)continue;let _=new RegExp(m.source,"g"),k=r.match(_);if(k&&k.length>0){let S=k.filter(N=>!w.some(J=>J.test(N)));S.length>0&&(x=!1,o.push({type:u,matches:S}))}}if(!x&&(n||d==="block"))for(let u of o)for(let m of u.matches)i=i.replace(m,\`[\${u.type}_REDACTED]\`);let g=x?"safe":"blocked";return!x&&d==="warn"&&(g="warning"),{safe:x||d==="warn"||d==="silent",status:g,findings:o,text:i}}function E(r){if(!r)return"";let a=r.trim();return a=a.replace(/^\`\`\`[a-zA-Z]*\\s*/,""),a=a.replace(/\\s*\`\`\`\$/,""),a}function R(r,a={}){if(!r)return"";let{last:c=!0}=a,e=r;e=e.replace(/<think>[\\s\\S]*?<\\/think>/gi,""),e=e.replace(/<think>[\\s\\S]*\$/gi,"");let s=/\`\`\`(?:json|json5|javascript|js)?\\s*([\\s\\S]*?)(?:\`\`\`|\$)/gi,t=[],l;for(;(l=s.exec(e))!==null;){let h=l[1].trim();h&&(h.startsWith("{")||h.startsWith("["))&&t.push(h)}if(t.length>0)return c?t[t.length-1]:t[0];let n=[],f=0,p=-1,d=!1,i=!1;for(let h=0;h<e.length;h++){let w=e[h];if(i){i=!1;continue}if(w==="\\\\"&&d){i=!0;continue}if(w==='"'&&!i){d=!d;continue}d||(w==="{"||w==="["?(f===0&&(p=h),f++):(w==="}"||w==="]")&&(f--,f===0&&p!==-1&&(n.push(e.slice(p,h+1)),p=-1)))}if(p!==-1&&f>0&&n.push(e.slice(p)),n.length>0)return c?n[n.length-1]:n[0];let o=e.indexOf("{"),x=e.indexOf("[");if(o===-1&&x===-1)return e.trim();let b=o===-1?x:x===-1?o:Math.min(o,x);return e.slice(b).trim()}function O(r,a={}){let{extract:c=!1}=a,e=c?R(r):E(r);if(!e||!e.trim())return{fixed:"{}",data:{},isPartial:!1,patches:[]};let s=e.trim(),t=[],l=!1,n=[],f=!1,p=!1;for(let i=0;i<s.length;i++){let o=s[i];if(p){p=!1;continue}if(o==="\\\\"&&f){p=!0;continue}if(o==='"'&&!p){f=!f,f?n.push('"'):n.length>0&&n[n.length-1]==='"'&&n.pop();continue}f||(o==="{"?n.push("{"):o==="["?n.push("["):o==="}"?n.length>0&&n[n.length-1]==="{"&&n.pop():o==="]"&&n.length>0&&n[n.length-1]==="["&&n.pop())}if(f&&(t.push({type:"unclosed_string",index:s.length}),s+='"',l=!0,n.length>0&&n[n.length-1]==='"'&&n.pop()),/,\\s*\$/.test(s)){let i=s.match(/,\\s*\$/);t.push({type:"trailing_comma",index:i.index}),s=s.replace(/,\\s*\$/,""),l=!0}for(;n.length>0;){let i=n.pop();i==="{"?(t.push({type:"missing_brace",index:s.length}),s+="}",l=!0):i==="["&&(t.push({type:"missing_brace",index:s.length}),s+="]",l=!0)}let d=null;try{d=JSON.parse(s)}catch{}return{fixed:s,data:d,isPartial:l,patches:t}}var P=null,I=null,z=!1;async function L(){if(!P){if(!z)throw new Error("Wasm Kernel is disabled in this build.");try{let r=await import("../core/repair_wasm.js");P=await(r.default||r)(),I=P.cwrap("repair_json","string",["string"])}catch(r){throw console.error("Failed to load Wasm kernel:",r),r}}}var y=new Map,A=new Map;async function W(r){let{name:a,url:c,module:e}=r;if(y.has(a))return{success:!0,name:a,cached:!0};if(A.has(a))return await A.get(a),{success:!0,name:a,cached:!0};let s=(async()=>{try{let t;if(e)t=e;else if(c)t=await import(c);else throw new Error("Plugin requires either url or module");return typeof t.init=="function"&&await t.init(),y.set(a,t),t}catch(t){throw A.delete(a),t}})();return A.set(a,s),await s,{success:!0,name:a}}async function j(r,a=null){let c=[],e=a?a.filter(s=>y.has(s)):Array.from(y.keys());for(let s of e){let t=y.get(s);if(t&&typeof t.check=="function")try{let l=await t.check(r);if(c.push({name:s,...l}),!l.safe)return{safe:!1,blockedBy:s,reason:l.reason||"Plugin blocked",score:l.score,results:c}}catch(l){c.push({name:s,error:l.message})}}return{safe:!0,results:c}}self.onmessage=async r=>{let{id:a,type:c,payload:e,options:s}=r.data;try{let t;switch(c){case"LOAD_PLUGIN":t=await W(e);break;case"UNLOAD_PLUGIN":let l=typeof e=="string"?e:e.name;y.delete(l),A.delete(l),t={success:!0,name:l};break;case"LIST_PLUGINS":t={plugins:Array.from(y.keys())};break;case"SCAN_TEXT":let n=typeof e=="string"?e:e?.text,f=s?.rules||e?.enabledRules||[],p=s?.redact??e?.redact??!1,d=s?.allow||e?.allow||[],i=s?.customRules||e?.customRules||[],o=s?.runPlugins??e?.runPlugins??!0,x=s?.plugins||e?.plugins||null;if(t=M(n,f,p,d,i),t.safe&&o&&y.size>0){let g=await j(n,x);g.safe?t.pluginResults=g.results:t={...t,safe:!1,blockedBy:g.blockedBy,reason:g.reason,score:g.score,pluginResults:g.results}}break;case"REPAIR_JSON":{let g=typeof e=="string"?e:e?.text,T=s?.extract??e?.extract??!1,u=s?.useWasm&&z,m;if(u){P||await L();let S=T?R(g):E(g);m={fixed:I(S),data:null,isPartial:!1,patches:[]}}else m=O(g,{extract:T});let _=m.data,k=!0;if(_===null&&m.fixed!=="null")try{_=JSON.parse(m.fixed)}catch{k=!1}t={fixedString:m.fixed,data:_,isValid:k,isPartial:m.isPartial,patches:m.patches,mode:u?"wasm":"js"}}break;case"EXTRACT_JSON":let b=typeof e=="string"?e:e?.text,h=s?.last??e?.last??!0;t={extracted:R(b,{last:h})};break;default:throw new Error(\`Unknown message type: \${c}\`)}self.postMessage({id:a,success:!0,payload:t})}catch(t){self.postMessage({id:a,success:!1,error:t.message})}};
`; 

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

