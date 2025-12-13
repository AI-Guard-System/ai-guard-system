import { useEffect, useRef, useState, useCallback } from 'react';
import { scanText } from './scanner.js';
import { repairJSON, extractJSON } from './repair.js';

// --- GLOBAL SINGLETON SCOPE ---
let sharedWorker = null;
let workerScriptUrl = null;
let fallbackMode = false;
const pendingRequests = new Map();
const loadedPluginNames = new Set(); // Track which plugins are loaded globally

// The "Blob" injection happens here in the build step.
// For dev, we assume this string is injected or loaded.
// In the final build, this var is populated.
const INLINE_WORKER_CODE = `var le=Object.defineProperty;var Xe=(l,s,r)=>s in l?le(l,s,{enumerable:!0,configurable:!0,writable:!0,value:r}):l[s]=r;var Ye=(l,s)=>()=>(l&&(s=l(l=0)),s);var Qe=(l,s)=>{for(var r in s)le(l,r,{get:s[r],enumerable:!0})};var ce=(l,s,r)=>Xe(l,typeof s!="symbol"?s+"":s,r);var Ae={};Qe(Ae,{default:()=>rt});async function tt(l={}){var s,r=l,n=!!globalThis.window,o=!!globalThis.WorkerGlobalScope,i=globalThis.process?.versions?.node&&globalThis.process?.type!="renderer",A=[],c="./this.program",v=import.meta.url,w="",b,p;if(n||o){try{w=new URL(".",v).href}catch{}o&&(p=e=>{var t=new XMLHttpRequest;return t.open("GET",e,!1),t.responseType="arraybuffer",t.send(null),new Uint8Array(t.response)}),b=async e=>{var t=await fetch(e,{credentials:"same-origin"});if(t.ok)return t.arrayBuffer();throw new Error(t.status+" : "+t.url)}}var y=console.log.bind(console),E=console.error.bind(console),T,R=!1;function P(e){for(var t=0,a=e.length,f=new Uint8Array(a),h;t<a;++t)h=e.charCodeAt(t),f[t]=~h>>8&h;return f}var S,I,m,_,U,j,W,H,q,he,de,ye,L=!1;function ve(){var e=ie.buffer;m=new Int8Array(e),U=new Int16Array(e),_=new Uint8Array(e),j=new Uint16Array(e),W=new Int32Array(e),H=new Uint32Array(e),q=new Float32Array(e),he=new Float64Array(e),de=new BigInt64Array(e),ye=new BigUint64Array(e)}function we(){if(r.preRun)for(typeof r.preRun=="function"&&(r.preRun=[r.preRun]);r.preRun.length;)Ne(r.preRun.shift());K(Y)}function Re(){L=!0,O.b()}function _e(){if(r.postRun)for(typeof r.postRun=="function"&&(r.postRun=[r.postRun]);r.postRun.length;)xe(r.postRun.shift());K(X)}function be(e){r.onAbort?.(e),e="Aborted("+e+")",E(e),R=!0,e+=". Build with -sASSERTIONS for more info.";var t=new WebAssembly.RuntimeError(e);throw I?.(t),t}var V;function Ee(){return P('\\0asm\\0\\0\\0\`\\x7F\\x7F\`\\0\\x7F\`\\x7F\\0\`\\0\\0\\0\\0\\x07\\xA2\\x80\\x80	\\x7FA\\x90\\x90\\x84\\v\\x07a\\0b\\0c\\0d\\0e\\0f\\0\\0\\f\\n\\xC1\\0#\\0\\v\\0#\\0 \\0kApq"\\0\$\\0 \\0\\v\\0 \\0\$\\0\\v\\x9E\\b\\x7FA\\x7F!A\\x80\\bA\\x7F6\\0@\\x7F@@ \\0"\\x07AqE\\r\\0A\\0 \\0-\\0\\0E\\r@ \\0Aj"\\0AqE\\r \\0-\\0\\0\\r\\0\\v\\f\\v@ \\0"Aj!\\0A\\x80\\x82\\x84\\b (\\0"\\bk \\brA\\x80\\x81\\x82\\x84xqA\\x80\\x81\\x82\\x84xF\\r\\0\\v@ "\\0Aj! \\0-\\0\\0\\r\\0\\v\\v \\0 \\x07k\\v"A\\0L\\r\\0\\x7F@A\\xFF\\xFF\\xFF\\0 A\\xFF\\xFF\\xFF\\0F\\r   \\x07j-\\0\\0"\\0:\\0\\x90 Aq!A\\0!@ \\r\\0 \\0A\\xDC\\0F@A!\\f\\v \\0A"F@ As!\\f\\v Aq@A!\\f\\v@@@ \\0A\\xDB\\0G@ \\0A\\xFB\\0G\\r A\\xFE\\x07J\\rA\\0!A\\x80\\b Aj"\\x006\\0 A\\x91\\bjA\\xFD\\0:\\0\\0 \\0!\\f\\v A\\xFE\\x07J\\rA\\0!A\\x80\\b Aj"\\x006\\0 A\\x91\\bjA\\xDD\\0:\\0\\0 \\0!\\f\\vA\\0! \\0A\\xDFqA\\xDD\\0G\\r A\\0H\\r -\\0\\x90\\b \\0G\\rA\\x80\\b Ak"6\\0\\f\\vA\\0!\\v\\v Aj" G\\r\\0\\v \\v! Aq@ A":\\0\\x90 Aj!\\vA\\0! A\\0H\\r\\0@ AqAF@ !\\f\\v AjAq!\\0 !@ A\\x90j -\\0\\x90\\b:\\0\\0 Aj! Ak! Aj" \\0G\\r\\0\\v\\v AO@@ A\\x90j A\\x90\\bj-\\0\\0:\\0\\0 A\\x91j A\\x8F\\bj-\\0\\0:\\0\\0 A\\x92j A\\x8E\\bj-\\0\\0:\\0\\0 A\\x93j A\\x8D\\bj-\\0\\0:\\0\\0 Aj! AG Ak!\\r\\0\\v\\vA\\x80\\bA\\x7F6\\0\\v A\\x90jA\\0:\\0\\0A\\x90\\v\\0\\v\\v\\v\\0A\\x80\\b\\v\\xFF\\xFF\\xFF\\xFF')}function it(e){return e}async function Se(e){return e}async function ke(e,t){try{var a=await Se(e),f=await WebAssembly.instantiate(a,t);return f}catch(h){E(\`failed to asynchronously prepare wasm: \${h}\`),be(h)}}async function Pe(e,t,a){return ke(t,a)}function Te(){var e={a:Le};return e}async function je(){function e(d,u){return O=d.exports,Ze(O),ve(),O}function t(d){return e(d.instance)}var a=Te();if(r.instantiateWasm)return new Promise((d,u)=>{r.instantiateWasm(a,(g,N)=>{d(e(g,N))})});V??(V=Ee());var f=await Pe(T,V,a),h=t(f);return h}class ot{constructor(t){ce(this,"name","ExitStatus");this.message=\`Program terminated with exit(\${t})\`,this.status=t}}for(var K=e=>{for(;e.length>0;)e.shift()(r)},X=[],xe=e=>X.push(e),Y=[],Ne=e=>Y.push(e),Be=!0,Ue=e=>ne(e),Me=()=>se(),Q=e=>{var t=r["_"+e];return t},Ce=(e,t)=>{m.set(e,t)},Ie=e=>{for(var t=0,a=0;a<e.length;++a){var f=e.charCodeAt(a);f<=127?t++:f<=2047?t+=2:f>=55296&&f<=57343?(t+=4,++a):t+=3}return t},We=(e,t,a,f)=>{if(!(f>0))return 0;for(var h=a,d=a+f-1,u=0;u<e.length;++u){var g=e.codePointAt(u);if(g<=127){if(a>=d)break;t[a++]=g}else if(g<=2047){if(a+1>=d)break;t[a++]=192|g>>6,t[a++]=128|g&63}else if(g<=65535){if(a+2>=d)break;t[a++]=224|g>>12,t[a++]=128|g>>6&63,t[a++]=128|g&63}else{if(a+3>=d)break;t[a++]=240|g>>18,t[a++]=128|g>>12&63,t[a++]=128|g>>6&63,t[a++]=128|g&63,u++}}return t[a]=0,a-h},Fe=(e,t,a)=>We(e,_,t,a),ee=e=>ae(e),Oe=e=>{var t=Ie(e)+1,a=ee(t);return Fe(e,a,t),a},te=globalThis.TextDecoder&&new TextDecoder,De=(e,t,a,f)=>{var h=t+a;if(f)return h;for(;e[t]&&!(t>=h);)++t;return t},ze=(e,t=0,a,f)=>{var h=De(e,t,a,f);if(h-t>16&&e.buffer&&te)return te.decode(e.subarray(t,h));for(var d="";t<h;){var u=e[t++];if(!(u&128)){d+=String.fromCharCode(u);continue}var g=e[t++]&63;if((u&224)==192){d+=String.fromCharCode((u&31)<<6|g);continue}var N=e[t++]&63;if((u&240)==224?u=(u&15)<<12|g<<6|N:u=(u&7)<<18|g<<12|N<<6|e[t++]&63,u<65536)d+=String.fromCharCode(u);else{var M=u-65536;d+=String.fromCharCode(55296|M>>10,56320|M&1023)}}return d},He=(e,t,a)=>e?ze(_,e,t,a):"",re=(e,t,a,f,h)=>{var d={string:k=>{var D=0;return k!=null&&k!==0&&(D=Oe(k)),D},array:k=>{var D=ee(k.length);return Ce(k,D),D}};function u(k){return t==="string"?He(k):t==="boolean"?!!k:k}var g=Q(e),N=[],M=0;if(f)for(var C=0;C<f.length;C++){var oe=d[a[C]];oe?(M===0&&(M=Me()),N[C]=oe(f[C])):N[C]=f[C]}var G=g(...N);function Ke(k){return M!==0&&Ue(M),u(k)}return G=Ke(G),G},Je=(e,t,a,f)=>{var h=!a||a.every(u=>u==="number"||u==="boolean"),d=t!=="string";return d&&h&&!f?Q(e):(...u)=>re(e,t,a,u,f)},F=new Uint8Array(123),x=25;x>=0;--x)F[48+x]=52+x,F[65+x]=x,F[97+x]=26+x;if(F[43]=62,F[47]=63,r.noExitRuntime&&(Be=r.noExitRuntime),r.print&&(y=r.print),r.printErr&&(E=r.printErr),r.wasmBinary&&(T=r.wasmBinary),r.arguments&&(A=r.arguments),r.thisProgram&&(c=r.thisProgram),r.preInit)for(typeof r.preInit=="function"&&(r.preInit=[r.preInit]);r.preInit.length>0;)r.preInit.shift()();r.ccall=re,r.cwrap=Je;var \$e,ne,ae,se,qe,Ge,ie;function Ze(e){\$e=r._repair_json=e.c,ne=e.d,ae=e.e,se=e.f,qe=ie=e.a,Ge=e.__indirect_function_table}var Le={};function Ve(){we();function e(){r.calledRun=!0,!R&&(Re(),S?.(r),r.onRuntimeInitialized?.(),_e())}r.setStatus?(r.setStatus("Running..."),setTimeout(()=>{setTimeout(()=>r.setStatus(""),1),e()},1)):e()}var O;return O=await je(),Ve(),L?s=r:s=new Promise((e,t)=>{S=e,I=t}),s}var rt,pe=Ye(()=>{rt=tt});var et={CREDIT_CARD:/\\b(?:\\d{4}[ -]?){3}\\d{4}\\b/,EMAIL:/\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b/,API_KEY:/\\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36})\\b/,SSN:/\\b\\d{3}-\\d{2}-\\d{4}\\b/,IPV4:/\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b/,AWS_KEY:/\\b(AKIA[0-9A-Z]{16})\\b/,JWT:/\\beyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*\\b/};function fe(l,s={},r=!1,n=[],o=[]){let i={};Array.isArray(s)?i={rules:s,redact:r,allow:n,customRules:o,mode:"block"}:i={rules:[],redact:!1,allow:[],customRules:[],mode:"block",...s};let{rules:A=[],redact:c=!1,allow:v=[],customRules:w=[],mode:b="block"}=i,p=l,y=[],E=!0,T={...et};for(let m of w)m.name&&m.pattern&&(T[m.name]=m.pattern);let R=A.length>0?A:Object.keys(T),P=v.map(m=>typeof m=="string"?new RegExp(m):m);for(let m of R){let _=T[m];if(!_)continue;let U=new RegExp(_.source,"g"),j=l.match(U);if(j&&j.length>0){let W=j.filter(H=>!P.some(q=>q.test(H)));W.length>0&&(E=!1,y.push({type:m,matches:W}))}}if(!E&&(c||b==="block"))for(let m of y)for(let _ of m.matches)p=p.replace(_,\`[\${m.type}_REDACTED]\`);let S=E?"safe":"blocked";return!E&&b==="warn"&&(S="warning"),{safe:E||b==="warn"||b==="silent",status:S,findings:y,text:p}}function Z(l){if(!l)return"";let s=l.trim();return s=s.replace(/^\`\`\`[a-zA-Z]*\\s*/,""),s=s.replace(/\\s*\`\`\`\$/,""),s}function J(l,s={}){if(!l)return"";let{last:r=!0}=s,n=l;n=n.replace(/<think>[\\s\\S]*?<\\/think>/gi,""),n=n.replace(/<think>[\\s\\S]*\$/gi,""),n=n.replace(/<\\/th\$/gi,"");let o=/\`\`\`(?:json|json5|javascript|js)?\\s*([\\s\\S]*?)(?:\`\`\`|\$)/gi,i=[],A;for(;(A=o.exec(n))!==null;){let R=A[1].trim();R&&(R.startsWith("{")||R.startsWith("["))&&i.push(R)}if(i.length>0)return r?i[i.length-1]:i[0];let c=[],v=0,w=-1,b=!1,p=!1;for(let R=0;R<n.length;R++){let P=n[R];if(p){p=!1;continue}if(P==="\\\\"&&b){p=!0;continue}if(P==='"'&&!p){b=!b;continue}b||(P==="{"||P==="["?(v===0&&(w=R),v++):(P==="}"||P==="]")&&(v--,v===0&&w!==-1&&(c.push(n.slice(w,R+1)),w=-1)))}if(w!==-1&&v>0&&c.push(n.slice(w)),c.length>0)return r?c[c.length-1]:c[0];let y=n.indexOf("{"),E=n.indexOf("[");if(y===-1&&E===-1)return n.trim();let T=y===-1?E:E===-1?y:Math.min(y,E);return n.slice(T).trim()}function ue(l,s={}){let{extract:r=!1}=s,n=r?J(l):Z(l);if(!n||!n.trim())return{fixed:"{}",data:{},isPartial:!1,patches:[]};let o=n.trim(),i=[],A=!1,c=[],v=!1,w=!1;for(let p=0;p<o.length;p++){let y=o[p];if(w){w=!1;continue}if(y==="\\\\"&&v){w=!0;continue}if(y==='"'&&!w){v=!v,v?c.push('"'):c.length>0&&c[c.length-1]==='"'&&c.pop();continue}v||(y==="{"?c.push("{"):y==="["?c.push("["):y==="}"?c.length>0&&c[c.length-1]==="{"&&c.pop():y==="]"&&c.length>0&&c[c.length-1]==="["&&c.pop())}if(v&&(i.push({type:"unclosed_string",index:o.length}),o+='"',A=!0,c.length>0&&c[c.length-1]==='"'&&c.pop()),/,\\s*\$/.test(o)){let p=o.match(/,\\s*\$/);i.push({type:"trailing_comma",index:p.index}),o=o.replace(/,\\s*\$/,""),A=!0}for(;c.length>0;){let p=c.pop();p==="{"?(i.push({type:"missing_brace",index:o.length}),o+="}",A=!0):p==="["&&(i.push({type:"missing_brace",index:o.length}),o+="]",A=!0)}let b=null;try{b=JSON.parse(o)}catch{}return{fixed:o,data:b,isPartial:A,patches:i}}var \$=null,ge=null,me=!0;async function nt(){if(!\$){if(!me)throw new Error("Wasm Kernel is disabled in this build.");try{let l=await Promise.resolve().then(()=>(pe(),Ae));\$=await(l.default||l)(),ge=\$.cwrap("repair_json","string",["string"])}catch(l){throw console.error("Failed to load Wasm kernel:",l),l}}}var B=new Map,z=new Map;async function at(l){let{name:s,url:r,module:n}=l;if(B.has(s))return{success:!0,name:s,cached:!0};if(z.has(s))return await z.get(s),{success:!0,name:s,cached:!0};let o=(async()=>{try{let i;if(n)i=n;else if(r)i=await import(r);else throw new Error("Plugin requires either url or module");return typeof i.init=="function"&&await i.init(),B.set(s,i),i}catch(i){throw z.delete(s),i}})();return z.set(s,o),await o,{success:!0,name:s}}async function st(l,s=null){let r=[],n=s?s.filter(o=>B.has(o)):Array.from(B.keys());for(let o of n){let i=B.get(o);if(i&&typeof i.check=="function")try{let A=await i.check(l);if(r.push({name:o,...A}),!A.safe)return{safe:!1,blockedBy:o,reason:A.reason||"Plugin blocked",score:A.score,results:r}}catch(A){r.push({name:o,error:A.message})}}return{safe:!0,results:r}}self.onmessage=async l=>{let{id:s,type:r,payload:n,options:o}=l.data;try{let i;switch(r){case"LOAD_PLUGIN":i=await at(n);break;case"UNLOAD_PLUGIN":let A=typeof n=="string"?n:n.name;B.delete(A),z.delete(A),i={success:!0,name:A};break;case"LIST_PLUGINS":i={plugins:Array.from(B.keys())};break;case"SCAN_TEXT":let c=typeof n=="string"?n:n?.text,v=o?.rules||n?.enabledRules||[],w=o?.redact??n?.redact??!1,b=o?.allow||n?.allow||[],p=o?.customRules||n?.customRules||[],y=o?.runPlugins??n?.runPlugins??!0,E=o?.plugins||n?.plugins||null;if(i=fe(c,v,w,b,p),i.safe&&y&&B.size>0){let S=await st(c,E);S.safe?i.pluginResults=S.results:i={...i,safe:!1,blockedBy:S.blockedBy,reason:S.reason,score:S.score,pluginResults:S.results}}break;case"REPAIR_JSON":{let S=typeof n=="string"?n:n?.text,I=o?.extract??n?.extract??!1,m=o?.useWasm&&me,_;if(m){\$||await nt();let W=I?J(S):Z(S);_={fixed:ge(W),data:null,isPartial:!1,patches:[]}}else _=ue(S,{extract:I});let U=_.data,j=!0;if(U===null&&_.fixed!=="null")try{U=JSON.parse(_.fixed)}catch{j=!1}i={fixedString:_.fixed,data:U,isValid:j,isPartial:_.isPartial,patches:_.patches,mode:m?"wasm":"js"}}break;case"EXTRACT_JSON":let T=typeof n=="string"?n:n?.text,R=o?.last??n?.last??!0;i={extracted:J(T,{last:R})};break;default:throw new Error(\`Unknown message type: \${r}\`)}self.postMessage({id:s,success:!0,payload:i})}catch(i){self.postMessage({id:s,success:!1,error:i.message})}};
`;

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
  if (!workerScriptUrl && INLINE_WORKER_CODE && INLINE_WORKER_CODE !== '/* INJECTED_BY_BUILD_SCRIPT */') {
    try {
      const blob = new Blob([INLINE_WORKER_CODE], { type: 'application/javascript' });
      workerScriptUrl = URL.createObjectURL(blob);
    } catch (e) {
      console.warn("react-ai-guard: Blob creation failed (CSP). Falling back to main thread.");
      fallbackMode = true;
      return null;
    }
  }

  // Fallback for dev environment (loading from file)
  const url = workerScriptUrl || new URL('../worker/index.js', import.meta.url);

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

