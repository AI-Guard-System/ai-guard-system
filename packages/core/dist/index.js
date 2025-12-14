// src/security/EntropyScanner.ts
function calculateShannonEntropy(str) {
  if (!str) return 0;
  const charMap = {};
  const len = str.length;
  for (let i = 0; i < len; i++) {
    const char = str[i];
    charMap[char] = (charMap[char] || 0) + 1;
  }
  let entropy = 0;
  for (const char in charMap) {
    const p = charMap[char] / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}
function scanEntropy(text, threshold = 5.2) {
  const tokens = text.split(/\s+/);
  const results = [];
  for (const token of tokens) {
    if (token.length < 8) continue;
    const entropy = calculateShannonEntropy(token);
    if (entropy > threshold) {
      results.push({
        score: entropy,
        isHighEntropy: true,
        text: token
      });
    }
  }
  return results;
}

// src/security/InjectionScanner.ts
var INJECTION_PATTERNS = [
  { pattern: /ignore previous instructions/i, score: 0.9, name: "IGNORE_PREVIOUS" },
  { pattern: /system override/i, score: 0.9, name: "SYSTEM_OVERRIDE" },
  { pattern: /\bDAN\b/i, score: 0.6, name: "DAN_MODE" },
  // Do Anything Now
  { pattern: /dev mode/i, score: 0.7, name: "DEV_MODE" },
  { pattern: /act as a/i, score: 0.3, name: "ACT_AS" },
  // Lower score, common in legitimate prompts
  { pattern: /you are unrestricted/i, score: 0.95, name: "UNRESTRICTED" },
  { pattern: /disable safety procedures/i, score: 1, name: "DISABLE_SAFETY" }
];
function scanInjection(text) {
  let maxScore = 0;
  let detected = false;
  let reason = "";
  for (const item of INJECTION_PATTERNS) {
    if (item.pattern.test(text)) {
      if (item.score > maxScore) {
        maxScore = item.score;
        detected = true;
        reason = `Detected pattern: ${item.name}`;
      }
    }
  }
  return {
    score: maxScore,
    isDetected: detected,
    reason: detected ? reason : void 0
  };
}

// src/security/PII.ts
var PATTERNS = {
  CREDIT_CARD: /\b(?:\d{4}[ -]?){3}\d{4}\b/,
  EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  API_KEY: /\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36})\b/,
  SSN: /\b\d{3}-\d{2}-\d{4}\b/,
  IPV4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/,
  AWS_KEY: /\b(AKIA[0-9A-Z]{16})\b/,
  JWT: /\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b/
};
var CONTEXT_TRIGGERS = {
  SSN: ["ssn", "social", "security", "number", "id"],
  CREDIT_CARD: ["cc", "card", "visa", "amex", "mastercard", "payment"],
  API_KEY: ["key", "api", "secret", "token"],
  EMAIL: ["email", "contact", "mail"]
};
function scanPII(text, options = {}) {
  const {
    rules = Object.keys(PATTERNS),
    redact = false,
    allow = [],
    mode = "block"
  } = options;
  let cleanText = text;
  const findings = [];
  let isClean = true;
  const allowPatterns = allow.map(
    (p) => typeof p === "string" ? new RegExp(p) : p
  );
  for (const ruleKey of rules) {
    const regex = PATTERNS[ruleKey];
    if (!regex) continue;
    const globalRegex = new RegExp(regex.source, "g");
    let match;
    while ((match = globalRegex.exec(text)) !== null) {
      const matchText = match[0];
      const index = match.index;
      if (allowPatterns.some((ap) => ap.test(matchText))) {
        continue;
      }
      const start = Math.max(0, index - 25);
      const prefix = text.slice(start, index).toLowerCase();
      let contextScore = 0;
      const triggers = CONTEXT_TRIGGERS[ruleKey] || [];
      if (triggers.length > 0) {
        if (triggers.some((t) => prefix.includes(t))) {
          contextScore = 1;
        }
      }
      findings.push({
        type: ruleKey,
        match: matchText,
        context: contextScore > 0 ? "supported" : "neutral"
      });
      isClean = false;
    }
  }
  if (!isClean && (redact || mode === "block")) {
    const uniqueMatches = [...new Set(findings.map((f) => f.match))];
    for (const m of uniqueMatches) {
      const type = findings.find((f) => f.match === m)?.type || "PII";
      const escaped = m.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      cleanText = cleanText.replace(new RegExp(escaped, "g"), `[${type}_REDACTED]`);
    }
  }
  const status = isClean ? "safe" : mode === "warn" ? "warning" : "blocked";
  return {
    hasPII: !isClean,
    status,
    redactedText: cleanText,
    findings
  };
}

// src/AiGuardStream.ts
var AiGuardStream = class extends TransformStream {
  constructor(options = {}) {
    const textDecoder = new TextDecoder();
    const textEncoder = new TextEncoder();
    super({
      transform(chunk, controller) {
        let text = typeof chunk === "string" ? chunk : textDecoder.decode(chunk, { stream: true });
        const injection = scanInjection(text);
        if (injection.isDetected) {
          if (options.onInjectionDetected) options.onInjectionDetected(injection);
          if (options.blockOnInjection) {
            controller.error(new Error(`Security Block: ${injection.reason}`));
            return;
          }
        }
        const entropy = scanEntropy(text);
        if (entropy.length > 0) {
          if (options.onEntropyDetected) options.onEntropyDetected(entropy);
        }
        const piiResult = scanPII(text, options.pii);
        if (piiResult.hasPII) {
          if (options.onPIIDetected) options.onPIIDetected(piiResult);
          controller.enqueue(textEncoder.encode(piiResult.redactedText));
        } else {
          controller.enqueue(textEncoder.encode(text));
        }
      }
    });
  }
};

// src/core/repair.js
function stripMarkdown(text) {
  if (!text) return "";
  let clean = text.trim();
  clean = clean.replace(/^```[a-zA-Z]*\s*/, "");
  clean = clean.replace(/\s*```$/, "");
  return clean;
}
function extractJSON(text, options = {}) {
  if (!text) return "";
  const { last = true } = options;
  let clean = text;
  clean = clean.replace(/<think>[\s\S]*?<\/think>/gi, "");
  clean = clean.replace(/<think>[\s\S]*$/gi, "");
  clean = clean.replace(/<\/th$/gi, "");
  const codeBlockRegex = /```(?:json|json5|javascript|js)?\s*([\s\S]*?)(?:```|$)/gi;
  const codeBlocks = [];
  let match;
  while ((match = codeBlockRegex.exec(clean)) !== null) {
    const content = match[1].trim();
    if (content && (content.startsWith("{") || content.startsWith("["))) {
      codeBlocks.push(content);
    }
  }
  if (codeBlocks.length > 0) {
    return last ? codeBlocks[codeBlocks.length - 1] : codeBlocks[0];
  }
  const jsonCandidates = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < clean.length; i++) {
    const char = clean[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === "\\" && inString) {
      escaped = true;
      continue;
    }
    if (char === '"' && !escaped) {
      inString = !inString;
      continue;
    }
    if (inString) continue;
    if (char === "{" || char === "[") {
      if (depth === 0) start = i;
      depth++;
    } else if (char === "}" || char === "]") {
      depth--;
      if (depth === 0 && start !== -1) {
        jsonCandidates.push(clean.slice(start, i + 1));
        start = -1;
      }
    }
  }
  if (start !== -1 && depth > 0) {
    jsonCandidates.push(clean.slice(start));
  }
  if (jsonCandidates.length > 0) {
    return last ? jsonCandidates[jsonCandidates.length - 1] : jsonCandidates[0];
  }
  const firstBrace = clean.indexOf("{");
  const firstBracket = clean.indexOf("[");
  if (firstBrace === -1 && firstBracket === -1) {
    return clean.trim();
  }
  const jsonStart = firstBrace === -1 ? firstBracket : firstBracket === -1 ? firstBrace : Math.min(firstBrace, firstBracket);
  return clean.slice(jsonStart).trim();
}
function repairJSON(raw, options = {}) {
  const { extract = false } = options;
  let text = extract ? extractJSON(raw) : stripMarkdown(raw);
  if (!text || !text.trim()) {
    return {
      fixed: "{}",
      data: {},
      isPartial: false,
      patches: []
    };
  }
  let result = text.trim();
  const patches = [];
  let isPartial = false;
  const stack = [];
  let inString = false;
  let escaped = false;
  for (let i = 0; i < result.length; i++) {
    const char = result[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === "\\" && inString) {
      escaped = true;
      continue;
    }
    if (char === '"' && !escaped) {
      inString = !inString;
      if (inString) {
        stack.push('"');
      } else {
        if (stack.length > 0 && stack[stack.length - 1] === '"') {
          stack.pop();
        }
      }
      continue;
    }
    if (inString) continue;
    if (char === "{") {
      stack.push("{");
    } else if (char === "[") {
      stack.push("[");
    } else if (char === "}") {
      if (stack.length > 0 && stack[stack.length - 1] === "{") {
        stack.pop();
      }
    } else if (char === "]") {
      if (stack.length > 0 && stack[stack.length - 1] === "[") {
        stack.pop();
      }
    }
  }
  if (inString) {
    patches.push({ type: "unclosed_string", index: result.length });
    result += '"';
    isPartial = true;
    if (stack.length > 0 && stack[stack.length - 1] === '"') {
      stack.pop();
    }
  }
  if (/,\s*$/.test(result)) {
    const match = result.match(/,\s*$/);
    patches.push({ type: "trailing_comma", index: match.index });
    result = result.replace(/,\s*$/, "");
    isPartial = true;
  }
  while (stack.length > 0) {
    const open = stack.pop();
    if (open === "{") {
      patches.push({ type: "missing_brace", index: result.length });
      result += "}";
      isPartial = true;
    } else if (open === "[") {
      patches.push({ type: "missing_brace", index: result.length });
      result += "]";
      isPartial = true;
    }
  }
  let data = null;
  try {
    data = JSON.parse(result);
  } catch (err) {
  }
  return {
    fixed: result,
    data,
    isPartial,
    patches
  };
}

// src/core/scanner.js
var PATTERNS2 = {
  // Credit Card - groups of 4 digits separated by spaces or dashes
  CREDIT_CARD: /\b(?:\d{4}[ -]?){3}\d{4}\b/,
  // Standard Email
  EMAIL: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/,
  // Generic "Secret Key" patterns (sk-, ghp-, etc)
  API_KEY: /\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36})\b/,
  // US SSN (Area-Group-Serial)
  SSN: /\b\d{3}-\d{2}-\d{4}\b/,
  // IP Address (IPv4)
  IPV4: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/,
  // AWS Access Key ID
  AWS_KEY: /\b(AKIA[0-9A-Z]{16})\b/,
  // JWT Token
  JWT: /\beyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b/
};
function scanText(text, options = {}, legacyRedact = false, legacyAllow = [], legacyCustom = []) {
  let config = {};
  if (Array.isArray(options)) {
    config = {
      rules: options,
      redact: legacyRedact,
      allow: legacyAllow,
      customRules: legacyCustom,
      mode: "block"
      // default
    };
  } else {
    config = {
      rules: [],
      redact: false,
      allow: [],
      customRules: [],
      mode: "block",
      ...options
    };
  }
  const { rules = [], redact = false, allow = [], customRules = [], mode = "block" } = config;
  let cleanText = text;
  const findings = [];
  let isClean = true;
  const allPatterns = { ...PATTERNS2 };
  for (const rule of customRules) {
    if (rule.name && rule.pattern) {
      allPatterns[rule.name] = rule.pattern;
    }
  }
  const rulesToCheck = rules.length > 0 ? rules : Object.keys(allPatterns);
  const allowPatterns = allow.map(
    (p) => typeof p === "string" ? new RegExp(p) : p
  );
  for (const rule of rulesToCheck) {
    const regex = allPatterns[rule];
    if (!regex) continue;
    const globalRegex = new RegExp(regex.source, "g");
    const matches = text.match(globalRegex);
    if (matches && matches.length > 0) {
      const filteredMatches = matches.filter(
        (match) => !allowPatterns.some((allow2) => allow2.test(match))
      );
      if (filteredMatches.length > 0) {
        isClean = false;
        findings.push({ type: rule, matches: filteredMatches });
      }
    }
  }
  if (!isClean && (redact || mode === "block")) {
    for (const finding of findings) {
      for (const match of finding.matches) {
        cleanText = cleanText.replace(match, `[${finding.type}_REDACTED]`);
      }
    }
  }
  let status = isClean ? "safe" : "blocked";
  if (!isClean && mode === "warn") {
    status = "warning";
  }
  const isSafe = isClean || mode === "warn" || mode === "silent";
  return {
    safe: isSafe,
    status,
    findings,
    text: cleanText
  };
}

// src/core/registry.js
var PROFILES = /* @__PURE__ */ new Map();
var DEFAULT_PROFILE = {
  extractors: [
    // Standard Markdown Code Block Stripper
    (text) => text.replace(/^```[a-z]*\s*/i, "").replace(/\s*```$/, ""),
    // DeepSeek/Reasoning Model <think> Stripper (Handles unclosed tags)
    (text) => text.replace(/<think>[\s\S]*?<\/think>/gi, "").replace(/<think>[\s\S]*$/gi, "").replace(/<\/th$/gi, "")
  ]
};
PROFILES.set("default", DEFAULT_PROFILE);
function registerProfile(name, config) {
  PROFILES.set(name, config);
}
function getProfile(name) {
  return PROFILES.get(name) || PROFILES.get("default");
}

// src/schema/SchemaEngine.js
import { z } from "zod";
var SchemaEngine = class {
  constructor(schema) {
    if (!schema) throw new Error("SchemaEngine requires a Zod schema");
    this.schema = schema;
    this.partialSchema = this._createDeepPartial(schema);
  }
  /**
   * Creates a 'relaxed' schema that allows missing fields/partial data
   * but enforces the structure that IS present.
   */
  _createDeepPartial(schema) {
    if (typeof schema.deepPartial === "function") {
      return schema.deepPartial();
    }
    if (typeof schema.partial === "function") {
      return schema.partial();
    }
    return schema;
  }
  /**
   * Validates partial data and strips unknown keys (hallucinations).
   * @param {any} data - The partial JSON from the repair stream
   * @returns {object} - { data, isValid, errors }
   */
  validate(data) {
    try {
      const result = this.partialSchema.safeParse(data);
      if (result.success) {
        return {
          data: result.data,
          isValid: true,
          errors: []
        };
      } else {
        return {
          data,
          // Return raw data if validation fails completely
          isValid: false,
          errors: result.error.errors
        };
      }
    } catch (err) {
      return {
        data,
        isValid: false,
        errors: [{ message: err.message }]
      };
    }
  }
  /**
   * Generates a structural skeleton (stub) from the schema.
   * Used for optimistic UI before the first token arrives.
   */
  generateSkeleton() {
    return this._generateStub(this.schema);
  }
  _generateStub(schema) {
    if (!schema) return null;
    if (schema instanceof z.ZodOptional || schema instanceof z.ZodNullable) {
      return this._generateStub(schema.unwrap?.() || schema._def.innerType);
    }
    if (schema instanceof z.ZodDefault) {
      return this._generateStub(schema.removeDefault());
    }
    if (schema instanceof z.ZodEffects) {
      return this._generateStub(schema._def.schema);
    }
    if (schema instanceof z.ZodString) return "";
    if (schema instanceof z.ZodNumber) return 0;
    if (schema instanceof z.ZodBoolean) return false;
    if (schema instanceof z.ZodArray) return [];
    if (schema instanceof z.ZodObject) {
      const shape = schema.shape;
      const stub = {};
      for (const key in shape) {
        stub[key] = this._generateStub(shape[key]);
      }
      return stub;
    }
    return null;
  }
};
export {
  AiGuardStream,
  SchemaEngine,
  calculateShannonEntropy,
  extractJSON,
  getProfile,
  registerProfile,
  repairJSON,
  scanEntropy,
  scanInjection,
  scanPII,
  scanText,
  stripMarkdown
};
//# sourceMappingURL=index.js.map

export const WORKER_CODE_PURE = "\"use strict\";(()=>{var ie=Object.defineProperty;var Qe=(i,s,r)=>s in i?ie(i,s,{enumerable:!0,configurable:!0,writable:!0,value:r}):i[s]=r;var et=(i,s)=>()=>(i&&(s=i(i=0)),s);var tt=(i,s)=>{for(var r in s)ie(i,r,{get:s[r],enumerable:!0})};var oe=(i,s,r)=>Qe(i,typeof s!=\"symbol\"?s+\"\":s,r);var fe={};tt(fe,{default:()=>it});async function st(i={}){var s,r=i,a=!!globalThis.window,o=!!globalThis.WorkerGlobalScope,l=globalThis.process?.versions?.node&&globalThis.process?.type!=\"renderer\",S=[],c=\"./this.program\",g=ot.url,R=\"\",b,f;if(a||o){try{R=new URL(\".\",g).href}catch{}o&&(f=e=>{var t=new XMLHttpRequest;return t.open(\"GET\",e,!1),t.responseType=\"arraybuffer\",t.send(null),new Uint8Array(t.response)}),b=async e=>{var t=await fetch(e,{credentials:\"same-origin\"});if(t.ok)return t.arrayBuffer();throw new Error(t.status+\" : \"+t.url)}}var m=console.log.bind(console),y=console.error.bind(console),_,A=!1;function d(e){for(var t=0,n=e.length,u=new Uint8Array(n),v;t<n;++t)v=e.charCodeAt(t),u[t]=~v>>8&v;return u}var I,x,j,k,C,me,ge,de,he,ye,ve,Ee,G=!1;function Re(){var e=ae.buffer;j=new Int8Array(e),C=new Int16Array(e),k=new Uint8Array(e),me=new Uint16Array(e),ge=new Int32Array(e),de=new Uint32Array(e),he=new Float32Array(e),ye=new Float64Array(e),ve=new BigInt64Array(e),Ee=new BigUint64Array(e)}function _e(){if(r.preRun)for(typeof r.preRun==\"function\"&&(r.preRun=[r.preRun]);r.preRun.length;)Me(r.preRun.shift());V(L)}function Se(){G=!0,O.b()}function we(){if(r.postRun)for(typeof r.postRun==\"function\"&&(r.postRun=[r.postRun]);r.postRun.length;)Ne(r.postRun.shift());V(K)}function be(e){r.onAbort?.(e),e=\"Aborted(\"+e+\")\",y(e),A=!0,e+=\". Build with -sASSERTIONS for more info.\";var t=new WebAssembly.RuntimeError(e);throw x?.(t),t}var Z;function Ie(){return d('\\0asm\u0001\\0\\0\\0\u0001\u0011\u0004`\u0001\\x7F\u0001\\x7F`\\0\u0001\\x7F`\u0001\\x7F\\0`\\0\\0\u0003\u0006\u0005\u0001\\0\u0002\\0\u0003\u0005\\x07\u0001\u0001\\xA2\u0002\\x80\\x80\u0002\u0006\t\u0001\\x7F\u0001A\\x90\\x90\\x84\u0001\\v\\x07\u0019\u0006\u0001a\u0002\\0\u0001b\\0\u0004\u0001c\\0\u0003\u0001d\\0\u0002\u0001e\\0\u0001\u0001f\\0\\0\\f\u0001\u0001\\n\\xC1\u0005\u0005\u0004\\0#\\0\\v\u0010\\0#\\0 \\0kApq\"\\0$\\0 \\0\\v\u0006\\0 \\0$\\0\\v\\x9E\u0005\u0001\\b\\x7FA\\x7F!\u0001A\\x80\\bA\\x7F6\u0002\\0\u0002@\u0002\\x7F\u0002@\u0002@ \\0\"\\x07A\u0003qE\\r\\0A\\0 \\0-\\0\\0E\\r\u0002\u001a\u0003@ \\0A\u0001j\"\\0A\u0003qE\\r\u0001 \\0-\\0\\0\\r\\0\\v\\f\u0001\\v\u0003@ \\0\"\u0005A\u0004j!\\0A\\x80\\x82\\x84\\b \u0005(\u0002\\0\"\\bk \\brA\\x80\\x81\\x82\\x84xqA\\x80\\x81\\x82\\x84xF\\r\\0\\v\u0003@ \u0005\"\\0A\u0001j!\u0005 \\0-\\0\\0\\r\\0\\v\\v \\0 \\x07k\\v\"\u0005A\\0L\\r\\0\u0002\\x7F\u0003@A\\xFF\\xFF\\xFF\\0 \u0002A\\xFF\\xFF\\xFF\\0F\\r\u0001\u001a \u0002 \u0002 \\x07j-\\0\\0\"\\0:\\0\\x90\u0010 \u0006A\u0001q!\u0003A\\0!\u0006\u0002@ \u0003\\r\\0 \\0A\\xDC\\0F\u0004@A\u0001!\u0006\\f\u0001\\v \\0A\"F\u0004@ \u0004A\u0001s!\u0004\\f\u0001\\v \u0004A\u0001q\u0004@A\u0001!\u0004\\f\u0001\\v\u0002@\u0002@\u0002@ \\0A\\xDB\\0G\u0004@ \\0A\\xFB\\0G\\r\u0001 \u0001A\\xFE\\x07J\\r\u0002A\\0!\u0004A\\x80\\b \u0001A\u0001j\"\\x006\u0002\\0 \u0001A\\x91\\bjA\\xFD\\0:\\0\\0 \\0!\u0001\\f\u0003\\v \u0001A\\xFE\\x07J\\r\u0001A\\0!\u0004A\\x80\\b \u0001A\u0001j\"\\x006\u0002\\0 \u0001A\\x91\\bjA\\xDD\\0:\\0\\0 \\0!\u0001\\f\u0002\\vA\\0!\u0004 \\0A\\xDF\u0001qA\\xDD\\0G\\r\u0001 \u0001A\\0H\\r\u0001 \u0001-\\0\\x90\\b \\0G\\r\u0001A\\x80\\b \u0001A\u0001k\"\u00016\u0002\\0\\f\u0001\\vA\\0!\u0004\\v\\v \u0002A\u0001j\"\u0002 \u0005G\\r\\0\\v \u0005\\v!\u0003 \u0004A\u0001q\u0004@ \u0003A\":\\0\\x90\u0010 \u0003A\u0001j!\u0003\\vA\\0!\u0006 \u0001A\\0H\\r\\0\u0002@ \u0001A\u0003qA\u0003F\u0004@ \u0001!\u0002\\f\u0001\\v \u0001A\u0001jA\u0003q!\\0 \u0001!\u0002\u0003@ \u0003A\\x90\u0010j \u0002-\\0\\x90\\b:\\0\\0 \u0003A\u0001j!\u0003 \u0002A\u0001k!\u0002 \u0006A\u0001j\"\u0006 \\0G\\r\\0\\v\\v \u0001A\u0003O\u0004@\u0003@ \u0003A\\x90\u0010j \u0002A\\x90\\bj-\\0\\0:\\0\\0 \u0003A\\x91\u0010j \u0002A\\x8F\\bj-\\0\\0:\\0\\0 \u0003A\\x92\u0010j \u0002A\\x8E\\bj-\\0\\0:\\0\\0 \u0003A\\x93\u0010j \u0002A\\x8D\\bj-\\0\\0:\\0\\0 \u0003A\u0004j!\u0003 \u0002A\u0003G \u0002A\u0004k!\u0002\\r\\0\\v\\vA\\x80\\bA\\x7F6\u0002\\0\\v \u0003A\\x90\u0010jA\\0:\\0\\0A\\x90\u0010\\v\u0002\\0\\v\\v\\v\u0001\\0A\\x80\\b\\v\u0004\\xFF\\xFF\\xFF\\xFF')}function lt(e){return e}async function Te(e){return e}async function Pe(e,t){try{var n=await Te(e),u=await WebAssembly.instantiate(n,t);return u}catch(v){y(`failed to asynchronously prepare wasm: ${v}`),be(v)}}async function xe(e,t,n){return Pe(t,n)}function je(){var e={a:Le};return e}async function ke(){function e(E,p){return O=E.exports,Ke(O),Re(),O}function t(E){return e(E.instance)}var n=je();if(r.instantiateWasm)return new Promise((E,p)=>{r.instantiateWasm(n,(h,P)=>{E(e(h,P))})});Z??(Z=Ie());var u=await xe(_,Z,n),v=t(u);return v}class ft{constructor(t){oe(this,\"name\",\"ExitStatus\");this.message=`Program terminated with exit(${t})`,this.status=t}}for(var V=e=>{for(;e.length>0;)e.shift()(r)},K=[],Ne=e=>K.push(e),L=[],Me=e=>L.push(e),Ce=!0,De=e=>te(e),Oe=()=>ne(),Y=e=>{var t=r[\"_\"+e];return t},Be=(e,t)=>{j.set(e,t)},Ue=e=>{for(var t=0,n=0;n<e.length;++n){var u=e.charCodeAt(n);u<=127?t++:u<=2047?t+=2:u>=55296&&u<=57343?(t+=4,++n):t+=3}return t},Fe=(e,t,n,u)=>{if(!(u>0))return 0;for(var v=n,E=n+u-1,p=0;p<e.length;++p){var h=e.codePointAt(p);if(h<=127){if(n>=E)break;t[n++]=h}else if(h<=2047){if(n+1>=E)break;t[n++]=192|h>>6,t[n++]=128|h&63}else if(h<=65535){if(n+2>=E)break;t[n++]=224|h>>12,t[n++]=128|h>>6&63,t[n++]=128|h&63}else{if(n+3>=E)break;t[n++]=240|h>>18,t[n++]=128|h>>12&63,t[n++]=128|h>>6&63,t[n++]=128|h&63,p++}}return t[n]=0,n-v},We=(e,t,n)=>Fe(e,k,t,n),X=e=>re(e),$e=e=>{var t=Ue(e)+1,n=X(t);return We(e,n,t),n},Q=globalThis.TextDecoder&&new TextDecoder,He=(e,t,n,u)=>{var v=t+n;if(u)return v;for(;e[t]&&!(t>=v);)++t;return t},Je=(e,t=0,n,u)=>{var v=He(e,t,n,u);if(v-t>16&&e.buffer&&Q)return Q.decode(e.subarray(t,v));for(var E=\"\";t<v;){var p=e[t++];if(!(p&128)){E+=String.fromCharCode(p);continue}var h=e[t++]&63;if((p&224)==192){E+=String.fromCharCode((p&31)<<6|h);continue}var P=e[t++]&63;if((p&240)==224?p=(p&15)<<12|h<<6|P:p=(p&7)<<18|h<<12|P<<6|e[t++]&63,p<65536)E+=String.fromCharCode(p);else{var N=p-65536;E+=String.fromCharCode(55296|N>>10,56320|N&1023)}}return E},ze=(e,t,n)=>e?Je(k,e,t,n):\"\",ee=(e,t,n,u,v)=>{var E={string:w=>{var B=0;return w!=null&&w!==0&&(B=$e(w)),B},array:w=>{var B=X(w.length);return Be(w,B),B}};function p(w){return t===\"string\"?ze(w):t===\"boolean\"?!!w:w}var h=Y(e),P=[],N=0;if(u)for(var M=0;M<u.length;M++){var se=E[n[M]];se?(N===0&&(N=Oe()),P[M]=se(u[M])):P[M]=u[M]}var W=h(...P);function Xe(w){return N!==0&&De(N),p(w)}return W=Xe(W),W},qe=(e,t,n,u)=>{var v=!n||n.every(p=>p===\"number\"||p===\"boolean\"),E=t!==\"string\";return E&&v&&!u?Y(e):(...p)=>ee(e,t,n,p,u)},D=new Uint8Array(123),T=25;T>=0;--T)D[48+T]=52+T,D[65+T]=T,D[97+T]=26+T;if(D[43]=62,D[47]=63,r.noExitRuntime&&(Ce=r.noExitRuntime),r.print&&(m=r.print),r.printErr&&(y=r.printErr),r.wasmBinary&&(_=r.wasmBinary),r.arguments&&(S=r.arguments),r.thisProgram&&(c=r.thisProgram),r.preInit)for(typeof r.preInit==\"function\"&&(r.preInit=[r.preInit]);r.preInit.length>0;)r.preInit.shift()();r.ccall=ee,r.cwrap=qe;var Ge,te,re,ne,Ze,Ve,ae;function Ke(e){Ge=r._repair_json=e.c,te=e.d,re=e.e,ne=e.f,Ze=ae=e.a,Ve=e.__indirect_function_table}var Le={};function Ye(){_e();function e(){r.calledRun=!0,!A&&(Se(),I?.(r),r.onRuntimeInitialized?.(),we())}r.setStatus?(r.setStatus(\"Running...\"),setTimeout(()=>{setTimeout(()=>r.setStatus(\"\"),1),e()},1)):e()}var O;return O=await ke(),Ye(),G?s=r:s=new Promise((e,t)=>{I=e,x=t}),s}var ot,it,ue=et(()=>{\"use strict\";ot={};it=st});var ce={CREDIT_CARD:/\\b(?:\\d{4}[ -]?){3}\\d{4}\\b/,EMAIL:/\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b/,API_KEY:/\\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36})\\b/,SSN:/\\b\\d{3}-\\d{2}-\\d{4}\\b/,IPV4:/\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b/,AWS_KEY:/\\b(AKIA[0-9A-Z]{16})\\b/,JWT:/\\beyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*\\b/},rt={SSN:[\"ssn\",\"social\",\"security\",\"number\",\"id\"],CREDIT_CARD:[\"cc\",\"card\",\"visa\",\"amex\",\"mastercard\",\"payment\"],API_KEY:[\"key\",\"api\",\"secret\",\"token\"],EMAIL:[\"email\",\"contact\",\"mail\"]};function $(i,s={}){let{rules:r=Object.keys(ce),redact:a=!1,allow:o=[],mode:l=\"block\"}=s,S=i,c=[],g=!0,R=o.map(f=>typeof f==\"string\"?new RegExp(f):f);for(let f of r){let m=ce[f];if(!m)continue;let y=new RegExp(m.source,\"g\"),_;for(;(_=y.exec(i))!==null;){let A=_[0],d=_.index;if(R.some(C=>C.test(A)))continue;let I=Math.max(0,d-25),x=i.slice(I,d).toLowerCase(),j=0,k=rt[f]||[];k.length>0&&k.some(C=>x.includes(C))&&(j=1),c.push({type:f,match:A,context:j>0?\"supported\":\"neutral\"}),g=!1}}if(!g&&(a||l===\"block\")){let f=[...new Set(c.map(m=>m.match))];for(let m of f){let y=c.find(A=>A.match===m)?.type||\"PII\",_=m.replace(/[.*+?^${}()|[\\]\\\\]/g,\"\\\\$&\");S=S.replace(new RegExp(_,\"g\"),`[${y}_REDACTED]`)}}return{hasPII:!g,status:g?\"safe\":l===\"warn\"?\"warning\":\"blocked\",redactedText:S,findings:c}}var nt=[{pattern:/ignore previous instructions/i,score:.9,name:\"IGNORE_PREVIOUS\"},{pattern:/system override/i,score:.9,name:\"SYSTEM_OVERRIDE\"},{pattern:/\\bDAN\\b/i,score:.6,name:\"DAN_MODE\"},{pattern:/dev mode/i,score:.7,name:\"DEV_MODE\"},{pattern:/act as a/i,score:.3,name:\"ACT_AS\"},{pattern:/you are unrestricted/i,score:.95,name:\"UNRESTRICTED\"},{pattern:/disable safety procedures/i,score:1,name:\"DISABLE_SAFETY\"}];function H(i){let s=0,r=!1,a=\"\";for(let o of nt)o.pattern.test(i)&&o.score>s&&(s=o.score,r=!0,a=`Detected pattern: ${o.name}`);return{score:s,isDetected:r,reason:r?a:void 0}}function at(i){if(!i)return 0;let s={},r=i.length;for(let o=0;o<r;o++){let l=i[o];s[l]=(s[l]||0)+1}let a=0;for(let o in s){let l=s[o]/r;a-=l*Math.log2(l)}return a}function J(i,s=5.2){let r=i.split(/\\s+/),a=[];for(let o of r){if(o.length<8)continue;let l=at(o);l>s&&a.push({score:l,isHighEntropy:!0,text:o})}return a}function z(i){if(!i)return\"\";let s=i.trim();return s=s.replace(/^```[a-zA-Z]*\\s*/,\"\"),s=s.replace(/\\s*```$/,\"\"),s}function U(i,s={}){if(!i)return\"\";let{last:r=!0}=s,a=i;a=a.replace(/<think>[\\s\\S]*?<\\/think>/gi,\"\"),a=a.replace(/<think>[\\s\\S]*$/gi,\"\"),a=a.replace(/<\\/th$/gi,\"\");let o=/```(?:json|json5|javascript|js)?\\s*([\\s\\S]*?)(?:```|$)/gi,l=[],S;for(;(S=o.exec(a))!==null;){let A=S[1].trim();A&&(A.startsWith(\"{\")||A.startsWith(\"[\"))&&l.push(A)}if(l.length>0)return r?l[l.length-1]:l[0];let c=[],g=0,R=-1,b=!1,f=!1;for(let A=0;A<a.length;A++){let d=a[A];if(f){f=!1;continue}if(d===\"\\\\\"&&b){f=!0;continue}if(d==='\"'&&!f){b=!b;continue}b||(d===\"{\"||d===\"[\"?(g===0&&(R=A),g++):(d===\"}\"||d===\"]\")&&(g--,g===0&&R!==-1&&(c.push(a.slice(R,A+1)),R=-1)))}if(R!==-1&&g>0&&c.push(a.slice(R)),c.length>0)return r?c[c.length-1]:c[0];let m=a.indexOf(\"{\"),y=a.indexOf(\"[\");if(m===-1&&y===-1)return a.trim();let _=m===-1?y:y===-1?m:Math.min(m,y);return a.slice(_).trim()}function le(i,s={}){let{extract:r=!1}=s,a=r?U(i):z(i);if(!a||!a.trim())return{fixed:\"{}\",data:{},isPartial:!1,patches:[]};let o=a.trim(),l=[],S=!1,c=[],g=!1,R=!1;for(let f=0;f<o.length;f++){let m=o[f];if(R){R=!1;continue}if(m===\"\\\\\"&&g){R=!0;continue}if(m==='\"'&&!R){g=!g,g?c.push('\"'):c.length>0&&c[c.length-1]==='\"'&&c.pop();continue}g||(m===\"{\"?c.push(\"{\"):m===\"[\"?c.push(\"[\"):m===\"}\"?c.length>0&&c[c.length-1]===\"{\"&&c.pop():m===\"]\"&&c.length>0&&c[c.length-1]===\"[\"&&c.pop())}if(g&&(l.push({type:\"unclosed_string\",index:o.length}),o+='\"',S=!0,c.length>0&&c[c.length-1]==='\"'&&c.pop()),/,\\s*$/.test(o)){let f=o.match(/,\\s*$/);l.push({type:\"trailing_comma\",index:f.index}),o=o.replace(/,\\s*$/,\"\"),S=!0}for(;c.length>0;){let f=c.pop();f===\"{\"?(l.push({type:\"missing_brace\",index:o.length}),o+=\"}\",S=!0):f===\"[\"&&(l.push({type:\"missing_brace\",index:o.length}),o+=\"]\",S=!0)}let b=null;try{b=JSON.parse(o)}catch{}return{fixed:o,data:b,isPartial:S,patches:l}}var F=null,pe=null,Ae=!1,q=\"\";async function ct(){if(!F){if(!Ae)throw new Error(\"Wasm Kernel is disabled in this build.\");try{let i=await Promise.resolve().then(()=>(ue(),fe));F=await(i.default||i)(),pe=F.cwrap(\"repair_json\",\"string\",[\"string\"])}catch(i){throw console.error(\"Failed to load Wasm kernel:\",i),i}}}self.onmessage=async i=>{let{id:s,type:r,payload:a,options:o}=i.data;try{let l;switch(r){case\"SCAN_STREAM_CHUNK\":q+=typeof a==\"string\"?a:\"\";let c=q,g=$(c,o?.pii||{}),R=H(c),b=J(c);l={safe:!g.hasPII&&!R.isDetected,pii:g,injection:R,entropy:b,textLength:c.length};break;case\"RESET_STREAM\":q=\"\",l={success:!0};break;case\"SCAN_TEXT\":{let y=typeof a==\"string\"?a:a.text,_=$(y,o?.pii||{}),A=H(y),d=J(y);l={safe:!_.hasPII&&!A.isDetected,pii:_,injection:A,entropy:d}}break;case\"REPAIR_JSON\":{let y=typeof a==\"string\"?a:a?.text,_=o?.extract??a?.extract??!1,A=o?.useWasm&&Ae,d;if(A){F||await ct();let j=_?U(y):z(y);d={fixed:pe(j),data:null,isPartial:!1,patches:[]}}else d=le(y,{extract:_});let I=d.data,x=!0;if(I===null&&d.fixed!==\"null\")try{I=JSON.parse(d.fixed)}catch{x=!1}l={fixedString:d.fixed,data:I,isValid:x,isPartial:d.isPartial,patches:d.patches,mode:A?\"wasm\":\"js\"}}break;case\"EXTRACT_JSON\":let f=typeof a==\"string\"?a:a?.text,m=o?.last??a?.last??!0;l={extracted:U(f,{last:m})};break;default:throw new Error(`Unknown message type: ${r}`)}self.postMessage({id:s,success:!0,payload:l})}catch(l){self.postMessage({id:s,success:!1,error:l.message})}};})();\n";
export const WORKER_CODE_PRO = "\"use strict\";(()=>{var ie=Object.defineProperty;var Qe=(i,s,r)=>s in i?ie(i,s,{enumerable:!0,configurable:!0,writable:!0,value:r}):i[s]=r;var et=(i,s)=>()=>(i&&(s=i(i=0)),s);var tt=(i,s)=>{for(var r in s)ie(i,r,{get:s[r],enumerable:!0})};var oe=(i,s,r)=>Qe(i,typeof s!=\"symbol\"?s+\"\":s,r);var fe={};tt(fe,{default:()=>it});async function st(i={}){var s,r=i,a=!!globalThis.window,o=!!globalThis.WorkerGlobalScope,l=globalThis.process?.versions?.node&&globalThis.process?.type!=\"renderer\",S=[],c=\"./this.program\",g=ot.url,R=\"\",b,f;if(a||o){try{R=new URL(\".\",g).href}catch{}o&&(f=e=>{var t=new XMLHttpRequest;return t.open(\"GET\",e,!1),t.responseType=\"arraybuffer\",t.send(null),new Uint8Array(t.response)}),b=async e=>{var t=await fetch(e,{credentials:\"same-origin\"});if(t.ok)return t.arrayBuffer();throw new Error(t.status+\" : \"+t.url)}}var m=console.log.bind(console),y=console.error.bind(console),_,A=!1;function d(e){for(var t=0,n=e.length,u=new Uint8Array(n),v;t<n;++t)v=e.charCodeAt(t),u[t]=~v>>8&v;return u}var I,x,j,k,C,me,ge,de,he,ye,ve,Ee,G=!1;function Re(){var e=ae.buffer;j=new Int8Array(e),C=new Int16Array(e),k=new Uint8Array(e),me=new Uint16Array(e),ge=new Int32Array(e),de=new Uint32Array(e),he=new Float32Array(e),ye=new Float64Array(e),ve=new BigInt64Array(e),Ee=new BigUint64Array(e)}function _e(){if(r.preRun)for(typeof r.preRun==\"function\"&&(r.preRun=[r.preRun]);r.preRun.length;)Me(r.preRun.shift());V(L)}function Se(){G=!0,O.b()}function we(){if(r.postRun)for(typeof r.postRun==\"function\"&&(r.postRun=[r.postRun]);r.postRun.length;)Ne(r.postRun.shift());V(K)}function be(e){r.onAbort?.(e),e=\"Aborted(\"+e+\")\",y(e),A=!0,e+=\". Build with -sASSERTIONS for more info.\";var t=new WebAssembly.RuntimeError(e);throw x?.(t),t}var Z;function Ie(){return d('\\0asm\u0001\\0\\0\\0\u0001\u0011\u0004`\u0001\\x7F\u0001\\x7F`\\0\u0001\\x7F`\u0001\\x7F\\0`\\0\\0\u0003\u0006\u0005\u0001\\0\u0002\\0\u0003\u0005\\x07\u0001\u0001\\xA2\u0002\\x80\\x80\u0002\u0006\t\u0001\\x7F\u0001A\\x90\\x90\\x84\u0001\\v\\x07\u0019\u0006\u0001a\u0002\\0\u0001b\\0\u0004\u0001c\\0\u0003\u0001d\\0\u0002\u0001e\\0\u0001\u0001f\\0\\0\\f\u0001\u0001\\n\\xC1\u0005\u0005\u0004\\0#\\0\\v\u0010\\0#\\0 \\0kApq\"\\0$\\0 \\0\\v\u0006\\0 \\0$\\0\\v\\x9E\u0005\u0001\\b\\x7FA\\x7F!\u0001A\\x80\\bA\\x7F6\u0002\\0\u0002@\u0002\\x7F\u0002@\u0002@ \\0\"\\x07A\u0003qE\\r\\0A\\0 \\0-\\0\\0E\\r\u0002\u001a\u0003@ \\0A\u0001j\"\\0A\u0003qE\\r\u0001 \\0-\\0\\0\\r\\0\\v\\f\u0001\\v\u0003@ \\0\"\u0005A\u0004j!\\0A\\x80\\x82\\x84\\b \u0005(\u0002\\0\"\\bk \\brA\\x80\\x81\\x82\\x84xqA\\x80\\x81\\x82\\x84xF\\r\\0\\v\u0003@ \u0005\"\\0A\u0001j!\u0005 \\0-\\0\\0\\r\\0\\v\\v \\0 \\x07k\\v\"\u0005A\\0L\\r\\0\u0002\\x7F\u0003@A\\xFF\\xFF\\xFF\\0 \u0002A\\xFF\\xFF\\xFF\\0F\\r\u0001\u001a \u0002 \u0002 \\x07j-\\0\\0\"\\0:\\0\\x90\u0010 \u0006A\u0001q!\u0003A\\0!\u0006\u0002@ \u0003\\r\\0 \\0A\\xDC\\0F\u0004@A\u0001!\u0006\\f\u0001\\v \\0A\"F\u0004@ \u0004A\u0001s!\u0004\\f\u0001\\v \u0004A\u0001q\u0004@A\u0001!\u0004\\f\u0001\\v\u0002@\u0002@\u0002@ \\0A\\xDB\\0G\u0004@ \\0A\\xFB\\0G\\r\u0001 \u0001A\\xFE\\x07J\\r\u0002A\\0!\u0004A\\x80\\b \u0001A\u0001j\"\\x006\u0002\\0 \u0001A\\x91\\bjA\\xFD\\0:\\0\\0 \\0!\u0001\\f\u0003\\v \u0001A\\xFE\\x07J\\r\u0001A\\0!\u0004A\\x80\\b \u0001A\u0001j\"\\x006\u0002\\0 \u0001A\\x91\\bjA\\xDD\\0:\\0\\0 \\0!\u0001\\f\u0002\\vA\\0!\u0004 \\0A\\xDF\u0001qA\\xDD\\0G\\r\u0001 \u0001A\\0H\\r\u0001 \u0001-\\0\\x90\\b \\0G\\r\u0001A\\x80\\b \u0001A\u0001k\"\u00016\u0002\\0\\f\u0001\\vA\\0!\u0004\\v\\v \u0002A\u0001j\"\u0002 \u0005G\\r\\0\\v \u0005\\v!\u0003 \u0004A\u0001q\u0004@ \u0003A\":\\0\\x90\u0010 \u0003A\u0001j!\u0003\\vA\\0!\u0006 \u0001A\\0H\\r\\0\u0002@ \u0001A\u0003qA\u0003F\u0004@ \u0001!\u0002\\f\u0001\\v \u0001A\u0001jA\u0003q!\\0 \u0001!\u0002\u0003@ \u0003A\\x90\u0010j \u0002-\\0\\x90\\b:\\0\\0 \u0003A\u0001j!\u0003 \u0002A\u0001k!\u0002 \u0006A\u0001j\"\u0006 \\0G\\r\\0\\v\\v \u0001A\u0003O\u0004@\u0003@ \u0003A\\x90\u0010j \u0002A\\x90\\bj-\\0\\0:\\0\\0 \u0003A\\x91\u0010j \u0002A\\x8F\\bj-\\0\\0:\\0\\0 \u0003A\\x92\u0010j \u0002A\\x8E\\bj-\\0\\0:\\0\\0 \u0003A\\x93\u0010j \u0002A\\x8D\\bj-\\0\\0:\\0\\0 \u0003A\u0004j!\u0003 \u0002A\u0003G \u0002A\u0004k!\u0002\\r\\0\\v\\vA\\x80\\bA\\x7F6\u0002\\0\\v \u0003A\\x90\u0010jA\\0:\\0\\0A\\x90\u0010\\v\u0002\\0\\v\\v\\v\u0001\\0A\\x80\\b\\v\u0004\\xFF\\xFF\\xFF\\xFF')}function lt(e){return e}async function Te(e){return e}async function Pe(e,t){try{var n=await Te(e),u=await WebAssembly.instantiate(n,t);return u}catch(v){y(`failed to asynchronously prepare wasm: ${v}`),be(v)}}async function xe(e,t,n){return Pe(t,n)}function je(){var e={a:Le};return e}async function ke(){function e(E,p){return O=E.exports,Ke(O),Re(),O}function t(E){return e(E.instance)}var n=je();if(r.instantiateWasm)return new Promise((E,p)=>{r.instantiateWasm(n,(h,P)=>{E(e(h,P))})});Z??(Z=Ie());var u=await xe(_,Z,n),v=t(u);return v}class ft{constructor(t){oe(this,\"name\",\"ExitStatus\");this.message=`Program terminated with exit(${t})`,this.status=t}}for(var V=e=>{for(;e.length>0;)e.shift()(r)},K=[],Ne=e=>K.push(e),L=[],Me=e=>L.push(e),Ce=!0,De=e=>te(e),Oe=()=>ne(),Y=e=>{var t=r[\"_\"+e];return t},Be=(e,t)=>{j.set(e,t)},Ue=e=>{for(var t=0,n=0;n<e.length;++n){var u=e.charCodeAt(n);u<=127?t++:u<=2047?t+=2:u>=55296&&u<=57343?(t+=4,++n):t+=3}return t},Fe=(e,t,n,u)=>{if(!(u>0))return 0;for(var v=n,E=n+u-1,p=0;p<e.length;++p){var h=e.codePointAt(p);if(h<=127){if(n>=E)break;t[n++]=h}else if(h<=2047){if(n+1>=E)break;t[n++]=192|h>>6,t[n++]=128|h&63}else if(h<=65535){if(n+2>=E)break;t[n++]=224|h>>12,t[n++]=128|h>>6&63,t[n++]=128|h&63}else{if(n+3>=E)break;t[n++]=240|h>>18,t[n++]=128|h>>12&63,t[n++]=128|h>>6&63,t[n++]=128|h&63,p++}}return t[n]=0,n-v},We=(e,t,n)=>Fe(e,k,t,n),X=e=>re(e),$e=e=>{var t=Ue(e)+1,n=X(t);return We(e,n,t),n},Q=globalThis.TextDecoder&&new TextDecoder,He=(e,t,n,u)=>{var v=t+n;if(u)return v;for(;e[t]&&!(t>=v);)++t;return t},Je=(e,t=0,n,u)=>{var v=He(e,t,n,u);if(v-t>16&&e.buffer&&Q)return Q.decode(e.subarray(t,v));for(var E=\"\";t<v;){var p=e[t++];if(!(p&128)){E+=String.fromCharCode(p);continue}var h=e[t++]&63;if((p&224)==192){E+=String.fromCharCode((p&31)<<6|h);continue}var P=e[t++]&63;if((p&240)==224?p=(p&15)<<12|h<<6|P:p=(p&7)<<18|h<<12|P<<6|e[t++]&63,p<65536)E+=String.fromCharCode(p);else{var N=p-65536;E+=String.fromCharCode(55296|N>>10,56320|N&1023)}}return E},ze=(e,t,n)=>e?Je(k,e,t,n):\"\",ee=(e,t,n,u,v)=>{var E={string:w=>{var B=0;return w!=null&&w!==0&&(B=$e(w)),B},array:w=>{var B=X(w.length);return Be(w,B),B}};function p(w){return t===\"string\"?ze(w):t===\"boolean\"?!!w:w}var h=Y(e),P=[],N=0;if(u)for(var M=0;M<u.length;M++){var se=E[n[M]];se?(N===0&&(N=Oe()),P[M]=se(u[M])):P[M]=u[M]}var W=h(...P);function Xe(w){return N!==0&&De(N),p(w)}return W=Xe(W),W},qe=(e,t,n,u)=>{var v=!n||n.every(p=>p===\"number\"||p===\"boolean\"),E=t!==\"string\";return E&&v&&!u?Y(e):(...p)=>ee(e,t,n,p,u)},D=new Uint8Array(123),T=25;T>=0;--T)D[48+T]=52+T,D[65+T]=T,D[97+T]=26+T;if(D[43]=62,D[47]=63,r.noExitRuntime&&(Ce=r.noExitRuntime),r.print&&(m=r.print),r.printErr&&(y=r.printErr),r.wasmBinary&&(_=r.wasmBinary),r.arguments&&(S=r.arguments),r.thisProgram&&(c=r.thisProgram),r.preInit)for(typeof r.preInit==\"function\"&&(r.preInit=[r.preInit]);r.preInit.length>0;)r.preInit.shift()();r.ccall=ee,r.cwrap=qe;var Ge,te,re,ne,Ze,Ve,ae;function Ke(e){Ge=r._repair_json=e.c,te=e.d,re=e.e,ne=e.f,Ze=ae=e.a,Ve=e.__indirect_function_table}var Le={};function Ye(){_e();function e(){r.calledRun=!0,!A&&(Se(),I?.(r),r.onRuntimeInitialized?.(),we())}r.setStatus?(r.setStatus(\"Running...\"),setTimeout(()=>{setTimeout(()=>r.setStatus(\"\"),1),e()},1)):e()}var O;return O=await ke(),Ye(),G?s=r:s=new Promise((e,t)=>{I=e,x=t}),s}var ot,it,ue=et(()=>{\"use strict\";ot={};it=st});var ce={CREDIT_CARD:/\\b(?:\\d{4}[ -]?){3}\\d{4}\\b/,EMAIL:/\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b/,API_KEY:/\\b(sk-[a-zA-Z0-9]{20,}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36})\\b/,SSN:/\\b\\d{3}-\\d{2}-\\d{4}\\b/,IPV4:/\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b/,AWS_KEY:/\\b(AKIA[0-9A-Z]{16})\\b/,JWT:/\\beyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*\\b/},rt={SSN:[\"ssn\",\"social\",\"security\",\"number\",\"id\"],CREDIT_CARD:[\"cc\",\"card\",\"visa\",\"amex\",\"mastercard\",\"payment\"],API_KEY:[\"key\",\"api\",\"secret\",\"token\"],EMAIL:[\"email\",\"contact\",\"mail\"]};function $(i,s={}){let{rules:r=Object.keys(ce),redact:a=!1,allow:o=[],mode:l=\"block\"}=s,S=i,c=[],g=!0,R=o.map(f=>typeof f==\"string\"?new RegExp(f):f);for(let f of r){let m=ce[f];if(!m)continue;let y=new RegExp(m.source,\"g\"),_;for(;(_=y.exec(i))!==null;){let A=_[0],d=_.index;if(R.some(C=>C.test(A)))continue;let I=Math.max(0,d-25),x=i.slice(I,d).toLowerCase(),j=0,k=rt[f]||[];k.length>0&&k.some(C=>x.includes(C))&&(j=1),c.push({type:f,match:A,context:j>0?\"supported\":\"neutral\"}),g=!1}}if(!g&&(a||l===\"block\")){let f=[...new Set(c.map(m=>m.match))];for(let m of f){let y=c.find(A=>A.match===m)?.type||\"PII\",_=m.replace(/[.*+?^${}()|[\\]\\\\]/g,\"\\\\$&\");S=S.replace(new RegExp(_,\"g\"),`[${y}_REDACTED]`)}}return{hasPII:!g,status:g?\"safe\":l===\"warn\"?\"warning\":\"blocked\",redactedText:S,findings:c}}var nt=[{pattern:/ignore previous instructions/i,score:.9,name:\"IGNORE_PREVIOUS\"},{pattern:/system override/i,score:.9,name:\"SYSTEM_OVERRIDE\"},{pattern:/\\bDAN\\b/i,score:.6,name:\"DAN_MODE\"},{pattern:/dev mode/i,score:.7,name:\"DEV_MODE\"},{pattern:/act as a/i,score:.3,name:\"ACT_AS\"},{pattern:/you are unrestricted/i,score:.95,name:\"UNRESTRICTED\"},{pattern:/disable safety procedures/i,score:1,name:\"DISABLE_SAFETY\"}];function H(i){let s=0,r=!1,a=\"\";for(let o of nt)o.pattern.test(i)&&o.score>s&&(s=o.score,r=!0,a=`Detected pattern: ${o.name}`);return{score:s,isDetected:r,reason:r?a:void 0}}function at(i){if(!i)return 0;let s={},r=i.length;for(let o=0;o<r;o++){let l=i[o];s[l]=(s[l]||0)+1}let a=0;for(let o in s){let l=s[o]/r;a-=l*Math.log2(l)}return a}function J(i,s=5.2){let r=i.split(/\\s+/),a=[];for(let o of r){if(o.length<8)continue;let l=at(o);l>s&&a.push({score:l,isHighEntropy:!0,text:o})}return a}function z(i){if(!i)return\"\";let s=i.trim();return s=s.replace(/^```[a-zA-Z]*\\s*/,\"\"),s=s.replace(/\\s*```$/,\"\"),s}function U(i,s={}){if(!i)return\"\";let{last:r=!0}=s,a=i;a=a.replace(/<think>[\\s\\S]*?<\\/think>/gi,\"\"),a=a.replace(/<think>[\\s\\S]*$/gi,\"\"),a=a.replace(/<\\/th$/gi,\"\");let o=/```(?:json|json5|javascript|js)?\\s*([\\s\\S]*?)(?:```|$)/gi,l=[],S;for(;(S=o.exec(a))!==null;){let A=S[1].trim();A&&(A.startsWith(\"{\")||A.startsWith(\"[\"))&&l.push(A)}if(l.length>0)return r?l[l.length-1]:l[0];let c=[],g=0,R=-1,b=!1,f=!1;for(let A=0;A<a.length;A++){let d=a[A];if(f){f=!1;continue}if(d===\"\\\\\"&&b){f=!0;continue}if(d==='\"'&&!f){b=!b;continue}b||(d===\"{\"||d===\"[\"?(g===0&&(R=A),g++):(d===\"}\"||d===\"]\")&&(g--,g===0&&R!==-1&&(c.push(a.slice(R,A+1)),R=-1)))}if(R!==-1&&g>0&&c.push(a.slice(R)),c.length>0)return r?c[c.length-1]:c[0];let m=a.indexOf(\"{\"),y=a.indexOf(\"[\");if(m===-1&&y===-1)return a.trim();let _=m===-1?y:y===-1?m:Math.min(m,y);return a.slice(_).trim()}function le(i,s={}){let{extract:r=!1}=s,a=r?U(i):z(i);if(!a||!a.trim())return{fixed:\"{}\",data:{},isPartial:!1,patches:[]};let o=a.trim(),l=[],S=!1,c=[],g=!1,R=!1;for(let f=0;f<o.length;f++){let m=o[f];if(R){R=!1;continue}if(m===\"\\\\\"&&g){R=!0;continue}if(m==='\"'&&!R){g=!g,g?c.push('\"'):c.length>0&&c[c.length-1]==='\"'&&c.pop();continue}g||(m===\"{\"?c.push(\"{\"):m===\"[\"?c.push(\"[\"):m===\"}\"?c.length>0&&c[c.length-1]===\"{\"&&c.pop():m===\"]\"&&c.length>0&&c[c.length-1]===\"[\"&&c.pop())}if(g&&(l.push({type:\"unclosed_string\",index:o.length}),o+='\"',S=!0,c.length>0&&c[c.length-1]==='\"'&&c.pop()),/,\\s*$/.test(o)){let f=o.match(/,\\s*$/);l.push({type:\"trailing_comma\",index:f.index}),o=o.replace(/,\\s*$/,\"\"),S=!0}for(;c.length>0;){let f=c.pop();f===\"{\"?(l.push({type:\"missing_brace\",index:o.length}),o+=\"}\",S=!0):f===\"[\"&&(l.push({type:\"missing_brace\",index:o.length}),o+=\"]\",S=!0)}let b=null;try{b=JSON.parse(o)}catch{}return{fixed:o,data:b,isPartial:S,patches:l}}var F=null,pe=null,Ae=!0,q=\"\";async function ct(){if(!F){if(!Ae)throw new Error(\"Wasm Kernel is disabled in this build.\");try{let i=await Promise.resolve().then(()=>(ue(),fe));F=await(i.default||i)(),pe=F.cwrap(\"repair_json\",\"string\",[\"string\"])}catch(i){throw console.error(\"Failed to load Wasm kernel:\",i),i}}}self.onmessage=async i=>{let{id:s,type:r,payload:a,options:o}=i.data;try{let l;switch(r){case\"SCAN_STREAM_CHUNK\":q+=typeof a==\"string\"?a:\"\";let c=q,g=$(c,o?.pii||{}),R=H(c),b=J(c);l={safe:!g.hasPII&&!R.isDetected,pii:g,injection:R,entropy:b,textLength:c.length};break;case\"RESET_STREAM\":q=\"\",l={success:!0};break;case\"SCAN_TEXT\":{let y=typeof a==\"string\"?a:a.text,_=$(y,o?.pii||{}),A=H(y),d=J(y);l={safe:!_.hasPII&&!A.isDetected,pii:_,injection:A,entropy:d}}break;case\"REPAIR_JSON\":{let y=typeof a==\"string\"?a:a?.text,_=o?.extract??a?.extract??!1,A=o?.useWasm&&Ae,d;if(A){F||await ct();let j=_?U(y):z(y);d={fixed:pe(j),data:null,isPartial:!1,patches:[]}}else d=le(y,{extract:_});let I=d.data,x=!0;if(I===null&&d.fixed!==\"null\")try{I=JSON.parse(d.fixed)}catch{x=!1}l={fixedString:d.fixed,data:I,isValid:x,isPartial:d.isPartial,patches:d.patches,mode:A?\"wasm\":\"js\"}}break;case\"EXTRACT_JSON\":let f=typeof a==\"string\"?a:a?.text,m=o?.last??a?.last??!0;l={extracted:U(f,{last:m})};break;default:throw new Error(`Unknown message type: ${r}`)}self.postMessage({id:s,success:!0,payload:l})}catch(l){self.postMessage({id:s,success:!1,error:l.message})}};})();\n";
