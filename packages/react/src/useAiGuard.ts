import { useRef, useCallback } from 'react';
import {
    scanPII,
    scanInjection,
    scanEntropy,
    WORKER_CODE_PURE,
    repairJSON,
    extractJSON
} from '@ai-guard/core';

// --- TYPES ---
interface AiGuardConfig {
    pii?: any;
    blockOnInjection?: boolean;
}

// --- GLOBAL SCOPE ---
let sharedWorker: Worker | null = null;
let workerScriptUrl: string | null = null;
let fallbackMode = false;
const pendingRequests = new Map<string, { resolve: Function, reject: Function, timeout: any }>();

// --- FALLBACK ---
async function runMainThread(type: string, payload: any, options: any) {
    if (type === 'SCAN_TEXT' || type === 'SCAN_STREAM_CHUNK') {
        const text = typeof payload === 'string' ? payload : payload.text;

        // In fallback mode, "Delta" implies we just scan the chunk or we ideally should maintain state?
        // Main thread fallback usually happens if Worker fails. 
        // We can just scan the text provided. 
        // Use the new Core modules.
        const pii = scanPII(text, options?.pii || {});
        const injection = scanInjection(text);
        const entropy = scanEntropy(text);

        return {
            safe: !pii.hasPII && !injection.isDetected,
            pii,
            injection,
            entropy
        };
    }

    if (type === 'REPAIR_JSON') {
        const repair_input = typeof payload === 'string' ? payload : payload?.text;
        const repair_extract = options?.extract ?? payload?.extract ?? false;
        // @ts-ignore - repairJSON might be JS or untyped
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
        // @ts-ignore
        const extracted = extractJSON(extract_input, { last: extract_last });
        return { extracted };
    }

    throw new Error(`Unknown message type: ${type}`);
}

function getWorker() {
    if (fallbackMode) return null;
    if (sharedWorker) return sharedWorker;
    if (typeof window === 'undefined') return null;

    if (!workerScriptUrl && WORKER_CODE_PURE) {
        try {
            const blob = new Blob([WORKER_CODE_PURE], { type: 'application/javascript' });
            workerScriptUrl = URL.createObjectURL(blob);
        } catch (e) {
            console.warn("react-ai-guard: Blob creation failed. Fallback.");
            fallbackMode = true;
            return null;
        }
    }

    if (!workerScriptUrl) {
        fallbackMode = true;
        return null;
    }

    try {
        // Note: We use 'classic' or 'module'? Core build output is 'iife'.
        // 'iife' works best as 'classic' worker usually, or just a script.
        sharedWorker = new Worker(workerScriptUrl);
    } catch (err) {
        fallbackMode = true;
        return null;
    }

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

    return sharedWorker;
}

// --- HOOK ---
export function useAiGuard(config: AiGuardConfig = {}) {
    const lastStreamText = useRef<string>("");

    const post = useCallback((type: string, payload: any, options: any = {}) => {
        if (fallbackMode) return runMainThread(type, payload, options);

        const worker = getWorker();
        if (!worker) return runMainThread(type, payload, options);

        const id = crypto.randomUUID();
        return new Promise((resolve, reject) => {
            const timeoutId = setTimeout(() => {
                pendingRequests.delete(id);
                reject(new Error("Worker timeout"));
            }, 30000);

            pendingRequests.set(id, { resolve, reject, timeout: timeoutId });
            worker.postMessage({ id, type, payload, options });
        });
    }, []);

    // 1. Standard one-shot
    const scanText = useCallback((text: string, options: any = {}) => {
        return post('SCAN_TEXT', text, { ...config, ...options });
    }, [post, config]);

    // 2. Stream Delta Protocol
    const scanStream = useCallback((text: string, options: any = {}) => {
        // Check if new text extends old text
        const previous = lastStreamText.current;

        // Simple heuristic: if text starts with previous, it's an append.
        // Else it's a new stream or random update -> Reset.
        if (text.startsWith(previous) && text.length >= previous.length) {
            const delta = text.slice(previous.length);
            lastStreamText.current = text;
            if (delta.length === 0) return Promise.resolve({ safe: true }); // No change

            return post('SCAN_STREAM_CHUNK', delta, { ...config, ...options });
        } else {
            // Reset
            lastStreamText.current = text;
            // We can send a RESET signal then a CHUNK, or just assume the worker handles this?
            // Our worker doesn't auto-reset. We should explicitly reset.
            // Or we can just send SCAN_TEXT (stateless) if we detect a mismatch?
            // But user wants "Maintain state inside Worker".
            // So we MUST clear the worker state first.

            // Optimization: Fire and forget reset? No, we need order.
            // We'll chaining.
            return post('RESET_STREAM', null).then(() => {
                return post('SCAN_STREAM_CHUNK', text, { ...config, ...options });
            });
        }
    }, [post, config]);

    const repairJson = useCallback((raw: string, options: any = {}) => {
        return post('REPAIR_JSON', raw, { extract: options.extract || false });
    }, [post]);

    const extractJson = useCallback((raw: string, options: any = {}) => {
        return post('EXTRACT_JSON', raw, { last: options.last ?? true });
    }, [post]);

    return {
        scanText,
        scanStream,
        repairJson,
        extractJson
    };
}
