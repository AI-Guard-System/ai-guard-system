import { scanPII } from '../security/PII';
import { scanInjection } from '../security/InjectionScanner';
import { scanEntropy } from '../security/EntropyScanner';
// @ts-ignore
import { stripMarkdown, extractJSON, repairJSON } from '../core/repair.js';

// === WASM KERNEL STATE ===
let wasmInstance: any = null;
let repair_c: any = null;

const WASM_ENABLED = process.env.WASM_ENABLED === 'true';

// === STREAM STATE ===
let streamBuffer = "";

async function initKernel() {
    if (wasmInstance) return;
    if (!WASM_ENABLED) throw new Error("Wasm Kernel is disabled in this build.");

    try {
        // @ts-ignore
        const module = await import('../core/repair_wasm.js');
        const createRepairModule = module.default || module;
        wasmInstance = await createRepairModule();
        repair_c = wasmInstance.cwrap('repair_json', 'string', ['string']);
    } catch (e) {
        console.error("Failed to load Wasm kernel:", e);
        throw e;
    }
}

self.onmessage = async (e: MessageEvent) => {
    const { id, type, payload, options } = e.data;

    try {
        let result;

        switch (type) {
            case 'SCAN_STREAM_CHUNK':
                const chunk = typeof payload === 'string' ? payload : "";
                streamBuffer += chunk;

                // Scan the accumulated buffer
                // Note: For large streams, we might want to window this.
                // But for "Chat Bot Response", full text is usually fine (< 100kb).

                const textToScan = streamBuffer;

                const pii = scanPII(textToScan, options?.pii || {});
                const injection = scanInjection(textToScan);
                const entropy = scanEntropy(textToScan);

                result = {
                    safe: !pii.hasPII && !injection.isDetected,
                    pii,
                    injection,
                    entropy,
                    textLength: textToScan.length
                };
                break;

            case 'RESET_STREAM':
                streamBuffer = "";
                result = { success: true };
                break;

            case 'SCAN_TEXT':
                // Legacy one-shot or non-streaming
                {
                    const text = typeof payload === 'string' ? payload : payload.text;
                    const pii = scanPII(text, options?.pii || {});
                    const injection = scanInjection(text);
                    const entropy = scanEntropy(text);

                    result = {
                        safe: !pii.hasPII && !injection.isDetected,
                        pii,
                        injection,
                        entropy
                    };
                }
                break;

            case 'REPAIR_JSON':
                {
                    const repair_input = typeof payload === 'string' ? payload : payload?.text;
                    const repair_extract = options?.extract ?? payload?.extract ?? false;
                    const useWasm = options?.useWasm && WASM_ENABLED;

                    let repairResult: any;

                    if (useWasm) {
                        if (!wasmInstance) await initKernel();
                        const cleanText = repair_extract ? extractJSON(repair_input) : stripMarkdown(repair_input);
                        const fixedStr = repair_c(cleanText);
                        repairResult = {
                            fixed: fixedStr,
                            data: null,
                            isPartial: false,
                            patches: []
                        };
                    } else {
                        repairResult = repairJSON(repair_input, { extract: repair_extract });
                    }

                    // Final Validation / Parse Check
                    let parsed = repairResult.data;
                    let isValid = true;
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
                result = { extracted: extractJSON(extract_input, { last: extract_last }) };
                break;

            default:
                throw new Error(`Unknown message type: ${type}`);
        }

        self.postMessage({ id, success: true, payload: result });

    } catch (error: any) {
        self.postMessage({ id, success: false, error: error.message });
    }
};
