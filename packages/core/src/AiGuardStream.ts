import { scanPII } from './security/PII';
import { scanInjection } from './security/InjectionScanner';
import { scanEntropy } from './security/EntropyScanner';
import { PIIOption } from './types';

export interface AiGuardStreamOptions {
    pii?: PIIOption;
    blockOnInjection?: boolean;
    onPIIDetected?: (result: any) => void;
    onInjectionDetected?: (result: any) => void;
    onEntropyDetected?: (result: any) => void;
}

/**
 * AiGuardStream
 * A TransformStream that scans and sanitizes chunks of text in real-time.
 * Usage: fetch(...).then(r => r.body.pipeThrough(new AiGuardStream(...)))
 */
export class AiGuardStream extends TransformStream {
    constructor(options: AiGuardStreamOptions = {}) {
        const textDecoder = new TextDecoder();
        const textEncoder = new TextEncoder();

        super({
            transform(chunk, controller) {
                // Decode chunk
                let text = typeof chunk === 'string' ? chunk : textDecoder.decode(chunk, { stream: true });

                // 1. Injection Check
                const injection = scanInjection(text);
                if (injection.isDetected) {
                    if (options.onInjectionDetected) options.onInjectionDetected(injection);

                    if (options.blockOnInjection) {
                        controller.error(new Error(`Security Block: ${injection.reason}`));
                        return;
                    }
                }

                // 2. Entropy Check
                const entropy = scanEntropy(text);
                if (entropy.length > 0) {
                    if (options.onEntropyDetected) options.onEntropyDetected(entropy);
                }

                // 3. PII Redaction
                const piiResult = scanPII(text, options.pii);
                if (piiResult.hasPII) {
                    if (options.onPIIDetected) options.onPIIDetected(piiResult);
                    // Enqueue redacted text
                    controller.enqueue(textEncoder.encode(piiResult.redactedText));
                } else {
                    // Enqueue original
                    controller.enqueue(textEncoder.encode(text));
                }
            }
        });
    }
}
