import { InjectionResult } from '../types';

const INJECTION_PATTERNS = [
    { pattern: /ignore previous instructions/i, score: 0.9, name: 'IGNORE_PREVIOUS' },
    { pattern: /system override/i, score: 0.9, name: 'SYSTEM_OVERRIDE' },
    { pattern: /\bDAN\b/i, score: 0.6, name: 'DAN_MODE' }, // Do Anything Now
    { pattern: /dev mode/i, score: 0.7, name: 'DEV_MODE' },
    { pattern: /act as a/i, score: 0.3, name: 'ACT_AS' }, // Lower score, common in legitimate prompts
    { pattern: /you are unrestricted/i, score: 0.95, name: 'UNRESTRICTED' },
    { pattern: /disable safety procedures/i, score: 1.0, name: 'DISABLE_SAFETY' }
];

/**
 * Scans text for Prompt Injection attacks.
 * Returns a risk score (0-1).
 */
export function scanInjection(text: string): InjectionResult {
    let maxScore = 0;
    let detected = false;
    let reason = '';

    for (const item of INJECTION_PATTERNS) {
        if (item.pattern.test(text)) {
            if (item.score > maxScore) {
                maxScore = item.score;
                detected = true;
                reason = `Detected pattern: ${item.name}`;
            }
        }
    }

    // Heuristic: Check for repeated overlapping commands?
    // For now, pattern matching is v1.

    return {
        score: maxScore,
        isDetected: detected,
        reason: detected ? reason : undefined
    };
}
