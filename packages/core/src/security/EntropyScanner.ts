import { EntropyResult } from '../types';

/**
 * Calculates the Shannon Entropy of a string.
 * Higher entropy usually indicates random data (keys, secrets, encrypted text).
 * Normal English text usually has entropy between 3.5 and 5.0.
 * Random 32-char hex strings -> ~4.0-4.5, but dense base64 -> ~5.5-6.0
 */
export function calculateShannonEntropy(str: string): number {
    if (!str) return 0;

    const charMap: Record<string, number> = {};
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

/**
 * Scans a string for high-entropy segments that might look like secrets.
 * We scan tokens (words) to avoid flagging checking entire sentences.
 */
export function scanEntropy(text: string, threshold: number = 5.2): EntropyResult[] {
    const tokens = text.split(/\s+/);
    const results: EntropyResult[] = [];

    for (const token of tokens) {
        // Ignore short tokens (less than 8 chars usually not a secret key)
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
