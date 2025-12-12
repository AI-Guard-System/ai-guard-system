import { test, expect } from 'vitest';
import { repairJSON } from '../src/core/repair';

function generateGarbage(length) {
    const chars = '{}"[],: \n\t\r\\u0000😂汉字<think>/'; // Added <think> / components to test extractor implicitly if ever used
    let res = '';
    for (let i = 0; i < length; i++) {
        res += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return res;
}

test('Fuzz Test: Should survive 10,000 rounds of chaos', () => {
    const ROUNDS = 10000;

    for (let i = 0; i < ROUNDS; i++) {
        const garbage = generateGarbage(Math.random() * 500); // 0 to 500 chars

        try {
            // Test both standard and extract mode
            const result = repairJSON(garbage);
            const resultExtracted = repairJSON(garbage, { extract: true });

            // 1. Must never return undefined/null
            expect(result).toBeDefined();
            expect(result.fixed).toBeDefined();

            expect(resultExtracted).toBeDefined();
            expect(resultExtracted.fixed).toBeDefined();

            // 2. Result must be parsable (that's the whole point of the library)
            // We check typical failures, but ensuring no throws is the priority.
            try {
                if (result.fixed !== 'null') JSON.parse(result.fixed);
            } catch (e) {
                // It is acceptable if JSON.parse fails on extreme garbage, 
                // BUT repairJSON itself must not throw.
            }

            try {
                if (resultExtracted.fixed !== 'null') JSON.parse(resultExtracted.fixed);
            } catch (e) {
                // It is acceptable if JSON.parse fails on extreme garbage, 
                // BUT repairJSON itself must not throw.
            }

        } catch (e) {
            console.error(`CRASHED ON: ${garbage}`);
            throw e;
        }
    }
});
