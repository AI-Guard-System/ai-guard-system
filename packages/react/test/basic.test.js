import { describe, it, expect } from 'vitest';
import { useStreamingJson } from '../src/index.js';

describe('useStreamingJson', () => {
    it('should be a function', () => {
        expect(typeof useStreamingJson).toBe('function');
    });
});
