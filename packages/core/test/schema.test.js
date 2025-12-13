import { describe, it, expect } from 'vitest';
import { SchemaEngine } from '../src/schema/SchemaEngine';
import { z } from 'zod';

describe('SchemaEngine: The Hallucination Filter', () => {

    it('should strip keys in nested objects', () => {
        const schema = z.object({
            user: z.object({
                profile: z.object({
                    bio: z.string()
                })
            })
        });

        const maliciousInput = {
            user: {
                profile: {
                    bio: "Just a user",
                    isAdmin: true // <--- KILL THIS
                },
                debugMode: true // <--- KILL THIS
            }
        };

        const engine = new SchemaEngine(schema);
        const validation = engine.validate(maliciousInput);
        const result = validation.data;

        expect(result.user.profile.isAdmin).toBeUndefined();
        expect(result.user.debugMode).toBeUndefined();
        expect(result.user.profile.bio).toBe("Just a user");
    });

    it('should handle Arrays of Objects correctly', () => {
        const schema = z.object({
            tags: z.array(z.object({ label: z.string() }))
        });

        const input = {
            tags: [
                { label: "Valid" },
                { label: "Also Valid", hidden_metadata: "secret" } // <--- STRIP METADATA
            ]
        };

        const engine = new SchemaEngine(schema);
        const validation = engine.validate(input);
        const result = validation.data;

        expect(result.tags[1].hidden_metadata).toBeUndefined();
        expect(result.tags[1].label).toBe("Also Valid");
    });

    it('should not crash on partial/incomplete streams', () => {
        const schema = z.object({ id: z.number() });

        // Simulating a stream that stopped mid-key
        const partialInput = { id: 123, unk: "no" }; // 'unk' is 'unknown' truncated

        const engine = new SchemaEngine(schema);
        const validation = engine.validate(partialInput);
        const result = validation.data;

        expect(result.id).toBe(123);
        expect(result.unk).toBeUndefined();
    });
});
