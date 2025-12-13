import { describe, it, expect } from 'vitest';
import { z } from 'zod';
import { SchemaEngine } from '../src/schema/SchemaEngine.js';

describe('SchemaEngine Security Features', () => {

    const UserSchema = z.object({
        id: z.string(),
        role: z.enum(['user', 'admin']),
        profile: z.object({
            name: z.string(),
            age: z.number().optional()
        })
    });

    it('Strictly Strips Hallucinations (Unknown Keys)', () => {
        const engine = new SchemaEngine(UserSchema);

        // Simulate LLM hallucinating fields or malicious injection
        const dirtyData = {
            id: "123",
            role: "user",
            debug_access: true,    // Hallucination
            isAdmin: true,         // Injection attempt
            profile: {
                name: "John",
                hidden_field: "secret" // Recursion check
            }
        };

        const { data } = engine.validate(dirtyData);

        // Ensure valid data remains
        expect(data.id).toBe("123");
        expect(data.role).toBe("user");
        expect(data.profile.name).toBe("John");

        // Ensure hallucinations are GONE
        expect(data).not.toHaveProperty('debug_access');
        expect(data).not.toHaveProperty('isAdmin');
        expect(data.profile).not.toHaveProperty('hidden_field');
    });

    it('Validates Deeply Partial Data (Incremental Streaming)', () => {
        const engine = new SchemaEngine(UserSchema);

        // Simulate stream at 50%: 'role' is missing, 'age' is missing
        const partialStream = {
            id: "123",
            profile: {
                name: "J"
            }
        };

        const { isValid, errors } = engine.validate(partialStream);

        // Should be valid because of Deep Partial logic
        expect(isValid).toBe(true);
        expect(errors).toHaveLength(0);

        // But Strict Parse (if we were to check completion) would fail
        const strictCheck = UserSchema.safeParse(partialStream);
        expect(strictCheck.success).toBe(false);
    });

    it('Generates Zero-Latency Skeleton (Stub)', () => {
        const engine = new SchemaEngine(UserSchema);
        const skeleton = engine.generateSkeleton();

        // Verify specific stub behavior
        expect(skeleton).toEqual({
            id: "",
            role: null, // Enums default to null implementation
            profile: {
                name: "",
                age: 0 // Optional number usually unwraps to number -> 0
            }
        });
    });
});
