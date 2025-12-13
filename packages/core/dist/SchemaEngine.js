import { z } from 'zod';

/**
 * SchemaEngine
 * Handles advanced Zod operations for streaming data:
 * 1. Deep Partial Validation (for incomplete streams)
 * 2. Hallucination Stripping (Security)
 * 3. Skeleton Generation (Zero-latency UI)
 */
export class SchemaEngine {
    constructor(schema) {
        if (!schema) throw new Error("SchemaEngine requires a Zod schema");
        this.schema = schema;
        // Cache the partial schema for performance
        this.partialSchema = this._createDeepPartial(schema);
    }

    /**
     * Creates a 'relaxed' schema that allows missing fields/partial data
     * but enforces the structure that IS present.
     */
    _createDeepPartial(schema) {
        if (typeof schema.deepPartial === 'function') {
            // Zod's native deepPartial handles objects/arrays recursively
            // and preserves the 'strip' behavior for unknown keys.
            return schema.deepPartial();
        }
        // Fallback for non-nested schemas or older Zod versions
        if (typeof schema.partial === 'function') {
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
            // safeParse with the partial schema will:
            // 1. Allow missing keys (due to deepPartial)
            // 2. Strip unknown keys (default Zod behavior)
            // 3. Validate types of present keys
            const result = this.partialSchema.safeParse(data);

            if (result.success) {
                return {
                    data: result.data,
                    isValid: true,
                    errors: []
                };
            } else {
                return {
                    data: data, // Return raw data if validation fails completely
                    isValid: false,
                    errors: result.error.errors
                };
            }
        } catch (err) {
            return {
                data: data,
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

        // Unwrap optional/nullable/default
        if (schema instanceof z.ZodOptional || schema instanceof z.ZodNullable) {
            // For stubs, we might want null or the underlying type's stub?
            // Usually matching the structure is better, even if null is allowed.
            return this._generateStub(schema.unwrap?.() || schema._def.innerType);
        }
        if (schema instanceof z.ZodDefault) {
            return this._generateStub(schema.removeDefault());
        }
        if (schema instanceof z.ZodEffects) {
            return this._generateStub(schema._def.schema);
        }

        // Handle primitives
        if (schema instanceof z.ZodString) return "";
        if (schema instanceof z.ZodNumber) return 0;
        if (schema instanceof z.ZodBoolean) return false;
        if (schema instanceof z.ZodArray) return [];

        // Handle Objects
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
}
