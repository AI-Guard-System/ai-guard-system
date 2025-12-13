import { useState, useEffect, useMemo, useRef } from 'react';
import { useAIGuard } from './useAIGuard.js';
import { SchemaEngine } from '@ai-guard/core';

/**
 * useGuard
 * Sentinel-Class hook for streaming AI data.
 * v2.0 Architecture
 * 
 * Flow:
 * Stream -> RepairStack -> SchemaEngine(DeepPartial + Strip) -> React State
 */
export function useGuard(stream, options = {}) {
    const {
        schema,
        defaultValues = {},
        onUnknownKey = 'strip', // Default security policy
        onComplete,
        onError
    } = options;

    // 1. Initialize Schema Engine (Memoized)
    const engine = useMemo(() => {
        if (!schema) return null;
        return new SchemaEngine(schema);
    }, [schema]);

    // 2. Generate Initial State (Zero-Latency Skeleton)
    const initialState = useMemo(() => {
        if (Object.keys(defaultValues).length > 0) return defaultValues;
        if (engine) return engine.generateSkeleton();
        return {};
    }, [engine, defaultValues]);

    const [data, setData] = useState(initialState);

    // Metrics & Status
    const [metrics, setMetrics] = useState({
        isValid: false,      // Passes strict schema
        isPartial: true,     // Is JSON stream complete?
        schemaErrors: [],    // Zod errors
        hallucinations: 0    // Count of stripped keys (future)
    });

    const { repairJson } = useAIGuard();
    const completedRef = useRef(false);
    const onCompleteRef = useRef(onComplete);
    const onErrorRef = useRef(onError);

    useEffect(() => {
        onCompleteRef.current = onComplete;
        onErrorRef.current = onError;
    }, [onComplete, onError]);

    useEffect(() => {
        if (!stream) return;

        let mounted = true;

        async function processStream() {
            try {
                // Step 1: Repair Broken JSON
                const result = await repairJson(stream);
                if (!mounted) return;

                let finalData = result.data;
                let validationErrors = [];
                let isValid = false;

                // Step 2: Schema Enforcement (Validation + Sanitation)
                if (engine && finalData) {
                    // A. Incremental Validation (Deep Partial)
                    // Also handle 'stripping' implicitly via Zod parse
                    const validation = engine.validate(finalData);

                    finalData = validation.data;
                    validationErrors = validation.errors;

                    // B. Strict Check (Is it DONE?)
                    // We check the full schema execution to see if we are 'valid'
                    const strictResult = engine.schema.safeParse(finalData);
                    isValid = strictResult.success;
                } else {
                    // Fallback if no schema (or repair failed partial)
                    isValid = result.isValid;
                }

                setData(finalData);

                setMetrics({
                    isValid,
                    isPartial: result.isPartial,
                    schemaErrors: validationErrors,
                    hallucinations: 0 // Placeholder for now
                });

                // Step 3: Lifecycle Hooks
                if (isValid && !result.isPartial && !completedRef.current) {
                    completedRef.current = true;
                    if (onCompleteRef.current) {
                        onCompleteRef.current(finalData);
                    }
                }
            } catch (err) {
                if (onErrorRef.current) onErrorRef.current(err);
            }
        }

        processStream();

        return () => { mounted = false; };
    }, [stream, engine, repairJson]);

    return {
        data,
        metrics
    };
}
