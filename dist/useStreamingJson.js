import { useState, useEffect, useRef } from 'react';
import { useAIGuard } from './useAIGuard.js';

/**
 * useStreamingJson with Zod Schema Validation
 * 
 * Takes a raw, broken string from an LLM stream, repairs it,
 * and optionally validates against a Zod schema in real-time.
 * 
 * @param {string} rawString - The input stream (e.g. from Vercel AI SDK)
 * @param {object} options - Configuration options (or fallback object for backwards compat)
 * @param {any} options.fallback - Initial state while loading (default: {})
 * @param {import('zod').ZodSchema} options.schema - Zod schema for validation (optional)
 * @param {boolean} options.partial - Allow partial matches during streaming (default: true)
 */
export function useStreamingJson(rawString, options = {}) {
  // Backwards compatibility: if options is a plain object without our keys, treat as fallback
  const isOptionsObject = options && (
    'fallback' in options || 'schema' in options || 'partial' in options
  );
  
  const { 
    fallback = isOptionsObject ? {} : options, 
    schema = null, 
    partial = true 
  } = isOptionsObject ? options : {};
  
  const [data, setData] = useState(fallback);
  const [isValid, setIsValid] = useState(false);
  const [schemaErrors, setSchemaErrors] = useState([]);
  
  const { repairJson } = useAIGuard();
  
  // Track the latest request to discard stale responses
  const requestIdRef = useRef(0);

  useEffect(() => {
    if (!rawString) return;

    // Increment request ID - any response with older ID is stale
    const currentRequestId = ++requestIdRef.current;

    const process = async () => {
      try {
        const result = await repairJson(rawString);
        
        // Discard stale response (newer request already in flight)
        if (currentRequestId !== requestIdRef.current) return;
        
        if (result && result.data) {
          let validatedData = result.data;
          let errors = [];
          let schemaValid = true;
          
          // Duck-type check: does schema have safeParse? Then it's Zod-like.
          // Runs on every chunk — this is intentional for real-time validation UX.
          const shouldValidateSchema = schema && 
            typeof schema.safeParse === 'function' && 
            result.isValid;
          
          if (shouldValidateSchema) {
            try {
              const parseResult = schema.safeParse(result.data);
              
              if (parseResult.success) {
                validatedData = parseResult.data;
                schemaValid = true;
                errors = [];
              } else {
                errors = parseResult.error.errors.map(e => ({
                  path: e.path.join('.'),
                  message: e.message,
                  code: e.code
                }));
                
                if (partial) {
                  // Partial mode: update data but track errors (for streaming)
                  validatedData = result.data;
                  schemaValid = false;
                } else {
                  // Strict mode: reject invalid data, keep previous
                  setSchemaErrors(errors);
                  setIsValid(false);
                  return;
                }
              }
            } catch (schemaError) {
              console.warn('[react-ai-guard] Schema validation error:', schemaError);
              errors = [{ path: '', message: schemaError.message, code: 'schema_error' }];
              schemaValid = false;
            }
          } else if (schema && !result.isValid) {
            // JSON still streaming, skip schema validation but mark as incomplete
            schemaValid = false;
          }
          
          setData(validatedData);
          setIsValid(result.isValid && schemaValid);
          setSchemaErrors(errors);
        }
      } catch (err) {
        // Only log if this is still the current request
        if (currentRequestId === requestIdRef.current) {
          console.warn("Repair failed", err);
        }
      }
    };

    process();
  }, [rawString, repairJson, schema, partial]);

  return { 
    data, 
    isValid,
    schemaErrors,
    isSchemaValid: schemaErrors.length === 0
  };
}

/**
 * useTypedStream - Convenience wrapper with better TypeScript ergonomics
 * 
 * Usage with Zod:
 * ```ts
 * const UserSchema = z.object({ name: z.string(), age: z.number() });
 * type User = z.infer<typeof UserSchema>;
 * const { data, isValid } = useTypedStream<User>(rawStream, UserSchema);
 * ```
 */
export function useTypedStream(rawString, schema, fallback = {}) {
  return useStreamingJson(rawString, { schema, fallback, partial: true });
}
