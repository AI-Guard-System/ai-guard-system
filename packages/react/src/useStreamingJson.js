import { useState, useEffect, useRef, useCallback } from 'react';
import { useAIGuard } from './useAIGuard.js';

/**
 * Creates a stub object from a Zod schema for optimistic UI.
 * Pre-fills required fields with empty defaults to prevent layout shift.
 */
function createSchemaStub(schema) {
  if (!schema || typeof schema.shape !== 'object') return {};

  const stub = {};
  try {
    const shape = schema.shape;
    for (const [key, field] of Object.entries(shape)) {
      // Check Zod field types via _def
      const def = field?._def;
      if (!def) continue;

      const typeName = def.typeName;
      switch (typeName) {
        case 'ZodString': stub[key] = ''; break;
        case 'ZodNumber': stub[key] = 0; break;
        case 'ZodBoolean': stub[key] = false; break;
        case 'ZodArray': stub[key] = []; break;
        case 'ZodObject': stub[key] = createSchemaStub(field); break;
        case 'ZodOptional': break; // Skip optional fields
        case 'ZodNullable': stub[key] = null; break;
        default: stub[key] = null;
      }
    }
  } catch {
    // Schema introspection failed, return empty object
  }
  return stub;
}

/**
 * useStreamingJson - v1.2.0
 * 
 * Features:
 * - JSON repair for streaming LLM output
 * - Extract mode for reasoning models (DeepSeek, o1)
 * - Zod schema validation with optimistic UI stubbing
 * - Event callbacks (onComplete, onError, onValidationFail)
 * - SSR-safe hydration
 * 
 * @param {string} rawString - The input stream
 * @param {object} options - Configuration options
 */
export function useStreamingJson(rawString, options = {}) {
  // Backwards compatibility
  const isOptionsObject = options && (
    'fallback' in options || 'schema' in options || 'partial' in options ||
    'extract' in options || 'onComplete' in options || 'onError' in options
  );

  const {
    fallback = isOptionsObject ? undefined : options,
    schema = null,
    partial = true,
    extract = false,           // v1.2.0: Extract JSON from reasoning traces
    stubFromSchema = false,    // v1.2.0: Pre-fill skeleton from schema
    onComplete = null,         // v1.2.0: Callback when stream completes
    onError = null,            // v1.2.0: Callback on repair error
    onValidationFail = null    // v1.2.0: Callback on schema validation failure
  } = isOptionsObject ? options : {};

  // Compute initial state (SSR-safe)
  const initialData = fallback !== undefined
    ? fallback
    : (stubFromSchema && schema ? createSchemaStub(schema) : {});

  const [data, setData] = useState(initialData);
  const [isValid, setIsValid] = useState(false);
  const [schemaErrors, setSchemaErrors] = useState([]);
  const [isComplete, setIsComplete] = useState(false);

  // SSR guard: track if we're on client
  const [isClient, setIsClient] = useState(false);
  useEffect(() => { setIsClient(true); }, []);

  const { repairJson } = useAIGuard();

  // Track latest request to discard stale responses
  const requestIdRef = useRef(0);
  const prevDataRef = useRef(null);
  const completedRef = useRef(false);

  // Stable callback refs
  const onCompleteRef = useRef(onComplete);
  const onErrorRef = useRef(onError);
  const onValidationFailRef = useRef(onValidationFail);

  useEffect(() => {
    onCompleteRef.current = onComplete;
    onErrorRef.current = onError;
    onValidationFailRef.current = onValidationFail;
  }, [onComplete, onError, onValidationFail]);

  useEffect(() => {
    // SSR guard: don't process on server
    if (!isClient) return;
    if (!rawString) return;

    const currentRequestId = ++requestIdRef.current;

    const process = async () => {
      try {
        // v1.2.0: Pass extract option to worker
        const result = await repairJson(rawString, { extract });

        if (currentRequestId !== requestIdRef.current) return;

        if (result && result.data) {
          let validatedData = result.data;
          let errors = [];
          let schemaValid = true;

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

                // v1.2.0: Fire validation fail callback
                if (onValidationFailRef.current) {
                  onValidationFailRef.current(errors);
                }

                if (partial) {
                  validatedData = result.data;
                  schemaValid = false;
                } else {
                  setSchemaErrors(errors);
                  setIsValid(false);
                  return;
                }
              }
            } catch (schemaError) {
              errors = [{ path: '', message: schemaError.message, code: 'schema_error' }];
              schemaValid = false;
            }
          } else if (schema && !result.isValid) {
            schemaValid = false;
          }

          setData(validatedData);
          setIsValid(result.isValid && schemaValid);
          setSchemaErrors(errors);

          // v1.2.0: Detect completion (valid JSON + schema passes)
          const nowComplete = result.isValid && schemaValid;
          if (nowComplete && !completedRef.current) {
            completedRef.current = true;
            setIsComplete(true);
            if (onCompleteRef.current) {
              onCompleteRef.current(validatedData);
            }
          }

          prevDataRef.current = validatedData;
        }
      } catch (err) {
        if (currentRequestId === requestIdRef.current) {
          // v1.2.0: Fire error callback
          if (onErrorRef.current) {
            onErrorRef.current(err);
          }
        }
      }
    };

    process();
  }, [rawString, repairJson, schema, partial, extract, isClient]);

  // Reset completion flag when rawString changes significantly
  useEffect(() => {
    if (rawString && completedRef.current) {
      // Check if this looks like a new stream (shorter or very different)
      const prev = prevDataRef.current;
      if (!prev || JSON.stringify(prev).length > rawString.length + 50) {
        completedRef.current = false;
        setIsComplete(false);
      }
    }
  }, [rawString]);

  return {
    data,
    isValid,
    schemaErrors,
    isSchemaValid: schemaErrors.length === 0,
    isComplete  // v1.2.0: True when stream finished + validated
  };
}

/**
 * useTypedStream - Convenience wrapper with TypeScript ergonomics
 */
export function useTypedStream(rawString, schema, fallback = {}) {
  return useStreamingJson(rawString, { schema, fallback, partial: true });
}

/**
 * useVercelStream - Adapter for Vercel AI SDK useChat
 * 
 * Usage:
 * ```js
 * const { messages } = useChat();
 * const { object, isStreaming } = useVercelStream(messages, { schema: MySchema });
 * ```
 */
export function useVercelStream(messages, options = {}) {
  const { schema, fallback, extract = true, ...rest } = options;

  // Get the last assistant message content
  const lastAssistantMessage = messages
    ?.filter(m => m.role === 'assistant')
    ?.pop();

  const content = lastAssistantMessage?.content || '';
  const isStreaming = lastAssistantMessage && !lastAssistantMessage.finished;

  const result = useStreamingJson(content, {
    schema,
    fallback,
    extract, // Default to extract mode for Vercel streams
    ...rest
  });

  return {
    ...result,
    object: result.data,  // Alias for Vercel SDK naming convention
    isStreaming: !result.isComplete
  };
}
