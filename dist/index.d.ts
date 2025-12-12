// dist/index.d.ts

import type { ZodSchema, ZodError } from 'zod';

export type PII_RULE = 'CREDIT_CARD' | 'EMAIL' | 'API_KEY' | 'SSN' | 'IPV4';

export interface ScanResult {
  safe: boolean;
  findings: PII_RULE[];
  text: string;
}

export interface RepairResult {
  fixedString: string;
  data: any;
  isValid: boolean;
}

export interface AIGuardConfig {
  rules?: PII_RULE[];
  redact?: boolean;
}

export interface AIGuardHook {
  scanInput: (text: string, options?: AIGuardConfig) => Promise<ScanResult>;
  repairJson: (raw: string) => Promise<RepairResult>;
}

export function useAIGuard(config?: AIGuardConfig): AIGuardHook;

// Schema validation types
export interface SchemaError {
  path: string;
  message: string;
  code: string;
}

export interface StreamingJsonOptions<T = any> {
  fallback?: T;
  schema?: ZodSchema<T>;
  partial?: boolean;
}

export interface StreamingJsonResult<T = any> {
  data: T;
  isValid: boolean;
  schemaErrors: SchemaError[];
  isSchemaValid: boolean;
}

/**
 * useStreamingJson - Repair broken JSON streams with optional Zod validation
 * 
 * @example
 * // Basic usage (backwards compatible)
 * const { data, isValid } = useStreamingJson(rawStream, {});
 * 
 * @example
 * // With Zod schema validation
 * const UserSchema = z.object({ name: z.string(), age: z.number() });
 * const { data, isValid, schemaErrors } = useStreamingJson(rawStream, { 
 *   schema: UserSchema,
 *   fallback: { name: '', age: 0 }
 * });
 */
export function useStreamingJson<T = any>(
  rawString: string,
  options?: StreamingJsonOptions<T> | T
): StreamingJsonResult<T>;

/**
 * useTypedStream - Type-safe streaming with Zod schema
 * 
 * @example
 * const UserSchema = z.object({ name: z.string(), age: z.number() });
 * type User = z.infer<typeof UserSchema>;
 * const { data } = useTypedStream<User>(rawStream, UserSchema);
 */
export function useTypedStream<T>(
  rawString: string,
  schema: ZodSchema<T>,
  fallback?: T
): StreamingJsonResult<T>;

export function scanText(
  text: string,
  enabledRules?: PII_RULE[],
  redact?: boolean
): ScanResult;
