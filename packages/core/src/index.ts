// Security Modules
export * from './security/EntropyScanner';
export * from './security/InjectionScanner';
export * from './security/PII';
export * from './AiGuardStream';
export * from './types';

// Legacy/Core exports
// @ts-ignore
export { repairJSON, extractJSON, stripMarkdown } from './core/repair.js';
// @ts-ignore
export { scanText } from './core/scanner.js';
// @ts-ignore
export { registerProfile, getProfile } from './core/registry.js';
// @ts-ignore
export { SchemaEngine } from './schema/SchemaEngine.js';
