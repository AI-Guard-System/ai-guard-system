export interface ScanResult {
    safe: boolean;
    status: 'safe' | 'warning' | 'blocked';
    findings: Array<{ type: string; matches: string[] }>;
    text: string;
}

export interface RepairResult {
    fixed: string;
    data: any;
    isPartial: boolean;
    patches: Array<{ type: string; index: number; char?: string }>;
}

export interface AIGuardConfig {
    rules?: string[];
    redact?: boolean;
    allow?: (string | RegExp)[];
    customRules?: Array<{ name: string; pattern: RegExp }>;
}

// Registry
export interface ProfileConfig {
    extractors: Array<(text: string) => string>;
}
export function registerProfile(name: string, config: ProfileConfig): void;
export function getProfile(name: string): ProfileConfig;

// Core Utils
export function scanText(
    text: string,
    options?: { rules?: string[]; redact?: boolean; allow?: (string | RegExp)[]; customRules?: any[]; mode?: 'block' | 'warn' | 'silent' } | string[],
    legacyRedact?: boolean,
    legacyAllow?: any[],
    legacyCustom?: any[]
): ScanResult;

export function repairJSON(
    raw: string,
    options?: { extract?: boolean }
): RepairResult;

export function extractJSON(
    text: string,
    options?: { last?: boolean }
): string;

// React Hooks
export function useAIGuard(config?: AIGuardConfig): {
    scanInput: (text: string, options?: any) => Promise<ScanResult>;
    repairJson: (text: string, options?: { extract?: boolean, useWasm?: boolean }) => Promise<RepairResult & { mode: 'js' | 'wasm' }>;
    extractJson: (text: string, options?: { last?: boolean }) => Promise<{ extracted: string }>;
    loadPlugin: (config: any) => Promise<any>;
    unloadPlugin: (name: string) => Promise<any>;
    listPlugins: () => Promise<any>;
    pluginsReady: boolean;
    pluginErrors: any[];
};

export function useStreamingJson(
    stream: string,
    options?: {
        fallback?: any;
        schema?: any;
        partial?: boolean;
        extract?: boolean;
        stubFromSchema?: boolean;
        onComplete?: (data: any) => void;
        onError?: (err: any) => void;
        onValidationFail?: (err: any) => void;
    }
): {
    data: any;
    isValid: boolean;
    isSchemaValid: boolean;
    schemaErrors: any[];
    isComplete: boolean;
};

export function useVercelStream(messages: any[], options?: any): any;

export declare const WORKER_CODE_PURE: string;
export declare const WORKER_CODE_PRO: string;
