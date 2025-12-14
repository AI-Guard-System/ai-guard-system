export interface EntropyResult {
    score: number;
    isHighEntropy: boolean;
    text: string; // The specific segment that triggered it
}

export interface InjectionResult {
    score: number;
    isDetected: boolean;
    reason?: string;
}

export interface PIIOption {
    rules?: string[];
    redact?: boolean;
    allow?: (string | RegExp)[];
    mode?: 'block' | 'warn' | 'silent';
}

export interface PIIFinding {
    type: string;
    match: string;
    context?: string;
}

export interface PIIResult {
    hasPII: boolean;
    status: 'safe' | 'blocked' | 'warning';
    redactedText: string;
    findings: PIIFinding[];
}

export type SecurityEventHandler = (event: SecurityEvent) => void;

export interface SecurityEvent {
    kind: 'PII_DETECTED' | 'INJECTION_DETECTED' | 'REDACTION';
    payload: any;
    timestamp: string;
}
