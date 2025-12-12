import { describe, it, expect } from 'vitest';
import { scanText } from '../scanner.js';

describe('scanText', () => {
  it('detects multiple PII types with default rules', () => {
    const text = 'Email a@b.com and card 4111-1111-1111-1111 plus ip 10.0.0.1';
    const result = scanText(text);

    expect(result.safe).toBe(false);
    const types = result.findings.map((f) => f.type).sort();
    expect(types).toEqual(['CREDIT_CARD', 'EMAIL', 'IPV4'].sort());
  });

  it('redacts when enabled', () => {
    const text = 'Key sk-abcdefghijklmnopqrstuvwxyz';
    const result = scanText(text, ['API_KEY'], true);
    expect(result.safe).toBe(false);
    expect(result.text).toContain('[API_KEY_REDACTED]');
  });

  it('honors enabled rules filter', () => {
    const text = 'card 4111-1111-1111-1111 and email a@b.com';
    const result = scanText(text, ['EMAIL']);

    expect(result.safe).toBe(false);
    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].type).toBe('EMAIL');
  });

  it('returns safe for clean text', () => {
    const result = scanText('Just a regular message.');
    expect(result.safe).toBe(true);
    expect(result.findings).toHaveLength(0);
    expect(result.text).toBe('Just a regular message.');
  });
});
