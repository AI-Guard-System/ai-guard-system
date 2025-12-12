import { describe, it, expect } from 'vitest';
import { repairJSON, stripMarkdown } from '../repair.js';

const parseSafe = (text) => JSON.parse(repairJSON(text));

describe('repairJSON', () => {
  it('returns valid JSON when input is already valid', () => {
    const input = '{"a":1,"b":2}';
    const repaired = repairJSON(input);
    expect(repaired).toBe(input);
    expect(JSON.parse(repaired)).toEqual({ a: 1, b: 2 });
  });

  it('returns empty object for blank input', () => {
    expect(repairJSON('   ')).toBe('{}');
  });

  it('closes open braces and quotes for streaming partials', () => {
    const input = '{"user": {"name": "Ali"';
    const parsed = parseSafe(input);
    expect(parsed).toEqual({ user: { name: 'Ali' } });
  });

  it('repairs trailing commas', () => {
    const input = '{"a":1, "b":2,}';
    const parsed = parseSafe(input);
    expect(parsed).toEqual({ a: 1, b: 2 });
  });

  it('handles escaped characters inside strings', () => {
    const input = '{"msg":"hello\\n"';
    const parsed = parseSafe(input);
    expect(parsed).toEqual({ msg: 'hello\n' });
  });

  it('strips markdown code fences before repairing', () => {
    const fenced = '```json\n{"a":1}\n```';
    const stripped = stripMarkdown(fenced);
    expect(stripped).toBe('{"a":1}');

    const parsed = parseSafe(fenced);
    expect(parsed).toEqual({ a: 1 });
  });
});
