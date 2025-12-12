import { describe, it, expect } from 'vitest';
import { repairJSON, extractJSON } from '../src/core/repair.js';
import { scanText } from '../src/core/scanner.js';

describe('extractJSON', () => {
  it('extracts JSON from <think> reasoning traces', () => {
    const input = `<think>
Let me think about this...
The user wants JSON output.
I'll format it properly.
</think>

{"name": "Alice", "age": 30}`;
    
    const result = extractJSON(input);
    expect(result).toBe('{"name": "Alice", "age": 30}');
  });

  it('extracts JSON from markdown code blocks', () => {
    const input = `Here is the data you requested:

\`\`\`json
{"items": ["apple", "banana"]}
\`\`\`

Let me know if you need anything else!`;
    
    const result = extractJSON(input);
    expect(result).toBe('{"items": ["apple", "banana"]}');
  });

  it('extracts JSON embedded in prose', () => {
    const input = 'The weather data is {"temp": 72, "unit": "F"} for today.';
    const result = extractJSON(input);
    expect(result).toBe('{"temp": 72, "unit": "F"}');
  });

  it('handles nested objects', () => {
    const input = `<think>thinking...</think>{"user": {"name": "Bob", "meta": {"id": 1}}}`;
    const result = extractJSON(input);
    const parsed = JSON.parse(result);
    expect(parsed.user.name).toBe('Bob');
    expect(parsed.user.meta.id).toBe(1);
  });

  it('returns last JSON by default', () => {
    const input = '{"first": true} some text {"second": true}';
    const result = extractJSON(input, { last: true });
    expect(JSON.parse(result).second).toBe(true);
  });
});

describe('repairJSON with extract option', () => {
  it('repairs and extracts from reasoning output', () => {
    const input = `<think>planning...</think>{"name": "Test", "incomplete": true`;
    const result = repairJSON(input, { extract: true });
    expect(result).toContain('"name"');
    // Should be parseable
    expect(() => JSON.parse(result)).not.toThrow();
  });
});

describe('scanText with allow-lists', () => {
  it('detects email by default', () => {
    const result = scanText('Contact: john@example.com', ['EMAIL']);
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].type).toBe('EMAIL');
  });

  it('skips allowed patterns', () => {
    const allowList = [/support@company\.com/];
    const result = scanText('Contact: support@company.com', ['EMAIL'], false, allowList);
    expect(result.findings.length).toBe(0);
  });

  it('skips allowed string patterns', () => {
    const allowList = ['test@example.com'];
    const result = scanText('Email: test@example.com', ['EMAIL'], false, allowList);
    expect(result.findings.length).toBe(0);
  });

  it('supports custom rules', () => {
    const customRules = [
      { name: 'TICKET_ID', pattern: /TICKET-\d{5}/g }
    ];
    const result = scanText('Issue TICKET-12345 reported', ['TICKET_ID'], false, [], customRules);
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].type).toBe('TICKET_ID');
  });

  it('redacts with allow-list respected', () => {
    const allowList = ['public@company.com'];
    const result = scanText(
      'Contact: private@company.com or public@company.com', 
      ['EMAIL'], 
      true, 
      allowList
    );
    expect(result.text).toContain('[EMAIL_REDACTED]');
    expect(result.text).toContain('public@company.com');
  });
});

describe('scanText with new patterns', () => {
  it('detects AWS keys', () => {
    const result = scanText('Key: AKIAIOSFODNN7EXAMPLE', ['AWS_KEY']);
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].type).toBe('AWS_KEY');
  });

  it('detects JWT tokens', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U';
    const result = scanText(`Token: ${jwt}`, ['JWT']);
    expect(result.findings.length).toBe(1);
    expect(result.findings[0].type).toBe('JWT');
  });
});
