import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { defaultPrivacyConfig } from '../src/config.js';
import { ibanValid, luhnValid, redact, twNationalIdValid } from '../src/privacy/redact.js';

const config = defaultPrivacyConfig();

describe('redact', () => {
  it('removes Luhn-valid card numbers, with or without separators', () => {
    assert.equal(redact('my card is 4111111111111111', config).text, 'my card is [redacted:card]');
    assert.equal(
      redact('pay to 4111 1111 1111 1111 please', config).text,
      'pay to [redacted:card] please',
    );
  });

  it('leaves digit strings that fail the Luhn check alone', () => {
    // Order numbers and reference codes are the same shape as a card number,
    // so the checksum is what keeps this from mangling ordinary text.
    const text = 'order number 4111111111111112';
    assert.equal(redact(text, config).text, text);
  });

  it('removes checksum-valid Taiwan national IDs only', () => {
    assert.equal(redact('id A123456789 ok', config).text, 'id [redacted:twid] ok');
    const invalid = 'code A123456788 ok';
    assert.equal(redact(invalid, config).text, invalid);
  });

  it('removes emails and phone numbers', () => {
    assert.equal(redact('mail me at a.b@example.com', config).text, 'mail me at [redacted:email]');
    assert.equal(redact('call +886 912 345 678', config).text, 'call [redacted:phone]');
    assert.equal(redact('call 0912345678', config).text, 'call [redacted:phone]');
  });

  it('removes API keys, bearer tokens and JWTs', () => {
    assert.match(redact('key sk-abcdefghijklmnopqrstuvwxyz', config).text, /\[redacted:secret\]/);
    assert.match(redact('Authorization: Bearer abcdefghijklmnopqrst', config).text, /Bearer \[redacted:secret\]/);
    assert.match(
      redact('token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.abcdefghijklmnop', config).text,
      /\[redacted:secret\]/,
    );
    assert.match(redact('password = hunter2xyz', config).text, /\[redacted:secret\]/);
  });

  it('strips query strings but keeps the destination readable', () => {
    assert.equal(
      redact('see https://example.com/doc?token=abc123', config).text,
      'see https://example.com/doc?[redacted:query]',
    );
  });

  it('removes raw LINE ids pasted into message text', () => {
    assert.equal(
      redact('forward to U1234567890abcdef1234567890abcdef', config).text,
      'forward to [redacted:lineid]',
    );
  });

  it('reports which rules fired, so gaps can be explained later', () => {
    const result = redact('a@b.com and 4111111111111111', config);
    assert.deepEqual(result.applied, ['creditCard', 'email']);
  });

  it('reports nothing for text that needed no redaction', () => {
    const result = redact('what time does the shop open tomorrow', config);
    assert.deepEqual(result.applied, []);
  });

  it('honours a disabled rule', () => {
    const relaxed = defaultPrivacyConfig();
    relaxed.redaction.rules.email = false;
    assert.equal(redact('mail a@b.com', relaxed).text, 'mail a@b.com');
  });

  it('applies custom rules from the config', () => {
    const custom = defaultPrivacyConfig();
    custom.redaction.custom.push({
      name: 'caseNumber',
      pattern: 'CASE-\\d{6}',
      flags: 'g',
      replacement: '[redacted:case]',
    });
    const result = redact('see CASE-123456', custom);
    assert.equal(result.text, 'see [redacted:case]');
    assert.deepEqual(result.applied, ['caseNumber']);
  });

  it('rejects a custom rule with an invalid pattern rather than ignoring it', () => {
    const broken = defaultPrivacyConfig();
    broken.redaction.custom.push({
      name: 'bad',
      pattern: '([unclosed',
      flags: 'g',
      replacement: 'x',
    });
    assert.throws(() => redact('anything', broken), /invalid pattern/);
  });

  it('leaves an ordinary message untouched', () => {
    const text = 'Hi! Are you open on Sunday? I would like to book a table for four.';
    assert.equal(redact(text, config).text, text);
  });
});

describe('checksum validators', () => {
  it('validates Luhn', () => {
    assert.equal(luhnValid('4111111111111111'), true);
    assert.equal(luhnValid('4111111111111112'), false);
    assert.equal(luhnValid('not a number'), false);
  });

  it('validates Taiwan national IDs', () => {
    assert.equal(twNationalIdValid('A123456789'), true);
    assert.equal(twNationalIdValid('A123456788'), false);
    assert.equal(twNationalIdValid('A923456789'), false); // second char must be 1 or 2
  });

  it('validates IBANs with the mod-97 rule', () => {
    assert.equal(ibanValid('GB82 WEST 1234 5698 7654 32'), true);
    assert.equal(ibanValid('GB82 WEST 1234 5698 7654 33'), false);
  });
});
