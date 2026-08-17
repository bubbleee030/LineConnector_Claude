/**
 * PII redaction, applied at capture time.
 *
 * The important design decision here is *when* this runs: before the message
 * is written to disk, not on the way out to the model. Redacting on read would
 * leave the raw credit card number sitting in the database, one config mistake
 * or one stolen file away from disclosure. Redacting on write means the
 * sensitive substring never lands on persistent storage at all.
 *
 * The cost of that choice is that redaction is irreversible: if a rule fires on
 * something you actually wanted, the original is gone. That is the intended
 * direction to fail in.
 *
 * Every pattern below is written to run in linear time. This code processes
 * text sent by strangers on the internet, so a regex with nested quantifiers
 * would be a denial-of-service hole in the ingest path.
 */

import type { PrivacyConfig } from '../config.js';
import type { RedactionResult } from '../types.js';

interface Rule {
  name: string;
  enabledByDefault: boolean;
  apply: (text: string) => string;
}

/** Replaces matches only when `validate` accepts them, to cut false positives. */
function validated(
  pattern: RegExp,
  replacement: string,
  validate: (match: string) => boolean,
): (text: string) => string {
  return (text) =>
    text.replace(pattern, (match) => (validate(normaliseDigits(match)) ? replacement : match));
}

function simple(pattern: RegExp, replacement: string): (text: string) => string {
  return (text) => text.replace(pattern, replacement);
}

/**
 * Rule order matters and is not alphabetical.
 *
 * Secrets run first: a token is the highest-severity thing in the list, and
 * running it first stops a later, broader rule from rewriting part of a token
 * and leaving the remainder in the clear. Card numbers run before phone
 * numbers for the same reason — the phone patterns would otherwise chew
 * through a 16-digit sequence and leave half of it behind.
 */
const RULES: Rule[] = [
  {
    name: 'secret',
    enabledByDefault: true,
    apply: (text) =>
      text
        // Provider-shaped keys, matched by their distinctive prefixes.
        .replace(/\bsk-[A-Za-z0-9_-]{16,}/g, '[redacted:secret]')
        .replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}/g, '[redacted:secret]')
        .replace(/\bgithub_pat_[A-Za-z0-9_]{20,}/g, '[redacted:secret]')
        .replace(/\bxox[baprs]-[A-Za-z0-9-]{10,}/g, '[redacted:secret]')
        .replace(/\bAKIA[0-9A-Z]{16}\b/g, '[redacted:secret]')
        // JSON Web Tokens.
        .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g, '[redacted:secret]')
        // Bearer credentials in pasted headers or curl commands.
        .replace(/\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*/gi, 'Bearer [redacted:secret]')
        // Generic `key: value` shapes. Bounded value class, no nesting.
        .replace(
          /\b(api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|passwd|pwd)\b\s*[:=]\s*["']?[^\s"',;]{6,}["']?/gi,
          '$1=[redacted:secret]',
        ),
  },
  {
    name: 'creditCard',
    enabledByDefault: true,
    apply: validated(
      /\b(?:\d[ -]?){12,18}\d\b/g,
      '[redacted:card]',
      (digits) => digits.length >= 13 && digits.length <= 19 && luhnValid(digits),
    ),
  },
  {
    name: 'twNationalId',
    enabledByDefault: true,
    // Taiwan national ID. Checksum-validated, because the raw shape
    // (letter + 9 digits) collides with ordinary product and order codes.
    apply: (text) =>
      text.replace(/\b[A-Z][12]\d{8}\b/g, (match) =>
        twNationalIdValid(match) ? '[redacted:twid]' : match,
      ),
  },
  {
    name: 'jpMyNumber',
    // Off by default: a bare 12-digit run is far more often an order number
    // than a My Number, and the check digit alone does not disambiguate.
    enabledByDefault: false,
    apply: validated(/\b\d{12}\b/g, '[redacted:mynumber]', (digits) => digits.length === 12),
  },
  {
    name: 'iban',
    enabledByDefault: true,
    apply: (text) =>
      text.replace(/\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{1,4}\b/g, (match) =>
        ibanValid(match) ? '[redacted:iban]' : match,
      ),
  },
  {
    name: 'email',
    enabledByDefault: true,
    apply: simple(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, '[redacted:email]'),
  },
  {
    name: 'phone',
    enabledByDefault: true,
    apply: (text) =>
      text
        // International, with explicit country code.
        .replace(/\+\d{1,3}[ -]?\d{1,4}[ -]?\d{3,4}[ -]?\d{3,4}\b/g, '[redacted:phone]')
        // Taiwan mobile (09xx) and landline (0x-xxxx-xxxx).
        .replace(/\b09\d{2}[ -]?\d{3}[ -]?\d{3}\b/g, '[redacted:phone]')
        .replace(/\b0[2-8][ -]?\d{3,4}[ -]?\d{4}\b/g, '[redacted:phone]')
        // Japan, which always writes the separators.
        .replace(/\b0\d{1,4}-\d{1,4}-\d{4}\b/g, '[redacted:phone]')
        // North American, separated.
        .replace(/\b\(?\d{3}\)?[ -]\d{3}[ -]\d{4}\b/g, '[redacted:phone]'),
  },
  {
    name: 'urlQuery',
    enabledByDefault: true,
    // Keeps the destination legible while dropping the query string, which is
    // where session tokens, invite codes and tracking identifiers live.
    apply: simple(/(https?:\/\/[^\s?#]+)\?[^\s#]*/g, '$1?[redacted:query]'),
  },
  {
    name: 'lineId',
    enabledByDefault: true,
    // Raw LINE ids pasted into message text, which would otherwise bypass the
    // pseudonymisation applied to structured sender fields.
    apply: simple(/\b[URC][0-9a-f]{32}\b/g, '[redacted:lineid]'),
  },
];

export const RULE_NAMES: readonly string[] = RULES.map((r) => r.name);

/** Rule names that are on unless the config turns them off. */
export function defaultEnabledRules(): string[] {
  return RULES.filter((r) => r.enabledByDefault).map((r) => r.name);
}

/**
 * Runs the enabled rules over `text`.
 *
 * Returns both the redacted text and the names of the rules that changed
 * something, so the stored message can carry a record of what was removed.
 * That record is what makes it possible to answer "why is there a gap here"
 * later without keeping the removed data around.
 */
export function redact(text: string, config: PrivacyConfig): RedactionResult {
  const overrides = config.redaction.rules;
  const applied = new Set<string>();
  let out = text;

  for (const rule of RULES) {
    const enabled = overrides[rule.name] ?? rule.enabledByDefault;
    if (!enabled) continue;
    const next = rule.apply(out);
    if (next !== out) {
      applied.add(rule.name);
      out = next;
    }
  }

  for (const custom of config.redaction.custom) {
    let pattern: RegExp;
    try {
      pattern = new RegExp(custom.pattern, custom.flags);
    } catch (err) {
      throw new Error(
        `Custom redaction rule ${JSON.stringify(custom.name)} has an invalid pattern: ${
          (err as Error).message
        }`,
      );
    }
    const next = out.replace(pattern, custom.replacement);
    if (next !== out) {
      applied.add(custom.name);
      out = next;
    }
  }

  return { text: out, applied: [...applied].sort() };
}

function normaliseDigits(value: string): string {
  return value.replace(/[^\d]/g, '');
}

/** Luhn check digit, the standard validator for payment card numbers. */
export function luhnValid(digits: string): boolean {
  if (!/^\d+$/.test(digits)) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

// Letter-to-number mapping used by the Taiwan national ID checksum.
const TW_LETTER_VALUES: Record<string, number> = {
  A: 10, B: 11, C: 12, D: 13, E: 14, F: 15, G: 16, H: 17, I: 34, J: 18,
  K: 19, L: 20, M: 21, N: 22, O: 35, P: 23, Q: 24, R: 25, S: 26, T: 27,
  U: 28, V: 29, W: 32, X: 30, Y: 31, Z: 33,
};

/** Validates a Taiwan national ID (one letter followed by nine digits). */
export function twNationalIdValid(id: string): boolean {
  if (!/^[A-Z][12]\d{8}$/.test(id)) return false;
  const letterValue = TW_LETTER_VALUES[id[0] as string];
  if (letterValue === undefined) return false;

  // The letter contributes as two digits, weighted 1 and 9.
  let sum = Math.floor(letterValue / 10) + (letterValue % 10) * 9;
  // The nine digits are weighted 8,7,6,5,4,3,2,1 with the check digit at 1.
  const weights = [8, 7, 6, 5, 4, 3, 2, 1, 1];
  for (let i = 0; i < 9; i++) {
    sum += (id.charCodeAt(i + 1) - 48) * (weights[i] as number);
  }
  return sum % 10 === 0;
}

/** Validates an IBAN using the mod-97 rule from ISO 13616. */
export function ibanValid(candidate: string): boolean {
  const compact = candidate.replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(compact)) return false;

  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const char of rearranged) {
    const value = char >= 'A' && char <= 'Z' ? char.charCodeAt(0) - 55 : char.charCodeAt(0) - 48;
    // Fold digit-by-digit to stay inside safe integer range.
    remainder = value > 9 ? (remainder * 100 + value) % 97 : (remainder * 10 + value) % 97;
  }
  return remainder === 1;
}
