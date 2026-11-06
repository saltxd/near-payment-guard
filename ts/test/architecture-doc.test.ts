// docs/architecture.md lists every refusal request_payment can return, in the order the
// contract checks them. This test reads the contract source and fails if the document
// drifts: a check added, removed or reordered in lib.rs has to be reflected in the doc.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const root = join(import.meta.dirname, '..', '..');

function refusalsInOrder(): string[] {
  const src = readFileSync(join(root, 'crates/guard-contract/src/lib.rs'), 'utf8');
  const start = src.indexOf('pub fn request_payment(');
  assert.ok(start >= 0, 'request_payment not found in lib.rs');
  // The signature itself ends in "-> PaymentResult {"; the body runs from there to the
  // PaymentResult struct literal the function returns.
  const sig = '-> PaymentResult {';
  const bodyStart = src.indexOf(sig, start) + sig.length;
  const end = src.indexOf('PaymentResult {', bodyStart);
  assert.ok(bodyStart > start && end > bodyStart, 'could not find the body of request_payment');
  const body = src.slice(bodyStart, end);
  const found: Array<{ at: number; msg: string }> = [];
  for (const m of body.matchAll(/require!\(\s*[\s\S]*?,\s*(?:format!\(\s*)?"([^"]+)"/g)) {
    found.push({ at: m.index ?? 0, msg: m[1] ?? '' });
  }
  for (const m of body.matchAll(/panic_str\(\s*&?(?:format!\(\s*)?"([^"]+)"/g)) {
    found.push({ at: m.index ?? 0, msg: m[1] ?? '' });
  }
  return found
    .sort((a, b) => a.at - b.at)
    .map((f) => (f.msg.split('{')[0] ?? '').trim())
    .filter((msg) => msg.length > 0);
}

test('the contract has the refusals this test expects to find', () => {
  const msgs = refusalsInOrder();
  assert.ok(msgs.length >= 20, `only ${msgs.length} refusals parsed from request_payment`);
  assert.equal(msgs[0], 'invalid authorization:');
  assert.ok(msgs.includes('counterparty cap exceeded'));
});

test('docs/architecture.md lists every request_payment refusal, in contract order', () => {
  const doc = readFileSync(join(root, 'docs/architecture.md'), 'utf8');
  let from = 0;
  for (const msg of refusalsInOrder()) {
    const at = doc.indexOf('`' + msg, from);
    assert.ok(at >= 0, `docs/architecture.md is missing \`${msg}\` (or lists it out of order)`);
    from = at + msg.length;
  }
});

test('docs/architecture.md carries a sequence diagram GitHub can render', () => {
  const doc = readFileSync(join(root, 'docs/architecture.md'), 'utf8');
  assert.match(doc, /```mermaid\s+sequenceDiagram/);
  for (const name of ['request_payment', '/api/near/authorize', 'mt_transfer']) {
    assert.ok(doc.includes(name), `diagram does not mention ${name}`);
  }
});
