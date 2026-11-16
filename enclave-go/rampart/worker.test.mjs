import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { loadClassifier, protect } from './worker.mjs';

const classifier = await loadClassifier();
test('real model: names, email, geography, long input, stable identities and isolated requests', async () => {
  const text = 'My name is Alice Smith. Email me at alice@example.com. I live in Seattle.';
  const long = 'This is a neutral paragraph about weather. '.repeat(150) + text;
  const r = await protect([text, text, long, '[EMAIL_1] is a literal.'], classifier);
  for (const safe of r.texts.slice(0, 3)) {
    for (const pii of ['Alice', 'Smith', 'alice@example.com', 'Seattle']) assert.ok(!safe.includes(pii), pii);
  }
  assert.equal(r.texts[0], r.texts[1]);
  assert.ok(r.texts[3].includes('[EMAIL_1]'));
  assert.ok(Object.values(r.replacements).includes('Alice'));
  assert.notEqual((await protect([text], classifier)).texts[0], r.texts[0]);
});
test('fail closed without token-aware long-input support', async () => {
  await assert.rejects(protect(['hi'], async () => []), /missing tokenizer/);
});
test('real worker protocol: one bounded request, sanitized failure output', () => {
  const script = fileURLToPath(new URL('./worker.mjs', import.meta.url));
  const success = spawnSync(process.execPath, [script], { input: JSON.stringify({texts:['My name is Alice Smith.']}), encoding:'utf8', timeout:30000 });
  assert.equal(success.status, 0, success.stderr);
  assert.ok(!JSON.parse(success.stdout).texts[0].includes('Alice'));
  const failure = spawnSync(process.execPath, [script], { input:'private malformed Alice Smith', encoding:'utf8', timeout:30000 });
  assert.equal(failure.status, 1);
  assert.equal(failure.stdout, '');
  assert.equal(failure.stderr, '');
});
