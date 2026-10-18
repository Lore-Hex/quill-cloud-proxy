// Run against the local Go test fixture, or a production API with an invalid key.
// QUILL_PLAYWRIGHT_MODULE may point to an existing Playwright installation.
const assert = require('node:assert/strict');
const http = require('node:http');
const { chromium } = require(process.env.QUILL_PLAYWRIGHT_MODULE || 'playwright');

async function main() {
  const api = process.argv[2];
  assert(api, 'Usage: node tools/browser-cors-smoke.cjs API_ORIGIN [--fixture]');
  const fixture = process.argv.includes('--fixture');
  const origin = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end('<!doctype html><title>Browser CORS test</title>');
  });
  await new Promise(resolve => origin.listen(0, '127.0.0.1', resolve));
  let browser;
  try {
    browser = await chromium.launch({ headless: true });
    const page = await browser.newPage();
    await page.goto(`http://127.0.0.1:${origin.address().port}`);
    const result = await page.evaluate(async ({ api, fixture }) => {
      async function call(path, token, payload, credentials = 'omit') {
        const response = await fetch(api + path, {
          method: 'POST', credentials,
          headers: {
            Authorization: `Bearer ${token}`,
            'Content-Type': 'application/json',
            'X-Stainless-OS': 'browser',
            'Idempotency-Key': crypto.randomUUID(),
          },
          body: JSON.stringify(payload),
        });
        const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
        let body = '';
        for (;;) {
          const chunk = await reader.read();
          if (chunk.done) break;
          body += chunk.value;
        }
        return { status: response.status, id: response.headers.get('x-request-id'), body };
      }
      const authPayload = {
        model: fixture ? 'test-model' : 'trustedrouter/monitor',
        messages: [{ role: 'user', content: 'reply exactly PONG' }],
        max_tokens: 8,
      };
      const invalid = await call('/v1/chat/completions', 'cors-smoke-invalid-key', authPayload);
      let credentialedBlocked = false;
      try {
        await call('/v1/chat/completions', 'cors-smoke-invalid-key', authPayload, 'include');
      } catch (error) {
        credentialedBlocked = error instanceof TypeError;
      }
      const successes = [];
      if (fixture) {
        for (const path of ['/v1/chat/completions', '/v1/responses']) {
          for (const stream of [false, true]) {
            const payload = path.endsWith('/responses')
              ? { model: 'test-model', input: 'hello', stream }
              : { model: 'test-model', messages: [{ role: 'user', content: 'hello' }], stream };
            successes.push({ path, stream, ...await call(path, 'browser-key', payload) });
          }
        }
      }
      return { invalid, credentialedBlocked, successes };
    }, { api, fixture });
    assert.equal(result.invalid.status, 401);
    assert.match(result.invalid.id, /^rlog_[0-9a-f]{32}$/);
    assert.equal(result.credentialedBlocked, true);
    for (const response of result.successes) {
      assert.equal(response.status, 200);
      assert.match(response.id, /^rlog_[0-9a-f]{32}$/);
      assert.match(response.body, /Hello/);
      if (response.stream) {
        assert.match(response.body, response.path.endsWith('/responses') ? /response.completed/ : /data: \[DONE\]/);
      }
    }
    console.log(JSON.stringify({ api, invalidKeyReadable: true, cookieCredentialsBlocked: true,
      fixtureSuccesses: result.successes.map(({ path, stream, status }) => ({ path, stream, status })) }));
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => origin.close(resolve));
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
