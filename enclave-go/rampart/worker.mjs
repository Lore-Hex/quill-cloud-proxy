import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { ChatGuard, detectNer } from '@nationaldesignstudio/rampart';
import { env, pipeline } from '@huggingface/transformers';

// No prompt or model download may leave the measured image at runtime.
env.allowRemoteModels = false;
env.useBrowserCache = false;
env.useFSCache = false;
env.backends.onnx.wasm.numThreads = 1;

const labels = 'SSN CREDIT_CARD IP_ADDRESS GIVEN_NAME SURNAME EMAIL PHONE URL TAX_ID BANK_ACCOUNT ROUTING_NUMBER GOVERNMENT_ID PASSPORT DRIVERS_LICENSE BUILDING_NUMBER STREET_NAME SECONDARY_ADDRESS CITY STATE ZIP_CODE'.split(' ');

export async function loadClassifier() {
  const model = await pipeline('token-classification', fileURLToPath(new URL('./model/', import.meta.url)), {
    dtype: 'q4', device: 'cpu', local_files_only: true,
    session_options: { intraOpNumThreads: 1, interOpNumThreads: 1 },
  });
  if (!model.tokenizer?.encode || !model.tokenizer?.tokenize) throw Error('missing tokenizer');
  const classifier = (text, options) => model(text, options);
  classifier.countTokens = text => model.tokenizer.encode(text, { add_special_tokens: false }).length;
  classifier.tokenize = text => model.tokenizer.tokenize(text);
  return classifier;
}

export async function protect(texts, classifier) {
  if (!Array.isArray(texts) || texts.length > 4096 || texts.some(t => typeof t !== 'string')) throw Error('invalid input');
  if (Buffer.byteLength(JSON.stringify(texts)) > 1048576) throw Error('input too large');
  // An input literal like [EMAIL_1] must never resolve to somebody else's value.
  const prefix = 'TR' + [...randomBytes(16)].map(n => String.fromCharCode(65 + n % 26)).join('');
  const aliases = Object.fromEntries(labels.map(label => [label, `${prefix}_${label}`]));
  if (!classifier.countTokens || !classifier.tokenize) throw Error('missing tokenizer');
  const guard = new ChatGuard({ keepLabels: [], aliases, ner: text => detectNer(text, classifier) });
  const protectedTexts = [];
  const replacements = Object.create(null);
  for (const text of texts) {
    const safe = await guard.protect(text);
    protectedTexts.push(safe.text);
    for (const token of safe.placeholders) replacements[token] = guard.reveal(token);
  }
  // Reuse detected identities even where the contextual model misses a later
  // occurrence. Only whole values outside placeholders are substituted.
  const known = new Map(Object.entries(replacements).map(([token, value]) => [value, token]));
  const escape = s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const values = [...known.keys()].sort((a, b) => b.length - a.length);
  if (values.length) {
    const pattern = new RegExp(`(?<![\\p{L}\\p{N}_])(?:${values.map(escape).join('|')})(?![\\p{L}\\p{N}_])`, 'gu');
    const tokens = /\[TR[A-Z]{16}_[A-Z_]+_[0-9]+\]/g;
    for (let i = 0; i < protectedTexts.length; i++) {
      const text = protectedTexts[i];
      let result = '', offset = 0;
      for (const match of text.matchAll(tokens)) {
        result += text.slice(offset, match.index).replace(pattern, value => known.get(value)) + match[0];
        offset = match.index + match[0].length;
      }
      protectedTexts[i] = result + text.slice(offset).replace(pattern, value => known.get(value));
    }
  }
  return { texts: protectedTexts, replacements };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    const chunks = [];
    let size = 0;
    for await (const chunk of process.stdin) {
      size += chunk.length;
      if (size > 1048576) throw Error('input too large');
      chunks.push(chunk);
    }
    const input = Buffer.concat(chunks).toString('utf8');
    const classifier = await loadClassifier();
    process.stdout.write(JSON.stringify(await protect(JSON.parse(input).texts, classifier)));
  } catch {
    // Never print exception strings: tokenizer/model errors can include input.
    process.exitCode = 1;
  }
}
