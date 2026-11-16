// Build/test time only. The production worker cannot download models.
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
const revision = 'b1993e4e68b082835b80ffc65acc03325ea2e501';
const files = ['config.json', 'tokenizer.json', 'tokenizer_config.json', 'special_tokens_map.json', 'vocab.txt', 'onnx/model_q4.onnx', 'LICENSE', 'MODEL_CARD.md'];
const hashes = JSON.parse(await readFile(new URL('./model-sha256.json', import.meta.url), 'utf8'));
await mkdir(new URL('./model/onnx/', import.meta.url), { recursive: true });
for (const file of files) {
  const response = await fetch(`https://huggingface.co/nationaldesignstudio/rampart/resolve/${revision}/${file}`);
  if (!response.ok) throw Error(`Model download failed: ${file} ${response.status}`);
  const data = Buffer.from(await response.arrayBuffer());
  if (createHash('sha256').update(data).digest('hex') !== hashes[file]) throw Error(`Model checksum mismatch: ${file}`);
  await writeFile(new URL(`./model/${file}`, import.meta.url), data);
  console.log(`${createHash('sha256').update(data).digest('hex')}  ${file}`);
}
