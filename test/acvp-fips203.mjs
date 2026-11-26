import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import * as wire from '../index.js';

const CACHE_DIR = path.resolve('.acvp-cache');
const BASE_URL = 'https://raw.githubusercontent.com/usnistgov/ACVP-Server/master/gen-val/json-files';

const VECTORS = {
  prompt: `${BASE_URL}/ML-KEM-encapDecap-FIPS203/prompt.json`,
  expected: `${BASE_URL}/ML-KEM-encapDecap-FIPS203/expectedResults.json`,
};

async function fetchCached(name, url) {
  await fs.mkdir(CACHE_DIR, { recursive: true });
  const file = path.join(CACHE_DIR, `${name}.json`);
  try {
    return JSON.parse(await fs.readFile(file, 'utf8'));
  } catch {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Failed to fetch ${url}: ${res.status}`);
    const data = await res.json();
    await fs.writeFile(file, JSON.stringify(data));
    return data;
  }
}

const fromHex = (hex) => (typeof hex === 'string' ? Buffer.from(hex, 'hex') : null);
const toHex = (buf) => Buffer.from(buf).toString('hex').toUpperCase();

function callDecap(ct, sk) {
  try {
    return wire.decapsulateMlKem512(ct, sk);
  } catch {
    return wire.decapsulateMlKem512(sk, ct);
  }
}

async function run() {
  const prompt = await fetchCached('mlkem-encapDecap-prompt', VECTORS.prompt);
  const expected = await fetchCached('mlkem-encapDecap-expected', VECTORS.expected);

  const expectedByGroup = new Map(expected.testGroups.map((g) => [g.tgId, g]));
  let bufferPassed = 0;
  let securePassed = 0;

  for (const group of prompt.testGroups) {
    if (group.parameterSet !== 'ML-KEM-512') continue;
    if (group.function !== 'decapsulation') continue;

    const expGroup = expectedByGroup.get(group.tgId);
    if (!expGroup) continue;
    const expByTc = new Map(expGroup.tests.map((t) => [t.tcId, t]));

    for (const tc of group.tests) {
      const exp = expByTc.get(tc.tcId);
      if (!exp) continue;

      const dkHex = tc.dk || group.dk;
      const ctHex = tc.c || tc.ct;
      const expectedHex = (exp.k || exp.ss || '').toUpperCase();
      if (!dkHex || !ctHex || !expectedHex) continue;

      const dk = fromHex(dkHex);
      const ct = fromHex(ctHex);

      // 1. Raw Buffer path
      const ssBuf = callDecap(ct, dk);
      assert.equal(
        toHex(ssBuf),
        expectedHex,
        `ML-KEM-512 Buffer Decap mismatch (tgId=${group.tgId}, tcId=${tc.tcId})`
      );
      bufferPassed++;

      // 2. mlock-backed SecureSecretHandle path
      const secureDk = wire.allocateSecret(dk);
      try {
        const ssSec = callDecap(ct, secureDk);
        assert.equal(
          toHex(ssSec),
          expectedHex,
          `ML-KEM-512 SecureSecretHandle Decap mismatch (tgId=${group.tgId}, tcId=${tc.tcId})`
        );
        securePassed++;
      } finally {
        wire.destroySecret(secureDk);
      }
    }
  }

  assert.ok(bufferPassed > 0, 'No ML-KEM-512 ACVP decapsulation vectors were executed');
  console.log(
    `PASS: ${bufferPassed} Buffer + ${securePassed} SecureSecretHandle NIST ACVP FIPS 203 ML-KEM-512 Decaps KATs verified bit-exact.`
  );
}

run().catch((err) => {
  console.error('ACVP FIPS 203 KAT FAILURE:', err);
  process.exit(1);
});
