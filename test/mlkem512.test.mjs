import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { join } from 'node:path';
import test from 'node:test';

import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const addon = require('../build/Release/lattice_wire_native.node');

test('native ML-KEM-512 wrapper roundtrip and implicit rejection tests', () => {
  const executable = join(
    'build',
    'Release',
    process.platform === 'win32' ? 'mlkem512_test.exe' : 'mlkem512_test',
  );
  const output = execFileSync(executable, { encoding: 'utf8' });
  assert.match(output, /ML-KEM-512 wrapper tests passed/);
});

test('standalone encapsulation and decapsulation accept secure handles', (t) => {
  const handles = [];
  try {
    const { publicKey, secretKey } = addon.generateMlKem512Keypair({
      secureHandle: true,
    });
    handles.push(secretKey);

    const { ciphertext, sharedSecret: clientSecret } =
      addon.encapsulateMlKem512(publicKey);
    const serverSecret = addon.decapsulateMlKem512(ciphertext, secretKey);
    assert.deepEqual(serverSecret, clientSecret);
    clientSecret.fill(0);
    serverSecret.fill(0);

    const { ciphertext: secureCiphertext, sharedSecret: clientHandle } =
      addon.encapsulateMlKem512(publicKey, { secureHandle: true });
    handles.push(clientHandle);
    const serverHandle = addon.decapsulateMlKem512(
      secureCiphertext,
      secretKey,
      { secureHandle: true },
    );
    handles.push(serverHandle);

    assert.equal(Buffer.isBuffer(clientHandle), false);
    assert.equal(Buffer.isBuffer(serverHandle), false);
    assert.equal(addon.destroySecret(clientHandle), undefined);
    assert.equal(addon.destroySecret(serverHandle), undefined);
    assert.equal(addon.destroySecret(secretKey), undefined);
    assert.throws(
      () => addon.decapsulateMlKem512(secureCiphertext, secretKey),
      /already been destroyed/i,
    );
  } catch (error) {
    if (/secure memory|memory-lock limits|core dumps/i.test(error.message)) {
      t.skip(`The operating system did not permit secure memory allocation: ${error.message}`);
      return;
    }
    throw error;
  } finally {
    for (const handle of handles) {
      addon.destroySecret(handle);
    }
  }
});
