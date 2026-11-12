import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import * as rootExports from '../index.js';
import { EpochKeyManager } from '../lib/crypto/EpochKeyManager.js';
import {
  OneRttSession,
  SlidingReplayWindow,
} from '../lib/crypto/OneRttSession.js';

const directory = path.dirname(fileURLToPath(import.meta.url));
const dtsPath = path.resolve(directory, '../index.d.ts');
const require = createRequire(import.meta.url);
const nativeAddon = require('../build/Release/lattice_wire_native.node');

function parseDtsContract(dtsSource) {
  const clean = dtsSource
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/\/\/.*$/gm, '');

  const functions = new Set(
    [...clean.matchAll(/export\s+(?:declare\s+)?function\s+([A-Za-z0-9_]+)\s*\(/g)]
      .map((match) => match[1]),
  );
  const classes = new Map();
  const classRegex =
    /export\s+(?:declare\s+)?class\s+([A-Za-z0-9_]+)(?:<[^>]+>)?(?:\s+implements\s+[^{]+)?\s*\{([\s\S]*?)^\}/gm;

  for (const match of clean.matchAll(classRegex)) {
    const members = new Set();
    let hasSymbolDispose = false;
    let signatureDepth = 0;
    for (const rawLine of match[2].split('\n')) {
      const line = rawLine.trim();
      if (!line) {
        continue;
      }
      if (signatureDepth > 0) {
        signatureDepth +=
          [...line].filter((character) => character === '(').length -
          [...line].filter((character) => character === ')').length;
        continue;
      }
      if (line.startsWith('constructor')) {
        signatureDepth +=
          [...line].filter((character) => character === '(').length -
          [...line].filter((character) => character === ')').length;
        continue;
      }
      if (line.startsWith('[Symbol.dispose]')) {
        hasSymbolDispose = true;
        continue;
      }
      const member = line.match(
        /^(?:readonly\s+)?([A-Za-z0-9_]+)\s*(?:<[^>]+>)?\s*[:(]/,
      );
      if (member) {
        members.add(member[1]);
        if (line.includes('(')) {
          signatureDepth =
            [...line].filter((character) => character === '(').length -
            [...line].filter((character) => character === ')').length;
        }
      }
    }
    classes.set(match[1], { members, hasSymbolDispose });
  }

  return { functions, classes };
}

test('index.d.ts functions match the root and native runtime exports', () => {
  assert.ok(fs.existsSync(dtsPath), 'Expected index.d.ts at the package root');
  const { functions, classes } = parseDtsContract(
    fs.readFileSync(dtsPath, 'utf8'),
  );
  assert.ok(functions.size > 0, 'Expected exported functions in index.d.ts');

  const runtimeSurface = {
    ...nativeAddon,
    ...rootExports,
  };
  for (const functionName of functions) {
    assert.equal(
      typeof runtimeSurface[functionName],
      'function',
      `index.d.ts declares "${functionName}()", but it is missing at runtime`,
    );
    assert.equal(
      typeof rootExports[functionName],
      'function',
      `Package root does not re-export "${functionName}()"`,
    );
  }

  const nativeFunctionNames = Object.getOwnPropertyNames(nativeAddon)
    .filter((name) => typeof nativeAddon[name] === 'function');
  for (const functionName of nativeFunctionNames) {
    assert.ok(
      functions.has(functionName),
      `Native addon exports "${functionName}()", but index.d.ts does not declare it`,
    );
  }
  for (const [exportName, value] of Object.entries(rootExports)) {
    if (typeof value === 'function' && !classes.has(exportName)) {
      assert.ok(
        functions.has(exportName),
        `Package root exports "${exportName}()", but index.d.ts does not declare it`,
      );
    }
  }
});

test('index.d.ts classes and members match their runtime exports and prototypes', () => {
  const { classes } = parseDtsContract(fs.readFileSync(dtsPath, 'utf8'));
  const runtimeClasses = new Map([
    ['EpochKeyManager', EpochKeyManager],
    ['OneRttSession', OneRttSession],
    ['SlidingReplayWindow', SlidingReplayWindow],
  ]);

  assert.deepEqual(
    [...classes.keys()].sort(),
    [...runtimeClasses.keys()].sort(),
    'Declared runtime classes must match the package runtime classes',
  );

  for (const [className, RuntimeClass] of runtimeClasses) {
    assert.ok(classes.has(className), `Expected ${className} in index.d.ts`);
    assert.equal(
      rootExports[className],
      RuntimeClass,
      `Package root does not re-export ${className}`,
    );

    const { members, hasSymbolDispose } = classes.get(className);
    const runtimeMembers = new Set(
      Object.getOwnPropertyNames(RuntimeClass.prototype)
        .filter((name) => name !== 'constructor')
        .filter((name) => {
          const descriptor = Object.getOwnPropertyDescriptor(
            RuntimeClass.prototype,
            name,
          );
          return typeof descriptor.value === 'function' ||
            typeof descriptor.get === 'function';
        }),
    );
    assert.deepEqual(
      [...members].sort(),
      [...runtimeMembers].sort(),
      `${className} declarations must match all public runtime methods and getters`,
    );

    for (const memberName of members) {
      const descriptor = Object.getOwnPropertyDescriptor(
        RuntimeClass.prototype,
        memberName,
      );
      assert.ok(
        descriptor,
        `${className}.prototype is missing declared member "${memberName}"`,
      );
      assert.ok(
        typeof descriptor.value === 'function' ||
          typeof descriptor.get === 'function',
        `${className}.prototype.${memberName} is not a method or getter`,
      );
    }
    if (hasSymbolDispose && typeof Symbol.dispose === 'symbol') {
      assert.equal(
        typeof RuntimeClass.prototype[Symbol.dispose],
        'function',
        `${className}.prototype is missing [Symbol.dispose]()`,
      );
    }
  }
});
