"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const powhash = require("..");

function readVectors() {
  return fs.readFileSync(path.join(__dirname, "nexapow_vectors.txt"), "utf8")
    .split("\n")
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => line.trim().split(/\s+/));
}

test("nexapow matches the Echelon spec vectors and real miner shares", () => {
  const vectors = readVectors();
  assert.ok(vectors.length >= 17);
  for (const [commitment, nonce, expected, source] of vectors) {
    const out = powhash.nexapow(Buffer.from(commitment, "hex"), Buffer.from(nonce, "hex"));
    assert.ok(Buffer.isBuffer(out), source);
    assert.equal(out.length, 32);
    // The final hash is compared little-endian; vectors print it big-endian.
    assert.equal(Buffer.from(out).reverse().toString("hex"), expected, `${source} commitment=${commitment} nonce=${nonce}`);
  }
});

test("nexapow binds the nonce length into the mining hash", () => {
  const [commitment, nonce, expected] = readVectors().find((vector) => vector[1].length === 24);
  const padded = Buffer.concat([Buffer.from(nonce, "hex"), Buffer.alloc(1)]);
  const out = powhash.nexapow(Buffer.from(commitment, "hex"), padded);
  assert.notEqual(Buffer.from(out).reverse().toString("hex"), expected);
});

test("nexapow rejects malformed arguments", () => {
  const commitment = Buffer.alloc(32, 1);
  assert.throws(() => powhash.nexapow(Buffer.alloc(31), Buffer.alloc(8)), /32-byte/);
  assert.throws(() => powhash.nexapow(commitment, Buffer.alloc(0)), /1-16 byte/);
  assert.throws(() => powhash.nexapow(commitment, Buffer.alloc(17)), /1-16 byte/);
  assert.throws(() => powhash.nexapow(commitment), /expects/);
  assert.equal(powhash.nexapow(commitment, Buffer.alloc(16)).length, 32);
});
