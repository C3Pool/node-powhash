"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const powhash = require("..");

const U512_MAX = (1n << 512n) - 1n;
const toBigInt = (buf) => BigInt("0x" + buf.toString("hex"));

function readVectors() {
  return fs.readFileSync(path.join(__dirname, "qpow_vectors.txt"), "utf8")
    .split("\n")
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => line.trim().split(/\s+/));
}

test("qpow matches the official qp-poseidon-core digests", () => {
  const vectors = readVectors();
  assert.ok(vectors.length >= 238);
  for (const [miningHash, nonce, digest] of vectors) {
    const out = powhash.qpow(Buffer.from(miningHash, "hex"), Buffer.from(nonce, "hex"));
    assert.equal(out.length, 64);
    assert.equal(out.toString("hex"), digest, `mining_hash=${miningHash} nonce=${nonce}`);
  }
});

test("qpow accepts every sealed mainnet block in the fixture", () => {
  const { blocks } = JSON.parse(fs.readFileSync(path.join(__dirname, "qpow_mainnet_blocks.json"), "utf8"));
  assert.ok(blocks.length >= 10);
  for (const block of blocks) {
    const digest = toBigInt(powhash.qpow(Buffer.from(block.mining_hash, "hex"), Buffer.from(block.nonce, "hex")));
    const target = U512_MAX / BigInt(block.difficulty);
    assert.ok(digest < target, `block ${block.height} must meet its difficulty`);
  }
});

test("qpow rejects a sealed mainnet nonce under a different mining hash", () => {
  const { blocks } = JSON.parse(fs.readFileSync(path.join(__dirname, "qpow_mainnet_blocks.json"), "utf8"));
  const [a, b] = blocks.slice(-2);
  const digest = toBigInt(powhash.qpow(Buffer.from(a.mining_hash, "hex"), Buffer.from(b.nonce, "hex")));
  assert.ok(digest >= U512_MAX / BigInt(a.difficulty));
});

test("qpow validates its arguments", () => {
  const hash = Buffer.alloc(32);
  const nonce = Buffer.alloc(64);
  assert.throws(() => powhash.qpow(hash), /expects mining hash/);
  assert.throws(() => powhash.qpow(Buffer.alloc(31), nonce), /32-byte/);
  assert.throws(() => powhash.qpow(hash, Buffer.alloc(63)), /64-byte/);
  assert.throws(() => powhash.qpow(hash.toString("hex"), nonce), /buffer object/);
  assert.equal(powhash.qpow(hash, nonce).length, 64);
});
