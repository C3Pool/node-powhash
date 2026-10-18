"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const powhash = require("..");

const supported = process.arch === "x64";

function readVectors() {
  return fs.readFileSync(path.join(__dirname, "xelishash_vectors.txt"), "utf8")
    .split("\n")
    .filter((line) => line && !line.startsWith("#"))
    .map((line) => line.trim().split(/\s+/));
}

test("xelishash_v3 matches the official vectors and real miner shares", { skip: !supported }, () => {
  const vectors = readVectors();
  assert.ok(vectors.length >= 14);
  for (const [work, expected, source] of vectors) {
    const out = powhash.xelishash_v3(Buffer.from(work, "hex"));
    assert.equal(out.length, 32);
    assert.equal(out.toString("hex"), expected, source);
  }
});

test("blake3 matches the BLAKE3 reference", { skip: !supported }, () => {
  assert.equal(powhash.blake3(Buffer.alloc(0)).toString("hex"), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
  // BLAKE3 test_vectors.json: input of length n is bytes i % 251.
  const input = Buffer.from(Array.from({ length: 1024 }, (_, i) => i % 251));
  assert.equal(powhash.blake3(input).toString("hex"), "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7");
});

test("xelishash_v3 rejects malformed arguments", { skip: !supported }, () => {
  assert.throws(() => powhash.xelishash_v3(Buffer.alloc(111)), /112-byte/);
  assert.throws(() => powhash.xelishash_v3(), /expects/);
  assert.throws(() => powhash.blake3("x"), /buffer/);
});
