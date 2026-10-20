"use strict";

// Satoshi Cash (SCASH): RandomX with the "RandomX-Scash\x01" Argon2 salt over the
// 112-byte header (hashRandomX zeroed), judged by the RandomX commitment.
// Vector: the mainnet genesis block (scash src/kernel/chainparams.cpp).
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const test = require("node:test");
const powHash = require("..");

const sha256d = (buf) => crypto.createHash("sha256").update(crypto.createHash("sha256").update(buf).digest()).digest();
const le32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const reversed = (hex) => Buffer.from(hex, "hex").reverse();

const GENESIS = {
    time: 1708650456, nonce: 20076863, bits: 0x1e0fffff, version: 1,
    merkleRoot: "2f7b90fafd8247ee73d213d49699fcfe12a37c608f1d9d1c06f10e43cb6426c6",
    hashRandomX: "33c450e0152826e3a8948b01464cf9182344a1544b3ddcf6153dd04b62938d01",
    hash: "e3bf1597a568216022dbda6a0945f09b005d19f041e7158c3cbca9d4029ee82d"
};

function header(hashRandomX) {
    return Buffer.concat([le32(GENESIS.version), Buffer.alloc(32), reversed(GENESIS.merkleRoot), le32(GENESIS.time),
        le32(GENESIS.bits), le32(GENESIS.nonce), hashRandomX]);
}

function seedHash(time) {
    return sha256d(Buffer.from(`Scash/RandomX/Epoch/${Math.floor(time / 604800)}`));
}

function targetFromBits(bits) {
    return BigInt(bits & 0x7fffff) << BigInt(8 * ((bits >>> 24) - 3));
}

test("rx/scash hashes the genesis header to its hashRandomX", () => {
    const rxHash = powHash.randomx(header(Buffer.alloc(32)), seedHash(GENESIS.time), "rx/scash");
    assert.equal(rxHash.toString("hex"), reversed(GENESIS.hashRandomX).toString("hex"));
    // Not the Monero configuration: the salt changes the hash.
    assert.notEqual(powHash.randomx(header(Buffer.alloc(32)), seedHash(GENESIS.time), 0).toString("hex"), rxHash.toString("hex"));
});

test("the genesis commitment meets its target and the header hashes to the genesis hash", () => {
    const rxHash = reversed(GENESIS.hashRandomX);
    const commitment = powHash.randomx_commitment(header(Buffer.alloc(32)), rxHash);
    assert.equal(commitment.length, 32);
    assert.ok(BigInt(`0x${Buffer.from(commitment).reverse().toString("hex")}`) <= targetFromBits(GENESIS.bits));
    assert.equal(sha256d(header(rxHash)).reverse().toString("hex"), GENESIS.hash);
    assert.throws(() => powHash.randomx_commitment(header(Buffer.alloc(32)), Buffer.alloc(31)), /32 bytes/);
});
