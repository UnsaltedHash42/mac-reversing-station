#!/usr/bin/env node
//
// Tolerant asar extractor.
//
// Closes SHAKEDOWN_NOTES.md item #27. Upstream `asar` and `@electron/asar`
// both ENOENT-bail on the first missing unpacked file, leaving the extract
// directory empty. PASS-001 hit this on Rocket.Chat 4.13.0: the asar header
// claimed 111 unpacked files but only some were present on disk.
//
// This walks the asar header directly and substitutes empty buffers for
// missing unpacked files, recording each substitution in a manifest so the
// operator can tell apart "really empty" from "substituted by extractor".
//
// No external deps. Tested on Node 20.15. The asar format is stable since
// Electron 1.x.
//
// Usage:
//   node extract-asar.js <input.asar> <out-dir>
//
// Exits 0 even when files were substituted; writes <out-dir>/.asar-extract-manifest.json
// with { extracted, inlined, copied, substituted: [paths] }.

'use strict';

const fs = require('fs');
const path = require('path');

function die(msg) { process.stderr.write(`extract-asar: ${msg}\n`); process.exit(2); }

if (process.argv.length !== 4) die('usage: extract-asar.js <input.asar> <out-dir>');

const asarPath = path.resolve(process.argv[2]);
const outDir   = path.resolve(process.argv[3]);
const unpackedDir = asarPath + '.unpacked';

if (!fs.existsSync(asarPath)) die(`no such file: ${asarPath}`);

const fd = fs.openSync(asarPath, 'r');

// Asar header is two nested chromium framing layers.
//   bytes 0..3   uint32 LE = 4 (outer size field width)
//   bytes 4..7   uint32 LE = inner frame size + padding
//   bytes 8..11  uint32 LE = inner frame size (string length)
//   bytes 12..15 uint32 LE = JSON byte length
//   bytes 16..16+jsonLen   JSON header
// Payload starts at 8 + (uint32 at offset 4).
const sizeBuf = Buffer.alloc(16);
fs.readSync(fd, sizeBuf, 0, 16, 0);
const outerHeaderSize = sizeBuf.readUInt32LE(4);
const jsonByteLen     = sizeBuf.readUInt32LE(12);

const headerBuf = Buffer.alloc(jsonByteLen);
fs.readSync(fd, headerBuf, 0, jsonByteLen, 16);
const header = JSON.parse(headerBuf.toString('utf8'));

const payloadOffset = 8 + outerHeaderSize;

const counts = { extracted: 0, inlined: 0, copied: 0, substituted: [] };

function ensureDir(p) { fs.mkdirSync(p, { recursive: true }); }

function writeNode(node, currentPath) {
    if (node.files) {
        ensureDir(currentPath);
        for (const [name, child] of Object.entries(node.files)) {
            writeNode(child, path.join(currentPath, name));
        }
        return;
    }

    const size = typeof node.size === 'number' ? node.size : 0;
    const relFromRoot = path.relative(outDir, currentPath);

    if (node.unpacked) {
        const src = path.join(unpackedDir, relFromRoot);
        if (fs.existsSync(src)) {
            fs.copyFileSync(src, currentPath);
            counts.copied += 1;
        } else {
            fs.writeFileSync(currentPath, Buffer.alloc(0));
            counts.substituted.push(relFromRoot);
        }
        counts.extracted += 1;
        return;
    }

    if (size === 0) {
        fs.writeFileSync(currentPath, Buffer.alloc(0));
        counts.inlined += 1;
        counts.extracted += 1;
        return;
    }

    const offset = parseInt(node.offset, 10);
    const buf = Buffer.alloc(size);
    fs.readSync(fd, buf, 0, size, payloadOffset + offset);
    fs.writeFileSync(currentPath, buf);
    counts.inlined += 1;
    counts.extracted += 1;
}

ensureDir(outDir);
writeNode(header, outDir);
fs.closeSync(fd);

const manifestPath = path.join(outDir, '.asar-extract-manifest.json');
fs.writeFileSync(manifestPath, JSON.stringify({
    asar: asarPath,
    unpackedDir,
    extracted: counts.extracted,
    inlined: counts.inlined,
    copiedFromUnpacked: counts.copied,
    substitutedEmpty: counts.substituted,
}, null, 2));

process.stderr.write(
    `extract-asar: ${counts.extracted} files (${counts.inlined} inlined, ${counts.copied} copied, ${counts.substituted.length} substituted-empty)\n`
);
if (counts.substituted.length > 0) {
    process.stderr.write(`extract-asar: substitution manifest: ${manifestPath}\n`);
}
