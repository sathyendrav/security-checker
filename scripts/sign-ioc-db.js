#!/usr/bin/env node
'use strict';

/**
 * Sign ioc-db.json with the maintainer's Ed25519 private key.
 *
 * Usage:
 *   node scripts/sign-ioc-db.js
 *
 * Reads:
 *   - ./ioc-db.json (the IOC database to sign)
 *   - ~/.sec-check/ioc-signing-key.pem (the Ed25519 private key)
 *
 * Writes:
 *   - ./ioc-db.json.sig (base64-encoded Ed25519 signature)
 *
 * The private key must NEVER be committed to the repository.
 * Store it in ~/.sec-check/ioc-signing-key.pem or set the
 * IOC_SIGNING_KEY_PATH environment variable to override.
 */

const fs = require('fs');
const path = require('path');
const os = require('os');
const crypto = require('crypto');

const iocPath = path.join(__dirname, '..', 'ioc-db.json');
const sigPath = iocPath + '.sig';

const keyPath = process.env.IOC_SIGNING_KEY_PATH ||
  path.join(os.homedir(), '.sec-check', 'ioc-signing-key.pem');

if (!fs.existsSync(iocPath)) {
  console.error(`❌ IOC database not found: ${iocPath}`);
  process.exit(1);
}

if (!fs.existsSync(keyPath)) {
  console.error(`❌ Private key not found: ${keyPath}`);
  console.error('   Generate one with: node -e "const c=require(\'crypto\');const{publicKey,privateKey}=c.generateKeyPairSync(\'ed25519\');console.log(publicKey.export({type:\'spki\',format:\'pem\'}));console.log(privateKey.export({type:\'pkcs8\',format:\'pem\'}))"');
  process.exit(1);
}

const data = fs.readFileSync(iocPath);
const privateKeyPem = fs.readFileSync(keyPath, 'utf8');
const privateKey = crypto.createPrivateKey(privateKeyPem);

const signature = crypto.sign(null, data, privateKey);
const signatureBase64 = signature.toString('base64');

fs.writeFileSync(sigPath, signatureBase64 + '\n');

console.log(`✅ Signed ${path.basename(iocPath)}`);
console.log(`   Signature: ${sigPath}`);
console.log(`   Base64: ${signatureBase64.slice(0, 40)}...`);
