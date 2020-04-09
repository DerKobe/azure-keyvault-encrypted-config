#! /usr/bin/env node
import { EncryptionAlgorithm } from "@azure/keyvault-keys";
import { KeyVault } from './KeyVault';

const method = process.argv[2];
const payload = process.argv[3];

if (!['encrypt', 'decrypt', 'encryptBig', 'decryptBig'].includes(method)) {
  console.log(`Unknown method ${method}.`);
  process.exit(1);
}
if (!payload) {
  console.log(`Missing payload. Nothing to ${method}.`);
  process.exit(2);
}

let keyVault
try {
  keyVault = new KeyVault(
    process.env.KEY_VAULT_TENANT as string,
    process.env.KEY_VAULT_CLIENT_ID as string,
    process.env.KEY_VAULT_CLIENT_SECRET as string,
    process.env.KEY_VAULT_KEY_IDENTIFIER as string,
    process.env.KEY_VAULT_ALGORITHM as EncryptionAlgorithm,
  );
} catch (e) {
  console.error(e.message);
  process.exit(3);
}

// @ts-ignore
keyVault[method](payload).then(console.log);
