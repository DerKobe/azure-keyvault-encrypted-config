#! /usr/bin/env node
import { KeyVault } from './KeyVault';
import { EncryptionAlgorithm } from "@azure/keyvault-keys";

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

const keys = ['KEY_VAULT_TENANT', 'KEY_VAULT_CLIENT_ID', 'KEY_VAULT_CLIENT_SECRET', 'KEY_VAULT_KEY_IDENTIFIER'];
const hasConfig = keys.reduce((acc: boolean, key: string) => acc && typeof process.env[key] !== 'undefined', true);
if (!hasConfig) {
  console.log(`KeyVault is not configured!`);
  process.exit(3);
}

const keyVault = new KeyVault(
  process.env.KEY_VAULT_TENANT as string,
  process.env.KEY_VAULT_CLIENT_ID as string,
  process.env.KEY_VAULT_CLIENT_SECRET as string,
  process.env.KEY_VAULT_KEY_IDENTIFIER as string,
  process.env.KEY_VAULT_ALGORITHM as EncryptionAlgorithm,
);

// @ts-ignore
keyVault[method](payload).then(console.log);
