#! /usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const KeyVault_1 = require("./KeyVault");
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
let keyVault;
try {
    let config;
    if (process.env.KEY_VAULT_CLIENT_ID) {
        config = [process.env.KEY_VAULT_TENANT, process.env.KEY_VAULT_CLIENT_ID, process.env.KEY_VAULT_CLIENT_SECRET, process.env.KEY_VAULT_KEY_IDENTIFIER];
    }
    else {
        config = [process.env.KEY_VAULT_KEY_IDENTIFIER];
    }
    if (process.env.KEY_VAULT_ALGORITHM) {
        config.push(process.env.KEY_VAULT_ALGORITHM);
    }
    keyVault = new KeyVault_1.KeyVault(...config);
}
catch (e) {
    console.error(e.message);
    process.exit(3);
}
// @ts-ignore
keyVault[method](payload).then(console.log);
