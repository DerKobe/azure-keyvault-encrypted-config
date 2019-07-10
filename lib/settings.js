"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require("fs");
const KeyVault_1 = require("./KeyVault");
const POSTFIX_ENCRYPTED = '-Encrypted';
const POSTFIX_BASE64 = '-Base64';
const semaphors = [];
let config;
let hasDecryptionFinished = false;
function decryptObject(decrypt, obj) {
    for (const k in obj) {
        if (obj.hasOwnProperty(k) && typeof obj[k] === 'object') {
            decryptObject(decrypt, obj[k]);
        }
        else {
            if (k.endsWith(POSTFIX_ENCRYPTED)) {
                const promise = decrypt(obj[k]);
                semaphors.push(promise);
                promise.then((val) => {
                    obj[k.substring(0, k.length - POSTFIX_ENCRYPTED.length)] = val;
                    delete obj[k];
                });
            }
            else if (k.endsWith(POSTFIX_BASE64)) {
                obj[k.substring(0, k.length - POSTFIX_BASE64.length)] = Buffer.from(obj[k], 'base64').toString();
                delete obj[k];
            }
        }
    }
}
exports.init = (configFilePath, keyVaultAccessConfig) => {
    const { clientId, clientSecret, keyIdentifier } = keyVaultAccessConfig;
    const keyVault = new KeyVault_1.KeyVault(clientId, clientSecret, keyIdentifier);
    const data = fs.readFileSync(configFilePath);
    config = JSON.parse(data.toString());
    decryptObject(keyVault.decrypt, config);
};
exports.getConfig = () => __awaiter(this, void 0, void 0, function* () {
    if (!hasDecryptionFinished) {
        yield Promise.all(semaphors).then(() => {
            hasDecryptionFinished = true;
        });
    }
    return config;
});
