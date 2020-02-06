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
const QuerablePromise_1 = require("./QuerablePromise");
const POSTFIX_ENCRYPTED = '-Encrypted';
const POSTFIX_BASE64 = '-Base64';
const STORED_MESSAGES_MAX_LENGTH = 200;
const semaphors = [];
let config;
let hasDecryptionFinished = false;
let logger = console.log;
let storedLogMessages = [];
function decryptObject(decrypt, obj) {
    for (const k in obj) {
        if (obj.hasOwnProperty(k) && typeof obj[k] === 'object') {
            decryptObject(decrypt, obj[k]);
        }
        else {
            if (k.endsWith(POSTFIX_ENCRYPTED)) {
                log(`akec: "${k}" needs to be decrypted`);
                const promise = (decrypt(obj[k])
                    .then((val) => {
                    obj[k.substring(0, k.length - POSTFIX_ENCRYPTED.length)] = val;
                    delete obj[k];
                    log(`akec: "${k}" decryption finished`);
                })
                    .catch((error) => {
                    obj[k.substring(0, k.length - POSTFIX_ENCRYPTED.length)] = `Decryption failed: ${error.toString()}`;
                    delete obj[k];
                    log(`akec: "${k}" decryption failed: ${error.toString()}`);
                }));
                semaphors.push(QuerablePromise_1.makeQuerablePromise(promise));
            }
            else if (k.endsWith(POSTFIX_BASE64)) {
                log(`akec: "${k}" needs to be decoded`);
                obj[k.substring(0, k.length - POSTFIX_BASE64.length)] = Buffer.from(obj[k], 'base64').toString();
                delete obj[k];
                log(`akec: "${k}" decoding finished`);
            }
        }
    }
}
exports.init = (configFilePath, keyVaultAccessConfig, customLogger, exceptionLogger) => {
    const data = fs.readFileSync(configFilePath);
    config = JSON.parse(data.toString());
    exports.initWithConfigContent(config, keyVaultAccessConfig, customLogger, exceptionLogger);
};
exports.initWithConfigContent = (configContent, keyVaultAccessConfig, customLogger, exceptionLogger) => {
    config = configContent;
    if (customLogger) {
        exports.setLogger(customLogger);
    }
    const { clientId, clientSecret, keyIdentifier } = keyVaultAccessConfig;
    const keyVault = new KeyVault_1.KeyVault(clientId, clientSecret, keyIdentifier);
    if (customLogger) {
        keyVault.setLogger(customLogger);
    }
    const decrypt = (encryptedValue) => __awaiter(this, void 0, void 0, function* () {
        let decryptedValue = '';
        try {
            decryptedValue = yield keyVault.decrypt(encryptedValue);
        }
        catch (exception) {
            if (exceptionLogger) {
                exceptionLogger(exception);
            }
            else {
                throw exception;
            }
        }
        return decryptedValue;
    });
    decryptObject(decrypt, config);
};
exports.getConfig = () => __awaiter(this, void 0, void 0, function* () {
    if (!hasDecryptionFinished) {
        const openSemaphors = semaphors.map(s => s.isResolved()).reduce((count, isResolved) => count + (isResolved ? 0 : 1), 0);
        log(`akec: getConfig -> open semaphors ${openSemaphors}/${semaphors.length}`);
        yield Promise.all(semaphors).then(() => { hasDecryptionFinished = true; });
    }
    return config;
});
function log(...args) {
    if (logger) {
        logger(...args);
    }
    else {
        storedLogMessages.push(args);
        if (storedLogMessages.length > STORED_MESSAGES_MAX_LENGTH) {
            storedLogMessages.shift();
        }
    }
}
exports.setLogger = (customLogger) => {
    customLogger('akec: custom logger set');
    logger = customLogger;
    storedLogMessages.forEach(msg => customLogger(msg));
    storedLogMessages = [];
};
