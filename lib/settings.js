"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.setLogger = exports.getConfig = exports.init = exports.initWithConfigContent = void 0;
const KeyVault_1 = require("./KeyVault");
const QuerablePromise_1 = require("./QuerablePromise");
const types_1 = require("./types");
const POSTFIX_ENCRYPTED = '-Encrypted';
const POSTFIX_BIG_ENCRYPTED = '-BigEncrypted';
const POSTFIX_BASE64 = '-Base64';
const STORED_MESSAGES_MAX_LENGTH = 200;
const semaphors = [];
let config;
let hasDecryptionFinished = false;
let logger;
let storedLogMessages = [];
const cache = {};
function decryptObject(decrypt, obj) {
    for (const k in obj) {
        if (obj.hasOwnProperty(k) && typeof obj[k] === 'object') {
            decryptObject(decrypt, obj[k]);
        }
        else {
            if (k.endsWith(POSTFIX_ENCRYPTED)) {
                log(`akec: "${k}" needs to be decrypted`);
                const promiseDecrypt = decrypt(obj[k])
                    .then((val) => {
                    obj[k.substring(0, k.length - POSTFIX_ENCRYPTED.length)] = val;
                    delete obj[k];
                    log(`akec: "${k}" decryption finished`);
                })
                    .catch((error) => {
                    throw new types_1.DecryptionError(`Decryption failed: ${error.toString()} for ${k}`);
                });
                semaphors.push(QuerablePromise_1.makeQuerablePromise(promiseDecrypt));
            }
            else if (k.endsWith(POSTFIX_BIG_ENCRYPTED)) {
                log(`akec: "${k}" needs to be decrypted locally because big payload`);
                const promiseDecryptBig = decrypt(obj[k], true)
                    .then((val) => {
                    obj[k.substring(0, k.length - POSTFIX_BIG_ENCRYPTED.length)] = val;
                    delete obj[k];
                    log(`akec: "${k}" decryption finished`);
                })
                    .catch((error) => {
                    throw new types_1.DecryptionError(`Decryption failed: ${error.toString()} for ${k}`);
                });
                semaphors.push(QuerablePromise_1.makeQuerablePromise(promiseDecryptBig));
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
function decryptObjectInSequence(decrypt, obj) {
    return __awaiter(this, void 0, void 0, function* () {
        for (const k in obj) {
            if (obj.hasOwnProperty(k) && typeof obj[k] === 'object') {
                yield decryptObjectInSequence(decrypt, obj[k]);
            }
            else {
                if (k.endsWith(POSTFIX_ENCRYPTED)) {
                    log(`akec: "${k}" needs to be decrypted`);
                    if (cache[obj[k]]) {
                        log(`akec: value for "${k}" found in cache`);
                        obj[k.substring(0, k.length - POSTFIX_ENCRYPTED.length)] = cache[obj[k]];
                    }
                    else {
                        yield decrypt(obj[k])
                            .then((val) => {
                            cache[obj[k]] = val;
                            obj[k.substring(0, k.length - POSTFIX_ENCRYPTED.length)] = val;
                            delete obj[k];
                            log(`akec: "${k}" decryption finished`);
                        })
                            .catch((error) => {
                            throw new types_1.DecryptionError(`Decryption failed: ${error.toString()} for ${k}`);
                        });
                    }
                }
                else if (k.endsWith(POSTFIX_BIG_ENCRYPTED)) {
                    log(`akec: "${k}" needs to be decrypted locally because big payload`);
                    if (cache[obj[k]]) {
                        log(`akec: value for "${k}" found in cache`);
                        obj[k.substring(0, k.length - POSTFIX_BIG_ENCRYPTED.length)] = cache[obj[k]];
                    }
                    else {
                        yield decrypt(obj[k], true)
                            .then((val) => {
                            cache[obj[k]] = val;
                            obj[k.substring(0, k.length - POSTFIX_BIG_ENCRYPTED.length)] = val;
                            delete obj[k];
                            log(`akec: "${k}" decryption finished`);
                        })
                            .catch((error) => {
                            throw new types_1.DecryptionError(`Decryption failed: ${error.toString()} for ${k}`);
                        });
                    }
                }
                else if (k.endsWith(POSTFIX_BASE64)) {
                    log(`akec: "${k}" needs to be decoded`);
                    obj[k.substring(0, k.length - POSTFIX_BASE64.length)] = Buffer.from(obj[k], 'base64').toString();
                    delete obj[k];
                    log(`akec: "${k}" decoding finished`);
                }
            }
        }
    });
}
const initWithConfigContent = (configContent, keyVaultAccessConfig, customLogger, exceptionLogger, decryptInSequenceAndUseLocalCache = false) => {
    config = configContent;
    const stringifyed = JSON.stringify(configContent);
    if (stringifyed.indexOf(POSTFIX_ENCRYPTED) === -1 &&
        stringifyed.indexOf(POSTFIX_BIG_ENCRYPTED) === -1 &&
        stringifyed.indexOf(POSTFIX_BASE64) === -1) {
        return;
    }
    if (customLogger) {
        exports.setLogger(customLogger);
    }
    let keyVault;
    if (keyVaultAccessConfig.clientSecret) {
        const { tenant, clientId, clientSecret, keyIdentifier, algorithm } = keyVaultAccessConfig;
        keyVault = new KeyVault_1.KeyVault(tenant, clientId, clientSecret, keyIdentifier, algorithm);
    }
    else {
        const { keyIdentifier, algorithm } = keyVaultAccessConfig;
        keyVault = new KeyVault_1.KeyVault(keyIdentifier, algorithm);
    }
    if (customLogger) {
        keyVault.setLogger(customLogger);
    }
    const decrypt = (encryptedValue, big = false) => __awaiter(void 0, void 0, void 0, function* () {
        let decryptedValue = '';
        try {
            decryptedValue = yield keyVault[big ? 'decryptBig' : 'decrypt'](encryptedValue);
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
    if (decryptInSequenceAndUseLocalCache) {
        semaphors.push(QuerablePromise_1.makeQuerablePromise(decryptObjectInSequence(decrypt, config)));
    }
    else {
        decryptObject(decrypt, config);
    }
};
exports.initWithConfigContent = initWithConfigContent;
exports.init = exports.initWithConfigContent;
const getConfig = () => __awaiter(void 0, void 0, void 0, function* () {
    if (!hasDecryptionFinished) {
        const openSemaphors = semaphors
            .map(s => s.isResolved())
            .reduce((count, isResolved) => count + (isResolved ? 0 : 1), 0);
        log(`akec: getConfig -> open semaphors ${openSemaphors}/${semaphors.length}`);
        yield Promise.all(semaphors).then(() => {
            hasDecryptionFinished = true;
        });
    }
    return config;
});
exports.getConfig = getConfig;
const setLogger = (customLogger) => {
    customLogger('akec: custom logger set');
    logger = customLogger;
    storedLogMessages.forEach(msg => customLogger(msg));
    storedLogMessages = [];
};
exports.setLogger = setLogger;
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
